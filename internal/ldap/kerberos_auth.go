package ldap

import (
	"fmt"
	"os"
	"strings"

	gokrb5client "github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/jcmturner/gokrb5/v8/types"
)

// KerberosGSSAPIClient implements go-ldap's GSSAPIClient interface using gokrb5.
// Used for Pass-the-Ticket (ccache) authentication against LDAP.
type KerberosGSSAPIClient struct {
	krb5Client *gokrb5client.Client
	spn        string
	sessionKey types.EncryptionKey
	seqNum     uint64
}

// NewKerberosClientFromCCache loads a Kerberos client from a ccache file.
// dc is the hostname/IP of the DC (used to build the LDAP SPN).
// domain is used to build a minimal krb5 config when KRB5_CONFIG / /etc/krb5.conf are absent.
func NewKerberosClientFromCCache(ccachePath, dc, domain string) (*KerberosGSSAPIClient, error) {
	cfg := loadKrb5Config(dc, domain)

	cc, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("kerberos: load ccache %s: %w", ccachePath, err)
	}

	cl, err := gokrb5client.NewFromCCache(cc, cfg, gokrb5client.DisablePAFXFAST(true))
	if err != nil {
		return nil, fmt.Errorf("kerberos: init client from ccache: %w", err)
	}

	// Use the ccache's principal realm to build the SPN realm suffix
	// Prefer FQDN over IP for Kerberos SPN
	spn := fmt.Sprintf("ldap/%s", dc)

	return &KerberosGSSAPIClient{
		krb5Client: cl,
		spn:        spn,
	}, nil
}

// loadKrb5Config tries, in order:
//  1. $KRB5_CONFIG env var
//  2. /etc/krb5.conf
//  3. minimal inline config derived from dc + domain
func loadKrb5Config(dc, domain string) *config.Config {
	if path := os.Getenv("KRB5_CONFIG"); path != "" {
		if cfg, err := config.Load(path); err == nil {
			return cfg
		}
	}
	if cfg, err := config.Load("/etc/krb5.conf"); err == nil {
		return cfg
	}

	realm := strings.ToUpper(domain)
	cfgText := fmt.Sprintf(`[libdefaults]
 default_realm = %s
 dns_lookup_realm = false
 dns_lookup_kdc = false

[realms]
 %s = {
  kdc = %s
  admin_server = %s
 }

[domain_realm]
 .%s = %s
 %s = %s
`, realm, realm, dc, dc, strings.ToLower(domain), realm, strings.ToLower(domain), realm)

	cfg, err := config.NewFromString(cfgText)
	if err != nil {
		return config.New()
	}
	return cfg
}

// InitSecContext creates the initial GSSAPI/SPNEGO token (AP-REQ).
// go-ldap calls this with an empty token on the initial exchange.
func (k *KerberosGSSAPIClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return k.InitSecContextWithOptions(target, token, []int{})
}

// InitSecContextWithOptions creates the SPNEGO token, optionally with AP options.
func (k *KerberosGSSAPIClient) InitSecContextWithOptions(target string, token []byte, options []int) ([]byte, bool, error) {
	tkt, sessionKey, err := k.krb5Client.GetServiceTicket(k.spn)
	if err != nil {
		return nil, false, friendlyKerberosError(fmt.Errorf("kerberos: get ticket for %s: %w", k.spn, err))
	}
	k.sessionKey = sessionKey

	// Wrap AP-REQ in SPNEGO NegTokenInit — Windows AD requires SPNEGO wrapping
	// even for the SASL GSSAPI mechanism
	negToken, err := spnego.NewNegTokenInitKRB5(k.krb5Client, tkt, sessionKey)
	if err != nil {
		return nil, false, fmt.Errorf("kerberos: create SPNEGO NegTokenInit: %w", err)
	}

	b, err := negToken.Marshal()
	if err != nil {
		return nil, false, fmt.Errorf("kerberos: marshal SPNEGO token: %w", err)
	}

	return b, false, nil
}

// DeleteSecContext destroys the Kerberos client context.
func (k *KerberosGSSAPIClient) DeleteSecContext() error {
	k.krb5Client.Destroy()
	return nil
}

// NegotiateSaslAuth implements RFC 4752 §3.4 security layer negotiation.
// go-ldap calls this after the AP-REQ/AP-REP exchange with the server's challenge.
// The server sends a GSS wrap token containing security layer options;
// we reply with our choice (no protection).
func (k *KerberosGSSAPIClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	// Unwrap server's security layer negotiation token
	var wrapToken gssapi.WrapToken
	if err := wrapToken.Unmarshal(token, true); err != nil {
		return nil, fmt.Errorf("kerberos: unmarshal server wrap token: %w", err)
	}

	if ok, err := wrapToken.Verify(k.sessionKey, keyusage.GSSAPI_ACCEPTOR_SEAL); !ok || err != nil {
		return nil, fmt.Errorf("kerberos: verify server wrap token: %w", err)
	}

	payload := wrapToken.Payload
	if len(payload) < 4 {
		return nil, fmt.Errorf("kerberos: security layer token too short (%d bytes)", len(payload))
	}

	// payload[0]   = bitmask of supported security layers
	// payload[1:4] = max message size (big-endian)
	serverLayers := payload[0]
	if serverLayers&0x01 == 0 {
		return nil, fmt.Errorf("kerberos: server does not support no-protection layer (mask=0x%02x)", serverLayers)
	}

	// Build our response: no protection (0x01), max size from server (3 bytes big-endian).
	// RFC 4752 §3.1: client message = [1 byte layer mask][3 bytes max buffer size][optional authzid]
	resp := make([]byte, 4)
	resp[0] = 0x01
	copy(resp[1:4], payload[1:4]) // copy server's max buffer size (3 bytes)
	if authzid != "" {
		resp = append(resp, []byte(authzid)...)
	}

	// Wrap response using initiator seal key
	k.seqNum++
	respToken, err := gssapi.NewInitiatorWrapToken(resp, k.sessionKey)
	if err != nil {
		return nil, fmt.Errorf("kerberos: wrap security layer response: %w", err)
	}

	b, err := respToken.Marshal()
	if err != nil {
		return nil, fmt.Errorf("kerberos: marshal wrap token response: %w", err)
	}

	return b, nil
}
