package ldap

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/fatih/color"
	goldap "github.com/go-ldap/ldap/v3"
	"golang.org/x/net/proxy"
)

// Client holds connection parameters and the active LDAP connection.
type Client struct {
	Host       string
	Port       int
	Domain     string
	Username   string
	Password   string
	NTHash     string // NT hash for Pass-the-Hash (NTLM auth)
	CcachePath string // path to ccache file for Pass-the-Ticket (Kerberos auth)
	ProxyURL   string // SOCKS5 proxy, e.g. socks5://127.0.0.1:1080 (PTT not supported through proxy)
	IsAnon        bool   // true after successful anonymous bind
	PrimaryDomain string // auth domain for cross-domain binds (empty = use Domain)
	BaseDN        string
	conn       *goldap.Conn
	saslWrap   *saslConn // non-nil only for Kerberos ccache connections
	Verbose    bool
	Quiet      bool // suppress all informational output (for CI/--quiet mode)
}

// NewClient creates a new Client.
// dc — DC IP or hostname; empty means autodiscover via DNS.
func NewClient(domain, username, password, dc string, verbose bool) *Client {
	host := dc
	if host == "" {
		host = domain // fallback: go-ldap resolves via DNS
	}

	return &Client{
		Host:     host,
		Port:     389,
		Domain:   domain,
		Username: username,
		Password: password,
		BaseDN:   domainToBaseDN(domain),
		Verbose:  verbose,
	}
}

// Connect dials the DC, trying port 389 first then 636 (LDAPS).
func (c *Client) Connect() error {
	address := fmt.Sprintf("%s:%d", c.Host, c.Port)

	if c.Verbose {
		color.Blue("[*] Connecting to %s", address)
	}

	conn, wrap, err := c.dialWithTimeout(address, false)
	if err != nil {
		// fallback to LDAPS port 636
		if !c.Quiet {
			color.White("  port 389 failed, trying LDAPS 636...")
		}
		c.Port = 636
		address = fmt.Sprintf("%s:%d", c.Host, c.Port)
		conn, wrap, err = c.dialWithTimeout(address, true)
		if err != nil {
			return friendlyLDAPError(fmt.Errorf("connection failed on both 389 and 636: %w", err))
		}
	}

	c.conn = conn
	c.saslWrap = wrap

	if c.Verbose {
		color.Green("[+] Connected to %s", address)
	}

	return nil
}

// dialWithTimeout opens a connection with a timeout.
// If ProxyURL is set, traffic routes through a SOCKS5 proxy (DNS resolved on the proxy side).
// Returns a go-ldap Conn, saslConn (for Kerberos wrapping), and an error.
// NOTE: PTT (Kerberos ccache) is not supported through a proxy — use password or PTH instead.
func (c *Client) dialWithTimeout(address string, useTLS bool) (*goldap.Conn, *saslConn, error) {
	timeout := 10 * time.Second

	dialer, err := c.buildDialer(timeout)
	if err != nil {
		return nil, nil, fmt.Errorf("proxy setup failed: %w", err)
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         c.Host,
	}

	if useTLS {
		netConn, err := dialer.Dial("tcp", address)
		if err != nil {
			return nil, nil, err
		}
		tlsConn := tls.Client(netConn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			netConn.Close()
			return nil, nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		conn := goldap.NewConn(tlsConn, true)
		conn.Start()
		return conn, nil, nil
	}

	netConn, err := dialer.Dial("tcp", address)
	if err != nil {
		return nil, nil, err
	}

	wrap := newSASLConn(netConn)
	conn := goldap.NewConn(wrap, false)
	conn.Start()
	return conn, wrap, nil
}

// buildDialer returns a plain net.Dialer or a SOCKS5 proxy dialer depending on ProxyURL.
func (c *Client) buildDialer(timeout time.Duration) (dialerIface, error) {
	if c.ProxyURL == "" {
		return &net.Dialer{Timeout: timeout}, nil
	}

	u, err := url.Parse(c.ProxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", c.ProxyURL, err)
	}
	if u.Scheme != "socks5" {
		return nil, fmt.Errorf("unsupported proxy scheme %q (only socks5 supported)", u.Scheme)
	}

	var auth *proxy.Auth
	if u.User != nil {
		pass, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pass}
	}

	d, err := proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 dialer creation failed: %w", err)
	}
	return d, nil
}

// dialerIface is satisfied by both *net.Dialer and proxy.Dialer.
type dialerIface interface {
	Dial(network, addr string) (net.Conn, error)
}

// Bind authenticates to the LDAP server.
func (c *Client) Bind() error {
	if c.conn == nil {
		return fmt.Errorf("not connected, call Connect() first")
	}

	// use PrimaryDomain for cross-domain binds (user lives in primary, not trusted domain)
	authDomain := c.Domain
	if c.PrimaryDomain != "" {
		authDomain = c.PrimaryDomain
	}
	upn := fmt.Sprintf("%s@%s", c.Username, authDomain)

	if c.Verbose {
		color.Blue("[*] Binding as %s", upn)
	}

	err := c.conn.Bind(upn, c.Password)
	if err != nil {
		// retry with DOMAIN\user format
		nt := fmt.Sprintf("%s\\%s", strings.ToUpper(strings.Split(authDomain, ".")[0]), c.Username)
		err2 := c.conn.Bind(nt, c.Password)
		if err2 != nil {
			return friendlyLDAPError(err)
		}
	}

	if !c.Quiet {
		color.Green("  authenticated     %s@%s", c.Username, c.Domain)
	}
	return nil
}

// BindNTLM performs Pass-the-Hash authentication via NTLM.
// NTHash must be a 32-character hex string without colons.
func (c *Client) BindNTLM() error {
	if c.conn == nil {
		return fmt.Errorf("not connected, call Connect() first")
	}

	authDomain := c.Domain
	if c.PrimaryDomain != "" {
		authDomain = c.PrimaryDomain
	}
	netbiosDomain := strings.ToUpper(strings.Split(authDomain, ".")[0])

	if c.Verbose {
		color.Blue("[*] NTLM bind (Pass-the-Hash) as %s\\%s", netbiosDomain, c.Username)
	}

	if err := c.conn.NTLMBindWithHash(netbiosDomain, c.Username, c.NTHash); err != nil {
		return friendlyLDAPError(err)
	}

	if !c.Quiet {
		color.Green("  authenticated     %s\\%s  (PTH/NTLM)", netbiosDomain, c.Username)
	}
	return nil
}

// BindKerberos performs Pass-the-Ticket authentication from a ccache file.
func (c *Client) BindKerberos() error {
	if c.conn == nil {
		return fmt.Errorf("not connected, call Connect() first")
	}

	if c.Verbose {
		color.Blue("[*] Kerberos bind (Pass-the-Ticket) from ccache: %s", c.CcachePath)
	}

	// Kerberos requires an FQDN SPN — resolve IP to hostname if needed
	host := c.kerberosHost()

	gssClient, err := NewKerberosClientFromCCache(c.CcachePath, host, c.Domain)
	if err != nil {
		return fmt.Errorf("kerberos init: %w", err)
	}

	spn := fmt.Sprintf("ldap/%s", host)
	if c.Verbose {
		color.Blue("[*] Kerberos SPN: %s", spn)
	}
	if err := c.conn.GSSAPIBind(gssClient, spn, ""); err != nil {
		return fmt.Errorf("kerberos bind failed: %w", err)
	}

	// Activate SASL message wrapping using the Kerberos session key.
	// After SPNEGO GSSAPI bind, Windows encrypts all subsequent LDAP PDUs
	// using the session key established during the AP-REQ/AP-REP exchange.
	if c.saslWrap != nil && gssClient.sessionKey.KeyType != 0 {
		c.saslWrap.Activate(gssClient.sessionKey)
		if c.Verbose {
			color.Blue("[*] SASL wrapping activated (keytype=%d)", gssClient.sessionKey.KeyType)
		}
	}

	if !c.Quiet {
		color.Green("  authenticated     %s  (PTT/Kerberos)", c.Username)
	}
	return nil
}

// AnonymousBind tests null session access.
func (c *Client) AnonymousBind() error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	err := c.conn.UnauthenticatedBind("")
	if err != nil {
		return friendlyLDAPError(err)
	}

	c.IsAnon = true
	if !c.Quiet {
		color.Yellow("  null session      anonymous bind OK")
	}
	return nil
}

// ProbeAnonymousRead attempts a minimal LDAP search to check whether anonymous
// sessions can read AD objects beyond RootDSE.
// Returns true if any user/group objects are readable without credentials.
func (c *Client) ProbeAnonymousRead() bool {
	if c.conn == nil || !c.IsAnon {
		return false
	}
	req := goldap.NewSearchRequest(
		c.BaseDN,
		goldap.ScopeSingleLevel,
		goldap.NeverDerefAliases,
		1, 5, false,
		"(objectClass=user)",
		[]string{"sAMAccountName"},
		nil,
	)
	sr, err := c.conn.Search(req)
	return err == nil && len(sr.Entries) > 0
}

// Search performs an LDAP search with automatic paging (1000 entries per page).
func (c *Client) Search(filter string, attributes []string) ([]*goldap.Entry, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	var allEntries []*goldap.Entry

	searchReq := goldap.NewSearchRequest(
		c.BaseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0,     // size limit (0 = no limit)
		30,    // time limit seconds
		false, // types only
		filter,
		attributes,
		nil,
	)

	// paging: large AD environments can have thousands of objects
	pagingControl := goldap.NewControlPaging(1000)
	searchReq.Controls = append(searchReq.Controls, pagingControl)

	for {
		result, err := c.conn.Search(searchReq)
		if err != nil {
			return nil, friendlyLDAPError(fmt.Errorf("search failed [filter: %s]: %w", filter, err))
		}

		allEntries = append(allEntries, result.Entries...)

		// check if more pages remain
		updatedControl := goldap.FindControl(result.Controls, goldap.ControlTypePaging)
		if updatedControl == nil {
			break
		}

		pagingResult, ok := updatedControl.(*goldap.ControlPaging)
		if !ok || len(pagingResult.Cookie) == 0 {
			break
		}

		pagingControl.SetCookie(pagingResult.Cookie)
	}

	return allEntries, nil
}

// SearchBase performs a search with an explicit base DN (overrides c.BaseDN).
func (c *Client) SearchBase(baseDN, filter string, attributes []string) ([]*goldap.Entry, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}
	searchReq := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 30, false,
		filter,
		attributes,
		nil,
	)
	result, err := c.conn.Search(searchReq)
	if err != nil {
		return nil, friendlyLDAPError(fmt.Errorf("search failed [base: %s, filter: %s]: %w", baseDN, filter, err))
	}
	return result.Entries, nil
}

// SearchGC connects to Global Catalog (port 3268) and searches the entire forest.
// Returns all objects across all domains in the forest.
// Supports password and NTLM hash auth; Kerberos ccache not yet supported.
func (c *Client) SearchGC(filter string, attributes []string) ([]*goldap.Entry, error) {
	gcAddress := fmt.Sprintf("%s:3268", c.Host)

	netConn, err := net.DialTimeout("tcp", gcAddress, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("GC connection to %s failed: %w", gcAddress, err)
	}

	wrap := newSASLConn(netConn)
	gcConn := goldap.NewConn(wrap, false)
	gcConn.Start()
	defer gcConn.Close()

	switch {
	case c.NTHash != "":
		netbios := strings.ToUpper(strings.Split(c.Domain, ".")[0])
		if err := gcConn.NTLMBindWithHash(netbios, c.Username, c.NTHash); err != nil {
			return nil, friendlyLDAPError(err)
		}
	case c.Password != "" && c.Username != "":
		upn := fmt.Sprintf("%s@%s", c.Username, c.Domain)
		if err := gcConn.Bind(upn, c.Password); err != nil {
			return nil, friendlyLDAPError(err)
		}
	default:
		return nil, fmt.Errorf("GC query requires credentials (anonymous/Kerberos not supported for GC yet)")
	}

	searchReq := goldap.NewSearchRequest(
		"", // empty base = forest-wide
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 30, false,
		filter,
		attributes,
		nil,
	)
	pagingControl := goldap.NewControlPaging(1000)
	searchReq.Controls = append(searchReq.Controls, pagingControl)

	var allEntries []*goldap.Entry
	for {
		result, err := gcConn.Search(searchReq)
		if err != nil {
			return nil, friendlyLDAPError(fmt.Errorf("GC search failed: %w", err))
		}
		allEntries = append(allEntries, result.Entries...)

		updated := goldap.FindControl(result.Controls, goldap.ControlTypePaging)
		if updated == nil {
			break
		}
		paging, ok := updated.(*goldap.ControlPaging)
		if !ok || len(paging.Cookie) == 0 {
			break
		}
		pagingControl.SetCookie(paging.Cookie)
	}

	return allEntries, nil
}

// SearchDomain connects to a specific DC and searches a given base DN.
// Used for cross-domain queries with full attribute resolution.
func (c *Client) SearchDomain(dc, baseDN, filter string, attributes []string) ([]*goldap.Entry, error) {
	address := fmt.Sprintf("%s:389", dc)

	netConn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("cross-domain connection to %s failed: %w", address, err)
	}

	wrap := newSASLConn(netConn)
	conn := goldap.NewConn(wrap, false)
	conn.Start()
	defer conn.Close()

	switch {
	case c.NTHash != "":
		netbios := strings.ToUpper(strings.Split(c.Domain, ".")[0])
		if err := conn.NTLMBindWithHash(netbios, c.Username, c.NTHash); err != nil {
			return nil, friendlyLDAPError(err)
		}
	case c.Password != "" && c.Username != "":
		upn := fmt.Sprintf("%s@%s", c.Username, c.Domain)
		if err := conn.Bind(upn, c.Password); err != nil {
			return nil, friendlyLDAPError(err)
		}
	default:
		return nil, fmt.Errorf("cross-domain query requires credentials")
	}

	searchReq := goldap.NewSearchRequest(
		baseDN,
		goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases,
		0, 30, false,
		filter,
		attributes,
		nil,
	)
	pagingControl := goldap.NewControlPaging(1000)
	searchReq.Controls = append(searchReq.Controls, pagingControl)

	var allEntries []*goldap.Entry
	for {
		result, err := conn.Search(searchReq)
		if err != nil {
			return nil, friendlyLDAPError(fmt.Errorf("cross-domain search failed: %w", err))
		}
		allEntries = append(allEntries, result.Entries...)

		updated := goldap.FindControl(result.Controls, goldap.ControlTypePaging)
		if updated == nil {
			break
		}
		paging, ok := updated.(*goldap.ControlPaging)
		if !ok || len(paging.Cookie) == 0 {
			break
		}
		pagingControl.SetCookie(paging.Cookie)
	}

	return allEntries, nil
}

// Close terminates the LDAP connection.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
		if c.Verbose {
			color.Blue("[*] Connection closed")
		}
	}
}

// GetBaseDN returns the base DN.
func (c *Client) GetBaseDN() string {
	return c.BaseDN
}

// GetConn returns the active LDAP connection.
func (c *Client) GetConn() *goldap.Conn {
    return c.conn
}

// SearchACL performs an LDAP search requesting nTSecurityDescriptor.
func (c *Client) SearchACL() ([]*goldap.Entry, error) {
    sdControl := goldap.NewControlString(
        "1.2.840.113556.1.4.801",
        true,
        string([]byte{0x30, 0x03, 0x02, 0x01, 0x04}),
    )

		filter := "(|(objectClass=user)(objectClass=group)(objectClass=computer)(objectClass=organizationalUnit)(objectClass=domainDNS))"

    searchReq := goldap.NewSearchRequest(
        c.BaseDN,
        goldap.ScopeWholeSubtree,
        goldap.NeverDerefAliases,
        0, 30, false,
        filter,
        []string{"distinguishedName", "sAMAccountName", "objectClass", "nTSecurityDescriptor"},
        []goldap.Control{sdControl},
    )

    result, err := c.conn.Search(searchReq)
    if err != nil {
        return nil, fmt.Errorf("ACL search error: %w", err)
    }

    return result.Entries, nil
}

// kerberosHost returns the FQDN for building the LDAP SPN.
// Kerberos requires a hostname, not an IP. If c.Host looks like an IP,
// we perform a reverse DNS lookup. If that fails, we fall back to the IP
// and let the KDC return a helpful error.
func (c *Client) kerberosHost() string {
	if net.ParseIP(c.Host) == nil {
		return c.Host // already a hostname
	}
	names, err := net.LookupAddr(c.Host)
	if err != nil || len(names) == 0 {
		if !c.Quiet {
			color.Yellow("[!] Reverse DNS lookup for %s failed: %v — using IP for SPN (may fail)", c.Host, err)
		}
		return c.Host
	}
	// LookupAddr returns names with a trailing dot; strip it
	fqdn := strings.TrimSuffix(names[0], ".")
	if c.Verbose {
		color.Blue("[*] Resolved %s → %s", c.Host, fqdn)
	}
	return fqdn
}

// domainToBaseDN converts "corp.local" → "DC=corp,DC=local".
func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}

// GetDomain returns the domain name.
func (c *Client) GetDomain() string {
    return c.Domain
}

// GetHost returns the DC hostname or IP.
func (c *Client) GetHost() string {
    return c.Host
}

// ConfigurationDN returns the AD configuration partition DN
// (CN=Configuration,DC=...) from RootDSE or derived from the domain.
func (c *Client) ConfigurationDN() (string, error) {
    req := goldap.NewSearchRequest(
        "",
        goldap.ScopeBaseObject, goldap.NeverDerefAliases,
        0, 0, false,
        "(objectClass=*)",
        []string{"configurationNamingContext"},
        nil,
    )
    sr, err := c.conn.Search(req)
    if err != nil || len(sr.Entries) == 0 {
        // fallback
        return "CN=Configuration," + c.BaseDN, nil
    }
    val := sr.Entries[0].GetAttributeValue("configurationNamingContext")
    if val == "" {
        return "CN=Configuration," + c.BaseDN, nil
    }
    return val, nil
}

// RootDSEInfo contains information readable from RootDSE without authentication.
type RootDSEInfo struct {
	DefaultNamingContext    string // e.g. DC=corp,DC=local
	ForestNamingContext     string // e.g. DC=corp,DC=local
	ConfigurationDN         string // CN=Configuration,...
	SchemaDN                string // CN=Schema,...
	DomainFunctionality    string // 0=2000, 2=2003, 3=2008, 4=2008R2, 5=2012, 6=2012R2, 7=2016+
	ForestFunctionality    string
	DomainControllerFunctionality string
	ServerName             string // FQDN of responding DC
	SupportedLDAPVersion    []string
	SupportedSASLMechanisms []string
	SupportedCapabilities   []string // OIDs, e.g. 1.2.840.113556.1.4.1791 = LDAP signing support
	PlainLDAP               bool     // true if connection is on port 389 (not LDAPS)
}

// functionalityLevel maps AD functional level integer to human name.
var functionalityLevel = map[string]string{
	"0": "Windows 2000",
	"1": "Windows Server 2003 Mixed",
	"2": "Windows Server 2003",
	"3": "Windows Server 2008",
	"4": "Windows Server 2008 R2",
	"5": "Windows Server 2012",
	"6": "Windows Server 2012 R2",
	"7": "Windows Server 2016/2019/2022",
}

// QueryRootDSE reads RootDSE attributes — available without authentication.
// Call after Connect() but before (or without) Bind().
func (c *Client) QueryRootDSE() (*RootDSEInfo, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("not connected")
	}
	req := goldap.NewSearchRequest(
		"",
		goldap.ScopeBaseObject, goldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{
			"defaultNamingContext",
			"rootDomainNamingContext",
			"configurationNamingContext",
			"schemaNamingContext",
			"domainFunctionality",
			"forestFunctionality",
			"domainControllerFunctionality",
			"dnsHostName",
			"supportedLDAPVersion",
			"supportedSASLMechanisms",
			"supportedCapabilities",
		},
		nil,
	)
	sr, err := c.conn.Search(req)
	if err != nil || len(sr.Entries) == 0 {
		return nil, fmt.Errorf("RootDSE query failed: %w", err)
	}
	e := sr.Entries[0]
	return &RootDSEInfo{
		DefaultNamingContext:           e.GetAttributeValue("defaultNamingContext"),
		ForestNamingContext:            e.GetAttributeValue("rootDomainNamingContext"),
		ConfigurationDN:                e.GetAttributeValue("configurationNamingContext"),
		SchemaDN:                       e.GetAttributeValue("schemaNamingContext"),
		DomainFunctionality:            e.GetAttributeValue("domainFunctionality"),
		ForestFunctionality:            e.GetAttributeValue("forestFunctionality"),
		DomainControllerFunctionality:  e.GetAttributeValue("domainControllerFunctionality"),
		ServerName:                     e.GetAttributeValue("dnsHostName"),
		SupportedLDAPVersion:    e.GetAttributeValues("supportedLDAPVersion"),
		SupportedSASLMechanisms: e.GetAttributeValues("supportedSASLMechanisms"),
		SupportedCapabilities:   e.GetAttributeValues("supportedCapabilities"),
		PlainLDAP:               c.Port == 389,
	}, nil
}

// FunctionalityLevelName returns human-readable name for a functionality level integer string.
func FunctionalityLevelName(level string) string {
	if name, ok := functionalityLevel[level]; ok {
		return name
	}
	return "Unknown (level " + level + ")"
}