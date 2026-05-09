package kerberos

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// UserStatus is the result of probing a single username.
type UserStatus int

const (
	StatusNotFound  UserStatus = iota // KDC_ERR_C_PRINCIPAL_UNKNOWN
	StatusExists                      // KDC_ERR_PREAUTH_REQUIRED
	StatusASREP                       // AS-REP received — no pre-auth (roastable)
	StatusDisabled                    // KDC_ERR_CLIENT_REVOKED
	StatusExpired                     // KDC_ERR_KEY_EXPIRED
	StatusError                       // connection or parse error
)

// UserResult holds the probe result for one username.
type UserResult struct {
	Username string
	Status   UserStatus
	Err      error
}

// EnumUsersResult aggregates all probe results.
type EnumUsersResult struct {
	Domain  string
	DC      string
	Results []UserResult
}

// EnumUsers probes each username in wordlistPath against the KDC.
// It does NOT require credentials — only network access to DC:88.
func EnumUsers(domain, dc, wordlistPath string) (*EnumUsersResult, error) {
	usernames, err := readWordlist(wordlistPath)
	if err != nil {
		return nil, fmt.Errorf("wordlist: %w", err)
	}

	realm := strings.ToUpper(domain)
	addr := dc + ":88"

	cfg := buildConfig(realm, addr)

	result := &EnumUsersResult{Domain: domain, DC: dc}

	color.Cyan("\n  ENUM-USERS")
	color.White("  %-24s %s", "domain", domain)
	color.White("  %-24s %s", "kdc", addr)
	color.White("  %-24s %d", "wordlist size", len(usernames))
	fmt.Println()

	found := 0
	for _, username := range usernames {
		r := probe(username, realm, addr, cfg)
		result.Results = append(result.Results, r)

		switch r.Status {
		case StatusExists:
			color.Green("  [+] %-30s EXISTS", username)
			found++
		case StatusASREP:
			color.Red("  [!] %-30s EXISTS  (AS-REP roastable — no pre-auth)", username)
			found++
		case StatusDisabled:
			color.Yellow("  [-] %-30s DISABLED", username)
			found++
		case StatusExpired:
			color.Yellow("  [~] %-30s EXISTS  (password expired)", username)
			found++
		case StatusNotFound:
			if false { // suppress not-found by default for cleaner output
				color.White("      %-30s not found", username)
			}
		case StatusError:
			color.White("  [?] %-30s error: %v", username, r.Err)
		}
	}

	fmt.Println()
	color.White("  %-24s %d / %d", "found", found, len(usernames))
	return result, nil
}

// probe sends a single AS-REQ and classifies the response.
func probe(username, realm, addr string, cfg *config.Config) UserResult {
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, username)
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+realm)

	asreq, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		return UserResult{Username: username, Status: StatusError, Err: err}
	}
	_ = sname

	b, err := asreq.Marshal()
	if err != nil {
		return UserResult{Username: username, Status: StatusError, Err: err}
	}

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return UserResult{Username: username, Status: StatusError, Err: fmt.Errorf("connect: %w", err)}
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// KRB5 over TCP: 4-byte big-endian length prefix
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(b)))
	if _, err = conn.Write(append(hdr, b...)); err != nil {
		return UserResult{Username: username, Status: StatusError, Err: fmt.Errorf("send: %w", err)}
	}

	// Read response length
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return UserResult{Username: username, Status: StatusError, Err: fmt.Errorf("recv header: %w", err)}
	}
	respLen := binary.BigEndian.Uint32(hdr)
	if respLen == 0 || respLen > 1<<20 {
		return UserResult{Username: username, Status: StatusError, Err: fmt.Errorf("invalid response length: %d", respLen)}
	}

	resp := make([]byte, respLen)
	if _, err = io.ReadFull(conn, resp); err != nil {
		return UserResult{Username: username, Status: StatusError, Err: fmt.Errorf("recv body: %w", err)}
	}

	return classify(username, resp)
}

// classify determines user status from the raw KRB5 response bytes.
// ASN.1 APPLICATION tags:
//   - 0x6b = APPLICATION 11 (AS-REP) → user exists, no pre-auth required
//   - 0x7e = APPLICATION 30 (KRB-ERROR) → parse error code
func classify(username string, resp []byte) UserResult {
	if len(resp) == 0 {
		return UserResult{Username: username, Status: StatusError, Err: fmt.Errorf("empty response")}
	}

	switch resp[0] {
	case 0x6b: // AS-REP — user has no pre-auth required (roastable)
		return UserResult{Username: username, Status: StatusASREP}

	case 0x7e: // KRB-ERROR
		var krbErr messages.KRBError
		if err := krbErr.Unmarshal(resp); err != nil {
			return UserResult{Username: username, Status: StatusError, Err: fmt.Errorf("parse krb error: %w", err)}
		}
		return classifyErrorCode(username, krbErr.ErrorCode)

	default:
		return UserResult{Username: username, Status: StatusError,
			Err: fmt.Errorf("unexpected response tag: 0x%02x", resp[0])}
	}
}

func classifyErrorCode(username string, code int32) UserResult {
	switch code {
	case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
		return UserResult{Username: username, Status: StatusNotFound}
	case errorcode.KDC_ERR_PREAUTH_REQUIRED:
		return UserResult{Username: username, Status: StatusExists}
	case errorcode.KDC_ERR_CLIENT_REVOKED:
		return UserResult{Username: username, Status: StatusDisabled}
	case errorcode.KDC_ERR_KEY_EXPIRED:
		return UserResult{Username: username, Status: StatusExpired}
	default:
		// Any other error means the principal exists (pre-auth failed, etc.)
		return UserResult{Username: username, Status: StatusExists}
	}
}

func buildConfig(realm, addr string) *config.Config {
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.NoAddresses = true
	cfg.Realms = []config.Realm{
		{
			Realm: realm,
			KDC:   []string{addr},
		},
	}
	return cfg
}

func readWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var users []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			users = append(users, line)
		}
	}
	return users, sc.Err()
}
