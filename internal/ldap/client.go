package ldap

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fatih/color"
	goldap "github.com/go-ldap/ldap/v3"
)

// Client зберігає параметри підключення та активне з'єднання
type Client struct {
	Host       string
	Port       int
	Domain     string
	Username   string
	Password   string
	NTHash     string // NT hash for Pass-the-Hash (NTLM auth)
	CcachePath string // path to ccache file for Pass-the-Ticket (Kerberos auth)
	BaseDN     string
	conn       *goldap.Conn
	saslWrap   *saslConn // non-nil only for Kerberos ccache connections
	Verbose    bool
}

// NewClient створює новий Client
// dc — IP або hostname DC, якщо порожній — autodiscover через DNS
func NewClient(domain, username, password, dc string, verbose bool) *Client {
	host := dc
	if host == "" {
		host = domain // fallback: go-ldap сам резолвить
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

// Connect встановлює з'єднання: спочатку 389, потім 636 (LDAPS)
func (c *Client) Connect() error {
	address := fmt.Sprintf("%s:%d", c.Host, c.Port)

	if c.Verbose {
		color.Blue("[*] Connecting to %s", address)
	}

	conn, wrap, err := c.dialWithTimeout(address, false)
	if err != nil {
		// fallback на LDAPS port 636
		color.Yellow("[!] Port 389 failed, trying LDAPS (636)...")
		c.Port = 636
		address = fmt.Sprintf("%s:%d", c.Host, c.Port)
		conn, wrap, err = c.dialWithTimeout(address, true)
		if err != nil {
			return fmt.Errorf("connection failed on both 389 and 636: %w", err)
		}
	}

	c.conn = conn
	c.saslWrap = wrap

	if c.Verbose {
		color.Green("[+] Connected to %s", address)
	}

	return nil
}

// dialWithTimeout відкриває з'єднання з таймаутом.
// Повертає go-ldap Conn, saslConn (для Kerberos wrapping), і помилку.
func (c *Client) dialWithTimeout(address string, useTLS bool) (*goldap.Conn, *saslConn, error) {
	timeout := 10 * time.Second

	if useTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true, // для пентесту прийнятно
			ServerName:         c.Host,
		}
		conn, err := goldap.DialTLS("tcp", address, tlsCfg)
		return conn, nil, err
	}

	// Створюємо saslConn-обгортку — passthrough до Activate()
	netConn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, nil, err
	}

	wrap := newSASLConn(netConn)
	conn := goldap.NewConn(wrap, false)
	conn.Start()
	return conn, wrap, nil
}

// Bind виконує автентифікацію
func (c *Client) Bind() error {
	if c.conn == nil {
		return fmt.Errorf("not connected, call Connect() first")
	}

	// формат: DOMAIN\username або username@domain
	upn := fmt.Sprintf("%s@%s", c.Username, c.Domain)

	if c.Verbose {
		color.Blue("[*] Binding as %s", upn)
	}

	err := c.conn.Bind(upn, c.Password)
	if err != nil {
		// спробуй DOMAIN\user формат
		nt := fmt.Sprintf("%s\\%s", strings.ToUpper(strings.Split(c.Domain, ".")[0]), c.Username)
		err2 := c.conn.Bind(nt, c.Password)
		if err2 != nil {
			return fmt.Errorf("bind failed (tried UPN and NT format): %w", err)
		}
	}

	color.Green("[+] Authenticated as %s", upn)
	return nil
}

// BindNTLM виконує Pass-the-Hash автентифікацію через NTLM.
// Потребує NTHash у форматі hex (32 символи, без двокрапок).
func (c *Client) BindNTLM() error {
	if c.conn == nil {
		return fmt.Errorf("not connected, call Connect() first")
	}

	netbiosDomain := strings.ToUpper(strings.Split(c.Domain, ".")[0])

	if c.Verbose {
		color.Blue("[*] NTLM bind (Pass-the-Hash) as %s\\%s", netbiosDomain, c.Username)
	}

	if err := c.conn.NTLMBindWithHash(netbiosDomain, c.Username, c.NTHash); err != nil {
		return fmt.Errorf("NTLM bind failed: %w", err)
	}

	color.Green("[+] Authenticated via NTLM (Pass-the-Hash) as %s\\%s", netbiosDomain, c.Username)
	return nil
}

// BindKerberos виконує Pass-the-Ticket автентифікацію через ccache файл.
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

	color.Green("[+] Authenticated via Kerberos (ccache: %s)", c.CcachePath)
	return nil
}

// AnonymousBind перевіряє null session
func (c *Client) AnonymousBind() error {
	if c.conn == nil {
		return fmt.Errorf("not connected")
	}

	err := c.conn.UnauthenticatedBind("")
	if err != nil {
		return fmt.Errorf("anonymous bind failed (null sessions disabled): %w", err)
	}

	color.Yellow("[!] Anonymous bind successful — null session enabled!")
	return nil
}

// Search виконує LDAP пошук з автоматичним paging (1000 записів за раз)
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

	// paging: великі AD можуть мати тисячі об'єктів
	pagingControl := goldap.NewControlPaging(1000)
	searchReq.Controls = append(searchReq.Controls, pagingControl)

	for {
		result, err := c.conn.Search(searchReq)
		if err != nil {
			return nil, fmt.Errorf("search failed [filter: %s]: %w", filter, err)
		}

		allEntries = append(allEntries, result.Entries...)

		// перевірка чи є ще сторінки
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
		return nil, fmt.Errorf("search failed [base: %s, filter: %s]: %w", baseDN, filter, err)
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
			return nil, fmt.Errorf("GC NTLM bind: %w", err)
		}
	case c.Password != "" && c.Username != "":
		upn := fmt.Sprintf("%s@%s", c.Username, c.Domain)
		if err := gcConn.Bind(upn, c.Password); err != nil {
			return nil, fmt.Errorf("GC bind: %w", err)
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
			return nil, fmt.Errorf("GC search failed: %w", err)
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
			return nil, fmt.Errorf("cross-domain NTLM bind: %w", err)
		}
	case c.Password != "" && c.Username != "":
		upn := fmt.Sprintf("%s@%s", c.Username, c.Domain)
		if err := conn.Bind(upn, c.Password); err != nil {
			return nil, fmt.Errorf("cross-domain bind: %w", err)
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
			return nil, fmt.Errorf("cross-domain search failed: %w", err)
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

// Close закриває з'єднання
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
		if c.Verbose {
			color.Blue("[*] Connection closed")
		}
	}
}

// GetBaseDN повертає BaseDN
func (c *Client) GetBaseDN() string {
	return c.BaseDN
}

// GetConn повертає активне з'єднання
func (c *Client) GetConn() *goldap.Conn {
    return c.conn
}

// SearchACL виконує LDAP пошук з nTSecurityDescriptor
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
		color.Yellow("[!] Reverse DNS lookup for %s failed: %v — using IP for SPN (may fail)", c.Host, err)
		return c.Host
	}
	// LookupAddr returns names with a trailing dot; strip it
	fqdn := strings.TrimSuffix(names[0], ".")
	if c.Verbose {
		color.Blue("[*] Resolved %s → %s", c.Host, fqdn)
	}
	return fqdn
}

// domainToBaseDN конвертує "corp.local" → "DC=corp,DC=local"
func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}

// GetDomain повертає домен
func (c *Client) GetDomain() string {
    return c.Domain
}