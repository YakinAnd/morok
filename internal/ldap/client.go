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
	Host     string
	Port     int
	Domain   string
	Username string
	Password string
	BaseDN   string
	conn     *goldap.Conn
	Verbose  bool
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

	conn, err := c.dialWithTimeout(address, false)
	if err != nil {
		// fallback на LDAPS port 636
		color.Yellow("[!] Port 389 failed, trying LDAPS (636)...")
		c.Port = 636
		address = fmt.Sprintf("%s:%d", c.Host, c.Port)
		conn, err = c.dialWithTimeout(address, true)
		if err != nil {
			return fmt.Errorf("connection failed on both 389 and 636: %w", err)
		}
	}

	c.conn = conn

	if c.Verbose {
		color.Green("[+] Connected to %s", address)
	}

	return nil
}

// dialWithTimeout відкриває з'єднання з таймаутом
func (c *Client) dialWithTimeout(address string, useTLS bool) (*goldap.Conn, error) {
	timeout := 10 * time.Second

	if useTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true, // для пентесту прийнятно
			ServerName:         c.Host,
		}
		return goldap.DialTLS("tcp", address, tlsCfg)
	}

	// звичайний dial з таймаутом
	netConn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, err
	}

	conn := goldap.NewConn(netConn, false)
	conn.Start()
	return conn, nil
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

// domainToBaseDN конвертує "corp.local" → "DC=corp,DC=local"
func domainToBaseDN(domain string) string {
	parts := strings.Split(domain, ".")
	dcs := make([]string, len(parts))
	for i, p := range parts {
		dcs[i] = "DC=" + p
	}
	return strings.Join(dcs, ",")
}
