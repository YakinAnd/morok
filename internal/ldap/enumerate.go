package ldap

import (
	"fmt"
	"strconv"
	"time"

	"github.com/fatih/color"
	goldap "github.com/go-ldap/ldap/v3"
)

// ============================================================
// Моделі даних
// ============================================================

// LDAPUser представляє користувача AD
type LDAPUser struct {
	DN               string
	SAMAccountName   string
	DisplayName      string
	Description      string
	Mail             string
	MemberOf         []string
	SPNs             []string
	AdminCount       bool
	Enabled          bool
	PasswordNeverExpires bool
	DontReqPreauth   bool   // AS-REP roastable
	LastLogon        string
	PasswordLastSet  string
	ObjectSid        string
}

// LDAPGroup представляє групу AD
type LDAPGroup struct {
	DN             string
	SAMAccountName string
	Description    string
	Members        []string // DN членів
	AdminCount     bool
	GroupType      string
	ObjectSid      string
}

// LDAPComputer представляє комп'ютер AD
type LDAPComputer struct {
	DN                     string
	SAMAccountName         string
	DNSHostName            string
	OperatingSystem        string
	OperatingSystemVersion string
	Enabled                bool
	LastLogon              string
	SPNs                   []string
	UnconstrainedDelegation bool
	ObjectSid              string
}

// EnumerationResult містить всі зібрані дані
type EnumerationResult struct {
	Domain    string
	BaseDN    string
	Users     []LDAPUser
	Groups    []LDAPGroup
	Computers []LDAPComputer
	CollectedAt time.Time
}

// ============================================================
// LDAP фільтри
// ============================================================

const (
	FilterAllUsers      = "(&(objectClass=user)(objectCategory=person))"
	FilterAllGroups     = "(objectClass=group)"
	FilterAllComputers  = "(objectClass=computer)"
	FilterKerberoastable = "(&(objectClass=user)(servicePrincipalName=*)(!sAMAccountName=krbtgt)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
	FilterASREP         = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
)

// ============================================================
// Атрибути для запитів
// ============================================================

var userAttributes = []string{
	"distinguishedName",
	"sAMAccountName",
	"displayName",
	"description",
	"mail",
	"memberOf",
	"servicePrincipalName",
	"adminCount",
	"userAccountControl",
	"lastLogonTimestamp",
	"pwdLastSet",
	"objectSid",
}

var groupAttributes = []string{
	"distinguishedName",
	"sAMAccountName",
	"description",
	"member",
	"adminCount",
	"groupType",
	"objectSid",
}

var computerAttributes = []string{
	"distinguishedName",
	"sAMAccountName",
	"dNSHostName",
	"operatingSystem",
	"operatingSystemVersion",
	"userAccountControl",
	"lastLogonTimestamp",
	"servicePrincipalName",
	"objectSid",
}

// ============================================================
// Основні функції enumeration
// ============================================================

// EnumerateAll запускає повний enumeration і повертає результат
func (c *Client) EnumerateAll() (*EnumerationResult, error) {
	result := &EnumerationResult{
		Domain:      c.Domain,
		BaseDN:      c.BaseDN,
		CollectedAt: time.Now(),
	}

	color.Cyan("\n[*] Starting enumeration of %s\n", c.Domain)

	// Users
	users, err := c.EnumerateUsers()
	if err != nil {
		return nil, fmt.Errorf("user enumeration failed: %w", err)
	}
	result.Users = users

	// Groups
	groups, err := c.EnumerateGroups()
	if err != nil {
		return nil, fmt.Errorf("group enumeration failed: %w", err)
	}
	result.Groups = groups

	// Computers
	computers, err := c.EnumerateComputers()
	if err != nil {
		return nil, fmt.Errorf("computer enumeration failed: %w", err)
	}
	result.Computers = computers

	// Підсумок
	color.Cyan("\n[*] Enumeration complete:")
	color.Green("    Users:     %d", len(result.Users))
	color.Green("    Groups:    %d", len(result.Groups))
	color.Green("    Computers: %d", len(result.Computers))

	// Швидкий аналіз цікавих об'єктів
	c.printQuickFindings(result)

	return result, nil
}

// EnumerateUsers збирає всіх користувачів AD
func (c *Client) EnumerateUsers() ([]LDAPUser, error) {
	color.Blue("[*] Enumerating users...")

	entries, err := c.Search(FilterAllUsers, userAttributes)
	if err != nil {
		return nil, err
	}

	users := make([]LDAPUser, 0, len(entries))

	for _, entry := range entries {
		user := parseUser(entry)
		users = append(users, user)
	}

	color.Green("[+] Found %d users", len(users))
	return users, nil
}

// EnumerateGroups збирає всі групи AD
func (c *Client) EnumerateGroups() ([]LDAPGroup, error) {
	color.Blue("[*] Enumerating groups...")

	entries, err := c.Search(FilterAllGroups, groupAttributes)
	if err != nil {
		return nil, err
	}

	groups := make([]LDAPGroup, 0, len(entries))

	for _, entry := range entries {
		group := parseGroup(entry)
		groups = append(groups, group)
	}

	color.Green("[+] Found %d groups", len(groups))
	return groups, nil
}

// EnumerateComputers збирає всі комп'ютери AD
func (c *Client) EnumerateComputers() ([]LDAPComputer, error) {
	color.Blue("[*] Enumerating computers...")

	entries, err := c.Search(FilterAllComputers, computerAttributes)
	if err != nil {
		return nil, err
	}

	computers := make([]LDAPComputer, 0, len(entries))

	for _, entry := range entries {
		computer := parseComputer(entry)
		computers = append(computers, computer)
	}

	color.Green("[+] Found %d computers", len(computers))
	return computers, nil
}

// ============================================================
// Парсери LDAP Entry → struct
// ============================================================

func parseUser(entry *goldap.Entry) LDAPUser {
	uac := parseUAC(entry.GetAttributeValue("userAccountControl"))

	return LDAPUser{
		DN:                   entry.DN,
		SAMAccountName:       entry.GetAttributeValue("sAMAccountName"),
		DisplayName:          entry.GetAttributeValue("displayName"),
		Description:          entry.GetAttributeValue("description"),
		Mail:                 entry.GetAttributeValue("mail"),
		MemberOf:             entry.GetAttributeValues("memberOf"),
		SPNs:                 entry.GetAttributeValues("servicePrincipalName"),
		AdminCount:           entry.GetAttributeValue("adminCount") == "1",
		Enabled:              !isBitSet(uac, 0x0002),  // ADS_UF_ACCOUNTDISABLE
		PasswordNeverExpires: isBitSet(uac, 0x10000),  // ADS_UF_DONT_EXPIRE_PASSWD
		DontReqPreauth:       isBitSet(uac, 0x400000), // ADS_UF_DONT_REQUIRE_PREAUTH
		LastLogon:            parseFileTime(entry.GetAttributeValue("lastLogonTimestamp")),
		PasswordLastSet:      parseFileTime(entry.GetAttributeValue("pwdLastSet")),
		ObjectSid:            parseSIDBytes(entry.GetRawAttributeValue("objectSid")),
	}
}

func parseGroup(entry *goldap.Entry) LDAPGroup {
	return LDAPGroup{
		DN:             entry.DN,
		SAMAccountName: entry.GetAttributeValue("sAMAccountName"),
		Description:    entry.GetAttributeValue("description"),
		Members:        entry.GetAttributeValues("member"),
		AdminCount:     entry.GetAttributeValue("adminCount") == "1",
		GroupType:      parseGroupType(entry.GetAttributeValue("groupType")),
		ObjectSid:      parseSIDBytes(entry.GetRawAttributeValue("objectSid")),
	}
}

func parseComputer(entry *goldap.Entry) LDAPComputer {
	uac := parseUAC(entry.GetAttributeValue("userAccountControl"))

	return LDAPComputer{
		DN:                      entry.DN,
		SAMAccountName:          entry.GetAttributeValue("sAMAccountName"),
		DNSHostName:             entry.GetAttributeValue("dNSHostName"),
		OperatingSystem:         entry.GetAttributeValue("operatingSystem"),
		OperatingSystemVersion:  entry.GetAttributeValue("operatingSystemVersion"),
		Enabled:                 !isBitSet(uac, 0x0002),
		LastLogon:               parseFileTime(entry.GetAttributeValue("lastLogonTimestamp")),
		SPNs:                    entry.GetAttributeValues("servicePrincipalName"),
		UnconstrainedDelegation: isBitSet(uac, 0x80000),
		ObjectSid:               parseSIDBytes(entry.GetRawAttributeValue("objectSid")),
	}
}

// ============================================================
// Допоміжні функції
// ============================================================

// parseUAC конвертує рядок userAccountControl в число
func parseUAC(val string) uint64 {
	if val == "" {
		return 0
	}
	n, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// isBitSet перевіряє чи встановлений конкретний біт у UAC
func isBitSet(uac uint64, bit uint64) bool {
	return uac&bit != 0
}

// parseFileTime конвертує Windows FILETIME → читабельна дата
// Windows FILETIME: кількість 100-наносекундних інтервалів з 1 січня 1601
func parseFileTime(val string) string {
	if val == "" || val == "0" || val == "9223372036854775807" {
		return "Never"
	}

	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil || n == 0 {
		return "Never"
	}

	// конвертуємо з Windows epoch (1601) до Unix epoch (1970)
	// різниця: 11644473600 секунд
	unixSec := n/10000000 - 11644473600
	if unixSec <= 0 {
		return "Never"
	}

	t := time.Unix(unixSec, 0)
	return t.Format("2006-01-02 15:04:05")
}

// parseGroupType конвертує числовий groupType в рядок
func parseGroupType(val string) string {
	if val == "" {
		return "Unknown"
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return "Unknown"
	}

	// старший біт = Security group (vs Distribution)
	isSecurity := n < 0

	switch n & 0x7FFFFFFF { // маскуємо знаковий біт
	case 1:
		if isSecurity {
			return "Security/System"
		}
		return "Distribution/Global"
	case 2:
		if isSecurity {
			return "Security/Global"
		}
		return "Distribution/Global"
	case 4:
		if isSecurity {
			return "Security/Local"
		}
		return "Distribution/Local"
	case 8:
		if isSecurity {
			return "Security/Universal"
		}
		return "Distribution/Universal"
	default:
		return fmt.Sprintf("Unknown(%d)", n)
	}
}

// printQuickFindings виводить короткий summary цікавих знахідок
func (c *Client) printQuickFindings(result *EnumerationResult) {
	color.Yellow("\n[!] Quick findings:")

	// Кербероастабельні акаунти
	kerberoastable := 0
	asrep := 0
	adminUsers := 0
	passwordNeverExpires := 0

	for _, u := range result.Users {
		if !u.Enabled {
			continue
		}
		if len(u.SPNs) > 0 {
			kerberoastable++
		}
		if u.DontReqPreauth {
			asrep++
		}
		if u.AdminCount {
			adminUsers++
		}
		if u.PasswordNeverExpires {
			passwordNeverExpires++
		}
	}

	printFinding("Kerberoastable accounts", kerberoastable)
	printFinding("AS-REP roastable accounts", asrep)
	printFinding("AdminCount=1 users", adminUsers)
	printFinding("Password never expires", passwordNeverExpires)

	// Комп'ютери з Unconstrained Delegation
	unconstrainedDelegation := 0
	for _, comp := range result.Computers {
		if comp.UnconstrainedDelegation && comp.Enabled {
			unconstrainedDelegation++
		}
	}
	printFinding("Unconstrained delegation computers", unconstrainedDelegation)
}

// printFinding виводить знахідку з кольором залежно від кількості
func printFinding(label string, count int) {
	if count == 0 {
		color.Green("    %-40s %d", label+":", count)
	} else {
		color.Red("    %-40s %d  ◄", label+":", count)
	}
}

// parseSIDBytes конвертує raw objectSid bytes в рядок S-1-5-...
func parseSIDBytes(data []byte) string {
	if len(data) < 8 {
		return ""
	}
	revision := data[0]
	subAuthorityCount := int(data[1])
	if len(data) < 8+subAuthorityCount*4 {
		return ""
	}
	var authority uint64
	for i := 0; i < 6; i++ {
		authority = authority<<8 | uint64(data[2+i])
	}
	sid := fmt.Sprintf("S-%d-%d", revision, authority)
	for i := 0; i < subAuthorityCount; i++ {
		subAuth := uint32(data[8+i*4]) |
			uint32(data[9+i*4])<<8 |
			uint32(data[10+i*4])<<16 |
			uint32(data[11+i*4])<<24
		sid += fmt.Sprintf("-%d", subAuth)
	}
	return sid
}