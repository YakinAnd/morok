package ldap

import (
	"fmt"
	"net"
	"strconv"
	"strings"
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
	PasswordNotRequired  bool   // UAC 0x20 — can authenticate with empty password
	DontReqPreauth       bool   // AS-REP roastable
	LastLogon        string
	PasswordLastSet  string
	ObjectSid        string
	CN               string
	CreatedOn        string
	ChangedOn        string
	PrimaryGroup     string // resolved name, e.g. "Domain Users"
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
	CN             string
	CreatedOn      string
	ChangedOn      string
	MemberOf       []string // DNs of parent groups (nested membership)
}

// LDAPComputer представляє комп'ютер AD
type LDAPComputer struct {
	DN                      string
	SAMAccountName          string
	DNSHostName             string
	OperatingSystem         string
	OperatingSystemVersion  string
	OperatingSystemSP       string
	Enabled                 bool
	LastLogon               string
	SPNs                    []string
	UnconstrainedDelegation bool
	ObjectSid               string
	Description             string
	WhenCreated             string
	LAPSEnabled             bool
	Domain                  string // e.g. "north.sevenkingdoms.local"
	IsGC                    bool   // true if data came from GC (may be partial)
	CN                      string
	ChangedOn               string
}

// EnumerationResult містить всі зібрані дані
type EnumerationResult struct {
	Domain      string
	BaseDN      string
	Users       []LDAPUser
	Groups      []LDAPGroup
	Computers   []LDAPComputer
	CollectedAt time.Time
	ForestWide  bool // true if computers cover entire forest (GC was used)
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
	"cn",
	"whenCreated",
	"whenChanged",
	"primaryGroupID",
}

var groupAttributes = []string{
	"distinguishedName",
	"sAMAccountName",
	"description",
	"member",
	"adminCount",
	"groupType",
	"objectSid",
	"cn",
	"whenCreated",
	"whenChanged",
	"memberOf",
}

var computerAttributes = []string{
	"distinguishedName",
	"sAMAccountName",
	"dNSHostName",
	"operatingSystem",
	"operatingSystemVersion",
	"operatingSystemServicePack",
	"userAccountControl",
	"lastLogonTimestamp",
	"servicePrincipalName",
	"objectSid",
	"description",
	"whenCreated",
	"whenChanged",
	"ms-MCS-AdmPwdExpirationTime",
	"cn",
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

	if !c.Quiet {
		color.White("\n  enumerating %s ...", c.Domain)
	}

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

	// Resolve user primary groups now that we have both users and groups
	resolvePrimaryGroups(result.Users, result.Groups)

	// Computers — try forest-wide (GC), fall back to domain-only
	computers, forestWide, err := c.enumerateComputersForest()
	if err != nil {
		return nil, fmt.Errorf("computer enumeration failed: %w", err)
	}
	result.Computers = computers
	result.ForestWide = forestWide

	return result, nil
}

// PrintEnumerationSummary prints the "OBJECTS COLLECTED" and quick findings sections.
// Call this only from the enum command — not from targeted analysis commands.
func (c *Client) PrintEnumerationSummary(result *EnumerationResult) {
	compLabel := "domain"
	if result.ForestWide {
		compLabel = "forest-wide"
	}
	color.Cyan("\n  OBJECTS COLLECTED")
	color.White("  %-12s %d", "users", len(result.Users))
	color.White("  %-12s %d", "groups", len(result.Groups))
	color.White("  %-12s %d  (%s)", "computers", len(result.Computers), compLabel)

	c.printQuickFindings(result)
}

// EnumerateUsers збирає всіх користувачів AD
func (c *Client) EnumerateUsers() ([]LDAPUser, error) {
	entries, err := c.Search(FilterAllUsers, userAttributes)
	if err != nil {
		return nil, err
	}

	users := make([]LDAPUser, 0, len(entries))
	for _, entry := range entries {
		users = append(users, parseUser(entry))
	}
	return users, nil
}

// EnumerateGroups збирає всі групи AD
func (c *Client) EnumerateGroups() ([]LDAPGroup, error) {
	entries, err := c.Search(FilterAllGroups, groupAttributes)
	if err != nil {
		return nil, err
	}

	groups := make([]LDAPGroup, 0, len(entries))
	for _, entry := range entries {
		groups = append(groups, parseGroup(entry))
	}
	return groups, nil
}

// EnumerateComputers збирає всі комп'ютери AD
func (c *Client) EnumerateComputers() ([]LDAPComputer, error) {

	entries, err := c.Search(FilterAllComputers, computerAttributes)
	if err != nil {
		return nil, err
	}

	computers := make([]LDAPComputer, 0, len(entries))

	for _, entry := range entries {
		computer := parseComputer(entry)
		computers = append(computers, computer)
	}

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
		PasswordNotRequired:  isBitSet(uac, 0x0020),   // ADS_UF_PASSWD_NOTREQD
		DontReqPreauth:       isBitSet(uac, 0x400000), // ADS_UF_DONT_REQUIRE_PREAUTH
		LastLogon:            parseFileTime(entry.GetAttributeValue("lastLogonTimestamp")),
		PasswordLastSet:      parseFileTime(entry.GetAttributeValue("pwdLastSet")),
		ObjectSid:            parseSIDBytes(entry.GetRawAttributeValue("objectSid")),
		CN:           entry.GetAttributeValue("cn"),
		CreatedOn:    parseADDateTime(entry.GetAttributeValue("whenCreated")),
		ChangedOn:    parseADDateTime(entry.GetAttributeValue("whenChanged")),
		PrimaryGroup: entry.GetAttributeValue("primaryGroupID"), // raw RID; resolved in EnumerateAll
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
		CN:             entry.GetAttributeValue("cn"),
		CreatedOn:      parseADDateTime(entry.GetAttributeValue("whenCreated")),
		ChangedOn:      parseADDateTime(entry.GetAttributeValue("whenChanged")),
		MemberOf:       entry.GetAttributeValues("memberOf"),
	}
}

func parseComputer(entry *goldap.Entry) LDAPComputer {
	uac := parseUAC(entry.GetAttributeValue("userAccountControl"))
	lapsExpiry := entry.GetAttributeValue("ms-MCS-AdmPwdExpirationTime")

	return LDAPComputer{
		DN:                      entry.DN,
		SAMAccountName:          entry.GetAttributeValue("sAMAccountName"),
		DNSHostName:             entry.GetAttributeValue("dNSHostName"),
		OperatingSystem:         entry.GetAttributeValue("operatingSystem"),
		OperatingSystemVersion:  entry.GetAttributeValue("operatingSystemVersion"),
		OperatingSystemSP:       entry.GetAttributeValue("operatingSystemServicePack"),
		Enabled:                 !isBitSet(uac, 0x0002),
		LastLogon:               parseFileTime(entry.GetAttributeValue("lastLogonTimestamp")),
		SPNs:                    entry.GetAttributeValues("servicePrincipalName"),
		UnconstrainedDelegation: isBitSet(uac, 0x80000) && !isBitSet(uac, 0x2000),
		ObjectSid:               parseSIDBytes(entry.GetRawAttributeValue("objectSid")),
		Description:             entry.GetAttributeValue("description"),
		WhenCreated:             parseGeneralizedTime(entry.GetAttributeValue("whenCreated")),
		LAPSEnabled:             lapsExpiry != "",
		Domain:                  dnToDomainLabel(entry.DN),
		CN:                      entry.GetAttributeValue("cn"),
		ChangedOn:               parseADDateTime(entry.GetAttributeValue("whenChanged")),
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
	kerberoastable, asrep, adminUsers, pwdNeverExpires := 0, 0, 0, 0
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
			pwdNeverExpires++
		}
	}
	unconstrainedDeleg := 0
	for _, comp := range result.Computers {
		if comp.UnconstrainedDelegation && comp.Enabled {
			unconstrainedDeleg++
		}
	}

	color.Cyan("\n  QUICK FINDINGS")
	printFinding("kerberoastable", kerberoastable)
	printFinding("AS-REP roastable", asrep)
	printFinding("privileged accts (SDProp)", adminUsers)
	printFinding("password never expires", pwdNeverExpires)
	printFinding("unconstrained delegation", unconstrainedDeleg)
}

func printFinding(label string, count int) {
	if count == 0 {
		color.White("  %-28s %d", label, count)
	} else {
		color.Yellow("  %-28s %d", label, count)
	}
}

// ============================================================
// Forest-wide computer enumeration
// ============================================================

// EnumerateComputersForest tries GC (port 3268) to get all forest computers,
// then upgrades to full attributes via direct domain DC queries.
// Returns (computers, forestWide, error).
func (c *Client) EnumerateComputersForest() ([]LDAPComputer, bool, error) {
	return c.enumerateComputersForest()
}

// enumerateComputersForest tries GC (port 3268) to get all forest computers,
// then upgrades to full attributes via direct domain DC queries.
// Returns (computers, forestWide, error).
func (c *Client) enumerateComputersForest() ([]LDAPComputer, bool, error) {
	gcEntries, err := c.SearchGC(FilterAllComputers, computerAttributes)
	if err != nil {
		if !c.Quiet {
			color.White("  GC unavailable (%v), domain-only", err)
		}
		computers, err := c.EnumerateComputers()
		return computers, false, err
	}

	// Group entries by domain baseDN
	domainEntries := make(map[string][]*goldap.Entry)
	for _, entry := range gcEntries {
		baseDN := dnToBaseDN(entry.DN)
		domainEntries[baseDN] = append(domainEntries[baseDN], entry)
	}

	var computers []LDAPComputer

	for baseDN, entries := range domainEntries {
		if baseDN == strings.ToLower(c.BaseDN) {
			// Current domain — query directly for full attributes
			full, err := c.EnumerateComputers()
			if err == nil {
				computers = append(computers, full...)
				continue
			}
		}

		// Child domain — try to resolve DC and query directly
		childDomain := baseDNToDomain(baseDN)
		fullEntries, err := c.queryChildDomainComputers(childDomain, baseDN)
		if err == nil {
			for _, e := range fullEntries {
				comp := parseComputer(e)
				computers = append(computers, comp)
			}
		} else {
			if !c.Quiet {
				color.White("  cannot reach %s (%v), using partial GC data", childDomain, err)
			}
			for _, e := range entries {
				comp := parseComputer(e)
				comp.IsGC = true
				computers = append(computers, comp)
			}
		}
	}

	return computers, true, nil
}

// queryChildDomainComputers resolves the child domain's DC via DNS and queries it.
func (c *Client) queryChildDomainComputers(domain, baseDN string) ([]*goldap.Entry, error) {
	addrs, err := net.LookupHost(domain)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("DNS lookup for %s: %w", domain, err)
	}
	if !c.Quiet {
		color.White("  querying %s via %s", domain, addrs[0])
	}
	return c.SearchDomain(addrs[0], baseDN, FilterAllComputers, computerAttributes)
}

// dnToBaseDN extracts the DC= components from a DN as a lowercase string.
// "CN=CASTELBLACK,CN=Computers,DC=north,DC=sevenkingdoms,DC=local" → "dc=north,dc=sevenkingdoms,dc=local"
func dnToBaseDN(dn string) string {
	parts := strings.Split(strings.ToLower(dn), ",")
	var dcs []string
	for _, p := range parts {
		if strings.HasPrefix(strings.TrimSpace(p), "dc=") {
			dcs = append(dcs, strings.TrimSpace(p))
		}
	}
	return strings.Join(dcs, ",")
}

// dnToDomainLabel extracts the domain label (e.g. "north.sevenkingdoms.local") from a DN.
func dnToDomainLabel(dn string) string {
	return baseDNToDomain(dnToBaseDN(dn))
}

// baseDNToDomain converts "dc=north,dc=sevenkingdoms,dc=local" → "north.sevenkingdoms.local"
func baseDNToDomain(baseDN string) string {
	parts := strings.Split(strings.ToLower(baseDN), ",")
	var labels []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "dc=") {
			labels = append(labels, strings.TrimPrefix(p, "dc="))
		}
	}
	return strings.Join(labels, ".")
}

// parseGeneralizedTime parses LDAP generalized time "20230101120000.0Z" → "2023-01-01"
func parseGeneralizedTime(val string) string {
	if val == "" {
		return ""
	}
	for _, layout := range []string{"20060102150405.0Z", "20060102150405Z", "20060102150405.0-0700", "20060102150405-0700"} {
		if t, err := time.Parse(layout, val); err == nil {
			return t.Format("2006-01-02")
		}
	}
	return val
}

// parseADDateTime parses LDAP generalized time → "2023-01-01 12:00:00" (date + time).
func parseADDateTime(val string) string {
	if val == "" {
		return ""
	}
	for _, layout := range []string{"20060102150405.0Z", "20060102150405Z", "20060102150405.0-0700", "20060102150405-0700"} {
		if t, err := time.Parse(layout, val); err == nil {
			return t.UTC().Format("2006-01-02 15:04:05")
		}
	}
	return val
}

// resolvePrimaryGroups replaces each user's PrimaryGroup (currently holding the raw RID string)
// with the SAMAccountName of the matching group, looked up by the last sub-authority of the group SID.
func resolvePrimaryGroups(users []LDAPUser, groups []LDAPGroup) {
	// Build RID → SAMAccountName from the last component of each group's SID.
	ridToName := make(map[string]string, len(groups))
	for _, g := range groups {
		if g.ObjectSid == "" {
			continue
		}
		idx := strings.LastIndex(g.ObjectSid, "-")
		if idx < 0 {
			continue
		}
		rid := g.ObjectSid[idx+1:]
		ridToName[rid] = g.SAMAccountName
	}

	for i := range users {
		rid := users[i].PrimaryGroup
		if rid == "" {
			continue
		}
		if name, ok := ridToName[rid]; ok {
			users[i].PrimaryGroup = name
		}
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