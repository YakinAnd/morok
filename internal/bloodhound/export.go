package bloodhound

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	adldap "github.com/YakinAnd/adpath/internal/ldap"
)

// ── BloodHound CE v5 JSON structures ────────────────────────────

type Meta struct {
	Methods int    `json:"methods"`
	Type    string `json:"type"`
	Count   int    `json:"count"`
	Version int    `json:"version"`
}

type TypedPrincipal struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

type SessionResult struct {
	Results       []any  `json:"Results"`
	Collected     bool   `json:"Collected"`
	FailureReason *string `json:"FailureReason"`
}

// ── Users ────────────────────────────────────────────────────────

type UserProperties struct {
	Name                    string   `json:"name"`
	Domain                  string   `json:"domain"`
	DomainSID               string   `json:"domainsid"`
	DistinguishedName       string   `json:"distinguishedname"`
	Enabled                 bool     `json:"enabled"`
	AdminCount              bool     `json:"admincount"`
	PwdNeverExpires         bool     `json:"pwdneverexpires"`
	DontReqPreauth          bool     `json:"dontreqpreauth"`
	HasSPN                  bool     `json:"hasspn"`
	ServicePrincipalNames   []string `json:"serviceprincipalnames"`
	DisplayName             string   `json:"displayname"`
	Email                   string   `json:"email"`
	Description             string   `json:"description"`
	LastLogon               int64    `json:"lastlogon"`
	LastLogonTimestamp      int64    `json:"lastlogontimestamp"`
	PwdLastSet              int64    `json:"pwdlastset"`
	UnconstrainedDelegation bool     `json:"unconstraineddelegation"`
	Sensitive               bool     `json:"sensitive"`
	WhenCreated             int64    `json:"whencreated"`
	SIDHistory              []string `json:"sidhistory"`
}

type BHUser struct {
	Properties       UserProperties   `json:"Properties"`
	ObjectIdentifier string           `json:"ObjectIdentifier"`
	Aces             []any            `json:"Aces"`
	SPNTargets       []any            `json:"SPNTargets"`
	HasSIDHistory    []any            `json:"HasSIDHistory"`
	AllowedToDelegate []any           `json:"AllowedToDelegate"`
	PrimaryGroupSID  string           `json:"PrimaryGroupSID"`
	IsDeleted        bool             `json:"IsDeleted"`
	IsACLProtected   bool             `json:"IsACLProtected"`
	ContainedBy      *TypedPrincipal  `json:"ContainedBy"`
}

type UsersFile struct {
	Data []BHUser `json:"data"`
	Meta Meta     `json:"meta"`
}

// ── Groups ───────────────────────────────────────────────────────

type GroupProperties struct {
	Name              string `json:"name"`
	Domain            string `json:"domain"`
	DomainSID         string `json:"domainsid"`
	DistinguishedName string `json:"distinguishedname"`
	Description       string `json:"description"`
	AdminCount        bool   `json:"admincount"`
	HighValue         bool   `json:"highvalue"`
	WhenCreated       int64  `json:"whencreated"`
}

type BHGroup struct {
	Properties       GroupProperties  `json:"Properties"`
	ObjectIdentifier string           `json:"ObjectIdentifier"`
	Members          []TypedPrincipal `json:"Members"`
	Aces             []any            `json:"Aces"`
	IsDeleted        bool             `json:"IsDeleted"`
	IsACLProtected   bool             `json:"IsACLProtected"`
	ContainedBy      *TypedPrincipal  `json:"ContainedBy"`
}

type GroupsFile struct {
	Data []BHGroup `json:"data"`
	Meta Meta      `json:"meta"`
}

// ── Computers ────────────────────────────────────────────────────

type ComputerProperties struct {
	Name                    string   `json:"name"`
	Domain                  string   `json:"domain"`
	DomainSID               string   `json:"domainsid"`
	DistinguishedName       string   `json:"distinguishedname"`
	Enabled                 bool     `json:"enabled"`
	UnconstrainedDelegation bool     `json:"unconstraineddelegation"`
	LastLogon               int64    `json:"lastlogon"`
	LastLogonTimestamp      int64    `json:"lastlogontimestamp"`
	PwdLastSet              int64    `json:"pwdlastset"`
	ServicePrincipalNames   []string `json:"serviceprincipalnames"`
	Description             string   `json:"description"`
	OperatingSystem         string   `json:"operatingsystem"`
	HasLAPS                 bool     `json:"haslaps"`
	WhenCreated             int64    `json:"whencreated"`
}

type BHComputer struct {
	Properties          ComputerProperties `json:"Properties"`
	ObjectIdentifier    string             `json:"ObjectIdentifier"`
	Aces                []any              `json:"Aces"`
	AllowedToDelegate   []any              `json:"AllowedToDelegate"`
	AllowedToAct        []any              `json:"AllowedToAct"`
	HasSIDHistory       []any              `json:"HasSIDHistory"`
	Sessions            SessionResult      `json:"Sessions"`
	PrivilegedSessions  SessionResult      `json:"PrivilegedSessions"`
	RegistrySessions    SessionResult      `json:"RegistrySessions"`
	LocalGroups         []any              `json:"LocalGroups"`
	UserRights          []any              `json:"UserRights"`
	DumpSMSAPassword    []any              `json:"DumpSMSAPassword"`
	PrimaryGroupSID     string             `json:"PrimaryGroupSID"`
	IsDeleted           bool               `json:"IsDeleted"`
	IsACLProtected      bool               `json:"IsACLProtected"`
	ContainedBy         *TypedPrincipal    `json:"ContainedBy"`
	Status              *string            `json:"Status"`
}

type ComputersFile struct {
	Data []BHComputer `json:"data"`
	Meta Meta         `json:"meta"`
}

// ── Domains ──────────────────────────────────────────────────────

type DomainProperties struct {
	Name              string `json:"name"`
	Domain            string `json:"domain"`
	DomainSID         string `json:"domainsid"`
	DistinguishedName string `json:"distinguishedname"`
	HighValue         bool   `json:"highvalue"`
	WhenCreated       int64  `json:"whencreated"`
	FunctionalLevel   string `json:"functionallevel"`
	Description       string `json:"description"`
}

type GPOChanges struct {
	LocalAdmins       []any `json:"LocalAdmins"`
	RemoteDesktopUsers []any `json:"RemoteDesktopUsers"`
	DcomUsers         []any `json:"DcomUsers"`
	PSRemoteUsers     []any `json:"PSRemoteUsers"`
	AffectedComputers []any `json:"AffectedComputers"`
}

type BHDomain struct {
	Properties       DomainProperties `json:"Properties"`
	ObjectIdentifier string           `json:"ObjectIdentifier"`
	Aces             []any            `json:"Aces"`
	Links            []any            `json:"Links"`
	Trusts           []any            `json:"Trusts"`
	ChildObjects     []any            `json:"ChildObjects"`
	GPOChanges       GPOChanges       `json:"GPOChanges"`
	IsDeleted        bool             `json:"IsDeleted"`
	IsACLProtected   bool             `json:"IsACLProtected"`
	ContainedBy      *TypedPrincipal  `json:"ContainedBy"`
}

type DomainsFile struct {
	Data []BHDomain `json:"data"`
	Meta Meta       `json:"meta"`
}

// ── Helpers ──────────────────────────────────────────────────────

// parseTimeToEpoch converts "2006-01-02 15:04:05" or "Never" → Unix epoch (-1 if unknown)
func parseTimeToEpoch(s string) int64 {
	if s == "" || s == "Never" {
		return -1
	}
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		return -1
	}
	return t.Unix()
}

// extractDomainSID returns the domain SID (strips the last -RID from an object SID)
func extractDomainSID(sid string) string {
	idx := strings.LastIndex(sid, "-")
	if idx < 0 {
		return sid
	}
	return sid[:idx]
}

// normDomain returns uppercased FQDN
func normDomain(d string) string {
	return strings.ToUpper(d)
}

// winFileTimeRaw converts raw FILETIME int string → Unix epoch (-1 if invalid)
// We use the already-parsed string version; falls back gracefully.
func fileTimeStrToEpoch(val string) int64 {
	if val == "" || val == "0" || val == "9223372036854775807" {
		return -1
	}
	n, err := strconv.ParseInt(val, 10, 64)
	if err != nil || n <= 0 {
		return -1
	}
	unix := n/10000000 - 11644473600
	if unix <= 0 {
		return -1
	}
	return unix
}

// memberType infers BH object type from DN structure (heuristic)
func memberType(dn string, dnToSID map[string]string, result *adldap.EnumerationResult) string {
	ldn := strings.ToLower(dn)
	for _, u := range result.Users {
		if strings.ToLower(u.DN) == ldn {
			return "User"
		}
	}
	for _, g := range result.Groups {
		if strings.ToLower(g.DN) == ldn {
			return "Group"
		}
	}
	for _, c := range result.Computers {
		if strings.ToLower(c.DN) == ldn {
			return "Computer"
		}
	}
	return "Base"
}

// highValueGroups are groups BloodHound marks as high-value by default
var highValueGroups = map[string]bool{
	"domain admins":          true,
	"enterprise admins":      true,
	"schema admins":          true,
	"administrators":         true,
	"backup operators":       true,
	"account operators":      true,
	"print operators":        true,
	"server operators":       true,
	"group policy creator owners": true,
	"domain controllers":     true,
	"read-only domain controllers": true,
	"dnssadmins":             true,
}

// ── Export ───────────────────────────────────────────────────────

// Export writes BloodHound CE v5 JSON files into outDir.
// Creates outDir if it doesn't exist.
// Produces: users.json, groups.json, computers.json, domains.json
func Export(outDir string, result *adldap.EnumerationResult) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("bloodhound: create output dir: %w", err)
	}

	domainUpper := normDomain(result.Domain)

	// Build DN → SID lookup
	dnToSID := make(map[string]string, len(result.Users)+len(result.Groups)+len(result.Computers))
	for _, u := range result.Users {
		if u.ObjectSid != "" {
			dnToSID[strings.ToLower(u.DN)] = u.ObjectSid
		}
	}
	for _, g := range result.Groups {
		if g.ObjectSid != "" {
			dnToSID[strings.ToLower(g.DN)] = g.ObjectSid
		}
	}
	for _, c := range result.Computers {
		if c.ObjectSid != "" {
			dnToSID[strings.ToLower(c.DN)] = c.ObjectSid
		}
	}

	// Derive domain SID from first available user/group SID
	domainSID := ""
	for _, u := range result.Users {
		if u.ObjectSid != "" {
			domainSID = extractDomainSID(u.ObjectSid)
			break
		}
	}
	if domainSID == "" {
		for _, g := range result.Groups {
			if g.ObjectSid != "" {
				domainSID = extractDomainSID(g.ObjectSid)
				break
			}
		}
	}

	if err := writeUsers(outDir, result, domainUpper, domainSID); err != nil {
		return err
	}
	if err := writeGroups(outDir, result, domainUpper, domainSID, dnToSID); err != nil {
		return err
	}
	if err := writeComputers(outDir, result, domainUpper, domainSID); err != nil {
		return err
	}
	if err := writeDomains(outDir, result, domainUpper, domainSID); err != nil {
		return err
	}

	return nil
}

func writeUsers(outDir string, result *adldap.EnumerationResult, domain, domainSID string) error {
	users := make([]BHUser, 0, len(result.Users))
	// Primary group SID for regular domain users = domain SID + -513 (Domain Users)
	primaryGroupSID := domainSID + "-513"

	for _, u := range result.Users {
		spns := u.SPNs
		if spns == nil {
			spns = []string{}
		}
		name := strings.ToUpper(u.SAMAccountName) + "@" + domain

		users = append(users, BHUser{
			Properties: UserProperties{
				Name:                  name,
				Domain:                domain,
				DomainSID:             domainSID,
				DistinguishedName:     strings.ToUpper(u.DN),
				Enabled:               u.Enabled,
				AdminCount:            u.AdminCount,
				PwdNeverExpires:       u.PasswordNeverExpires,
				DontReqPreauth:        u.DontReqPreauth,
				HasSPN:                len(u.SPNs) > 0,
				ServicePrincipalNames: spns,
				DisplayName:           u.DisplayName,
				Email:                 u.Mail,
				Description:           u.Description,
				LastLogon:             parseTimeToEpoch(u.LastLogon),
				LastLogonTimestamp:    parseTimeToEpoch(u.LastLogon),
				PwdLastSet:            parseTimeToEpoch(u.PasswordLastSet),
				WhenCreated:           0,
				SIDHistory:            []string{},
			},
			ObjectIdentifier:  u.ObjectSid,
			Aces:              []any{},
			SPNTargets:        []any{},
			HasSIDHistory:     []any{},
			AllowedToDelegate: []any{},
			PrimaryGroupSID:   primaryGroupSID,
			IsDeleted:         false,
			IsACLProtected:    u.AdminCount,
			ContainedBy:       nil,
		})
	}

	return writeJSON(filepath.Join(outDir, "users.json"), UsersFile{
		Data: users,
		Meta: Meta{Type: "users", Version: 5, Count: len(users)},
	})
}

func writeGroups(outDir string, result *adldap.EnumerationResult, domain, domainSID string, dnToSID map[string]string) error {
	groups := make([]BHGroup, 0, len(result.Groups))

	for _, g := range result.Groups {
		members := make([]TypedPrincipal, 0, len(g.Members))
		for _, memberDN := range g.Members {
			sid, ok := dnToSID[strings.ToLower(memberDN)]
			if !ok || sid == "" {
				continue
			}
			mtype := memberType(memberDN, dnToSID, result)
			members = append(members, TypedPrincipal{
				ObjectIdentifier: sid,
				ObjectType:       mtype,
			})
		}

		name := strings.ToUpper(g.SAMAccountName) + "@" + domain
		isHighValue := highValueGroups[strings.ToLower(g.SAMAccountName)]

		groups = append(groups, BHGroup{
			Properties: GroupProperties{
				Name:              name,
				Domain:            domain,
				DomainSID:         domainSID,
				DistinguishedName: strings.ToUpper(g.DN),
				Description:       g.Description,
				AdminCount:        g.AdminCount,
				HighValue:         isHighValue,
				WhenCreated:       0,
			},
			ObjectIdentifier: g.ObjectSid,
			Members:          members,
			Aces:             []any{},
			IsDeleted:        false,
			IsACLProtected:   g.AdminCount,
			ContainedBy:      nil,
		})
	}

	return writeJSON(filepath.Join(outDir, "groups.json"), GroupsFile{
		Data: groups,
		Meta: Meta{Type: "groups", Version: 5, Count: len(groups)},
	})
}

func writeComputers(outDir string, result *adldap.EnumerationResult, domain, domainSID string) error {
	computers := make([]BHComputer, 0, len(result.Computers))
	// Primary group SID for domain computers = domain SID + -515 (Domain Computers)
	primaryGroupSID := domainSID + "-515"

	emptySession := SessionResult{Results: []any{}, Collected: false}

	for _, c := range result.Computers {
		spns := c.SPNs
		if spns == nil {
			spns = []string{}
		}

		name := strings.ToUpper(c.DNSHostName)
		if name == "" {
			name = strings.ToUpper(strings.TrimSuffix(c.SAMAccountName, "$")) + "." + strings.ToLower(domain)
		}

		computers = append(computers, BHComputer{
			Properties: ComputerProperties{
				Name:                    name,
				Domain:                  domain,
				DomainSID:               domainSID,
				DistinguishedName:       strings.ToUpper(c.DN),
				Enabled:                 c.Enabled,
				UnconstrainedDelegation: c.UnconstrainedDelegation,
				LastLogon:               parseTimeToEpoch(c.LastLogon),
				LastLogonTimestamp:      parseTimeToEpoch(c.LastLogon),
				PwdLastSet:              -1,
				ServicePrincipalNames:   spns,
				Description:             c.Description,
				OperatingSystem:         c.OperatingSystem,
				HasLAPS:                 c.LAPSEnabled,
				WhenCreated:             0,
			},
			ObjectIdentifier:   c.ObjectSid,
			Aces:               []any{},
			AllowedToDelegate:  []any{},
			AllowedToAct:       []any{},
			HasSIDHistory:      []any{},
			Sessions:           emptySession,
			PrivilegedSessions: emptySession,
			RegistrySessions:   emptySession,
			LocalGroups:        []any{},
			UserRights:         []any{},
			DumpSMSAPassword:   []any{},
			PrimaryGroupSID:    primaryGroupSID,
			IsDeleted:          false,
			IsACLProtected:     false,
			ContainedBy:        nil,
			Status:             nil,
		})
	}

	return writeJSON(filepath.Join(outDir, "computers.json"), ComputersFile{
		Data: computers,
		Meta: Meta{Type: "computers", Version: 5, Count: len(computers)},
	})
}

func writeDomains(outDir string, result *adldap.EnumerationResult, domain, domainSID string) error {
	bhdomain := BHDomain{
		Properties: DomainProperties{
			Name:              domain,
			Domain:            domain,
			DomainSID:         domainSID,
			DistinguishedName: strings.ToUpper(result.BaseDN),
			HighValue:         true,
			WhenCreated:       0,
			FunctionalLevel:   "",
			Description:       "",
		},
		ObjectIdentifier: domainSID,
		Aces:             []any{},
		Links:            []any{},
		Trusts:           []any{},
		ChildObjects:     []any{},
		GPOChanges:       GPOChanges{LocalAdmins: []any{}, RemoteDesktopUsers: []any{}, DcomUsers: []any{}, PSRemoteUsers: []any{}, AffectedComputers: []any{}},
		IsDeleted:        false,
		IsACLProtected:   false,
		ContainedBy:      nil,
	}

	return writeJSON(filepath.Join(outDir, "domains.json"), DomainsFile{
		Data: []BHDomain{bhdomain},
		Meta: Meta{Type: "domains", Version: 5, Count: 1},
	})
}

func writeJSON(path string, v any) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("bloodhound: create %s: %w", filepath.Base(path), err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("bloodhound: encode %s: %w", filepath.Base(path), err)
	}
	return nil
}
