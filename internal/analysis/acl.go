package analysis

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	goldap "github.com/go-ldap/ldap/v3"

	adldap "github.com/YakinAnd/morok/internal/ldap"
)

// ============================================================
// Моделі даних
// ============================================================

// ACLRight — тип небезпечного права
type ACLRight string

const (
	RightGenericAll          ACLRight = "GenericAll"
	RightWriteDACL           ACLRight = "WriteDACL"
	RightWriteOwner          ACLRight = "WriteOwner"
	RightGenericWrite        ACLRight = "GenericWrite"
	RightForceChangePassword ACLRight = "ForceChangePassword"
	RightAddMember           ACLRight = "AddMember"
)

// Replication right GUIDs — both required for DCSync
const (
	guidDSReplicationGetChanges    = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
	guidDSReplicationGetChangesAll = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
)

// DCSyncFinding — principal that has full DCSync rights on the domain object
type DCSyncFinding struct {
	PrincipalName string
	PrincipalType string
	PrincipalDN   string
	CVSS          float64
	CVSSVector    string
	Severity      string
	SourceDomain  string // set for findings from trusted domains
}

// ACLFinding — одна небезпечна ACL знахідка
type ACLFinding struct {
	PrincipalDN   string
	PrincipalName string
	PrincipalType string

	TargetDN   string
	TargetName string
	TargetType string

	Right        ACLRight
	Severity     string
	CVSS         float64
	CVSSVector   string
	SourceDomain string // set for findings from trusted domains
}

// ACLResult — результат ACL аналізу
// OwnerFinding — non-default owner on a privileged AD object.
// The owner always has implicit WriteDACL regardless of the DACL.
type OwnerFinding struct {
	OwnerSID      string
	OwnerName     string
	TargetDN      string
	TargetName    string
	Severity      string
	CVSS          float64
	CVSSVector    string
}

type ACLResult struct {
	Domain         string
	Findings       []ACLFinding
	DCSyncFindings []DCSyncFinding
	OwnerFindings  []OwnerFinding // privileged objects with non-default owners
}

// ============================================================
// LDAP атрибути і константи
// ============================================================

// GUID прав для розпізнавання extended rights
const (
	// ForceChangePassword extended right GUID
	guidForceChangePassword = "00299570-246d-11d0-a768-00aa006e0529"
	// AddMember extended right GUID
	guidAddMember = "bf9679c0-0de6-11d0-a285-00aa003049e2"
)

// ACL атрибути для LDAP запиту
var aclAttributes = []string{
	"distinguishedName",
	"sAMAccountName",
	"objectClass",
	"nTSecurityDescriptor",
}

const (
	ADS_RIGHT_GENERIC_ALL   = 0x10000000
	ADS_RIGHT_GENERIC_WRITE = 0x40000000
	ADS_RIGHT_WRITE_DACL    = 0x00040000
	ADS_RIGHT_WRITE_OWNER   = 0x00080000

	// специфічні маски AD
	ADS_RIGHT_DS_WRITE_PROP     = 0x00000020 // GenericWrite еквівалент
	ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100 // Extended rights (ForceChangePassword, DCSync)
	ADS_RIGHT_DS_SELF           = 0x00000008 // Validated write (AddMember / Self-Membership)
	ADS_RIGHT_ACTRL_DS_LIST     = 0x00000004
	// повний доступ до об'єкту
	ADS_RIGHT_DS_FULL = 0x000F01FF
)

// ============================================================
// Основна функція аналізу
// ============================================================

// AnalyzeACL збирає небезпечні ACL з AD
func AnalyzeACL(client *adldap.Client, result *adldap.EnumerationResult, extraResults ...*adldap.EnumerationResult) (*ACLResult, error) {
	aclResult := &ACLResult{
		Domain: result.Domain,
	}

	// запитуємо ACL для всіх об'єктів
	entries, err := client.SearchACL()
	if err != nil {
		return nil, fmt.Errorf("ACL search failed: %w", err)
	}

	// будуємо map DN → SAMAccountName для швидкого lookup
	// extraResults дозволяє включити об'єкти з інших доменів (напр. primary domain при аналізі trusted)
	nameMap := buildNameMap(result)
	for _, extra := range extraResults {
		if extra == nil {
			continue
		}
		for sid, info := range buildNameMap(extra) {
			if _, exists := nameMap[sid]; !exists {
				nameMap[sid] = info
			}
		}
	}



	// аналізуємо кожен об'єкт
	for _, entry := range entries {
		findings := parseACLEntry(entry, nameMap, result)
		aclResult.Findings = append(aclResult.Findings, findings...)
	}
	// debug dump перших 20 raw findings (тільки при trusted domain аналізі)
	if len(extraResults) > 0 {
		limit := len(aclResult.Findings)
		if limit > 20 {
			limit = 20
		}
		for _, f := range aclResult.Findings[:limit] {
			color.White("    [raw] %-30s %-20s %-20s %s", f.PrincipalName, f.Right, f.TargetName, f.Severity)
		}
	}
	// фільтруємо стандартні системні права
	aclResult.Findings = filterSystemACL(aclResult.Findings)

	// DCSync: scan domain object for replication rights
	aclResult.DCSyncFindings = checkDCSync(entries, nameMap, client.GetBaseDN())

	if len(aclResult.DCSyncFindings) > 0 {
		color.Red("  %-28s %d  (secretsdump possible)", "DCSync rights", len(aclResult.DCSyncFindings))
		for _, f := range aclResult.DCSyncFindings {
			color.Red("    %s  (%s)", f.PrincipalName, f.PrincipalType)
		}
	}

	// Owner check: non-default owner on privileged objects has implicit WriteDACL.
	aclResult.OwnerFindings = checkPrivilegedOwners(entries, nameMap, result)

	return aclResult, nil
}

// checkDCSync finds principals with both DS-Replication-Get-Changes and
// DS-Replication-Get-Changes-All on the domain object (= DCSync capable).
func checkDCSync(entries []*goldap.Entry, nameMap map[string]nameInfo, baseDN string) []DCSyncFinding {
	// find the domain object entry
	var domainEntry *goldap.Entry
	for _, e := range entries {
		if strings.EqualFold(e.DN, baseDN) {
			domainEntry = e
			break
		}
	}
	if domainEntry == nil {
		return nil
	}

	sdBytes := domainEntry.GetRawAttributeValue("nTSecurityDescriptor")
	if len(sdBytes) == 0 {
		return nil
	}

	aces, err := parseSecurityDescriptor(sdBytes)
	if err != nil {
		return nil
	}

	// track which replication GUIDs each SID has
	type replRights struct{ getChanges, getChangesAll bool }
	sidRights := make(map[string]*replRights)

	for _, ace := range aces {
		if ace.ACEType == 0x01 || ace.ACEType == 0x06 || ace.ACEType == 0x0A || ace.ACEType == 0x0C {
			continue // deny ACE
		}

		// GenericAll (0x10000000) or full-control mask on the domain object implicitly
		// includes DS_CONTROL_ACCESS and therefore both replication rights (DCSync).
		if ace.AccessMask&ADS_RIGHT_GENERIC_ALL != 0 || ace.AccessMask&0x000F01FF == 0x000F01FF {
			if sidRights[ace.SID] == nil {
				sidRights[ace.SID] = &replRights{}
			}
			sidRights[ace.SID].getChanges = true
			sidRights[ace.SID].getChangesAll = true
			continue
		}

		if ace.AccessMask&ADS_RIGHT_DS_CONTROL_ACCESS == 0 {
			continue
		}
		guid := strings.ToLower(ace.ObjectType)
		switch guid {
		case guidDSReplicationGetChanges:
			if sidRights[ace.SID] == nil {
				sidRights[ace.SID] = &replRights{}
			}
			sidRights[ace.SID].getChanges = true
		case guidDSReplicationGetChangesAll:
			if sidRights[ace.SID] == nil {
				sidRights[ace.SID] = &replRights{}
			}
			sidRights[ace.SID].getChangesAll = true
		}
	}

	var findings []DCSyncFinding
	for sid, rights := range sidRights {
		if !rights.getChanges || !rights.getChangesAll {
			continue
		}
		info, ok := nameMap[sid]
		if !ok {
			continue
		}
		// Skip well-known built-in accounts that legitimately hold DCSync rights.
		// Use SID suffix matching — name-based filtering is bypassable with a
		// custom group named "Administrators" or "Enterprise Admins".
		if isBuiltinDCSyncSID(sid) {
			continue
		}
		const dcSyncVec = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"
		score := CVSSScore(dcSyncVec)
		findings = append(findings, DCSyncFinding{
			PrincipalName: info.Name,
			PrincipalType: info.Type,
			PrincipalDN:   info.DN,
			CVSS:          score,
			CVSSVector:    dcSyncVec,
			Severity:      CVSSSeverity(score),
		})
	}
	return findings
}

// isBuiltinDCSyncSID returns true for well-known SIDs that legitimately hold
// DCSync rights (Domain Controllers, Administrators, Domain/Enterprise Admins).
// SID suffix matching is used instead of name matching so that custom groups
// named "Administrators" or "Enterprise Admins" are not silently skipped.
func isBuiltinDCSyncSID(sid string) bool {
	// S-1-5-9 — Enterprise Domain Controllers (forest-wide)
	if sid == "S-1-5-9" {
		return true
	}
	// S-1-5-32-544 — BUILTIN\Administrators
	if sid == "S-1-5-32-544" {
		return true
	}
	// Domain-relative well-known RIDs: -512 DA, -516 DCs, -519 EA, -521 RODC
	for _, suffix := range []string{"-512", "-516", "-519", "-521"} {
		if strings.HasSuffix(sid, suffix) {
			return true
		}
	}
	return false
}

// checkPrivilegedOwners scans the SD of privileged objects (DA/EA/DC members)
// for non-default owners. The owner of any AD object has implicit WriteDACL rights
// regardless of the DACL, making non-default ownership a backdoor primitive.
func checkPrivilegedOwners(entries []*goldap.Entry, nameMap map[string]nameInfo, result *adldap.EnumerationResult) []OwnerFinding {
	// Build set of privileged user DNs (members of DA/EA/SA/Administrators)
	privDNs := make(map[string]string) // lower(DN) → SAMAccountName
	for _, g := range result.Groups {
		switch strings.ToLower(g.SAMAccountName) {
		case "domain admins", "enterprise admins", "schema admins", "administrators":
			for _, m := range g.Members {
				privDNs[strings.ToLower(m)] = m
			}
		}
	}
	for _, u := range result.Users {
		if u.AdminCount {
			privDNs[strings.ToLower(u.DN)] = u.SAMAccountName
		}
	}

	const ownerVec = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
	ownerScore := CVSSScore(ownerVec)

	var findings []OwnerFinding
	for _, entry := range entries {
		ldn := strings.ToLower(entry.DN)
		targetName, ok := privDNs[ldn]
		if !ok {
			continue
		}
		sdBytes := entry.GetRawAttributeValue("nTSecurityDescriptor")
		if len(sdBytes) == 0 {
			continue
		}
		ownerSID := parseSDOwner(sdBytes)
		if ownerSID == "" {
			continue
		}
		if isBuiltinDCSyncSID(ownerSID) {
			continue // expected privileged owner
		}
		// check if it's another privileged-group member by SID
		info, inMap := nameMap[ownerSID]
		if inMap && isPrivilegedPrincipal(info.Name) {
			continue
		}
		ownerName := ownerSID
		if inMap {
			ownerName = info.Name
		}
		findings = append(findings, OwnerFinding{
			OwnerSID:   ownerSID,
			OwnerName:  ownerName,
			TargetDN:   entry.DN,
			TargetName: targetName,
			Severity:   CVSSSeverity(ownerScore),
			CVSS:       ownerScore,
			CVSSVector: ownerVec,
		})
	}
	return findings
}

// ============================================================
// Парсинг ACL записів
// ============================================================

// parseACLEntry аналізує security descriptor одного об'єкта
func parseACLEntry(
	entry *goldap.Entry,
	nameMap map[string]nameInfo,
	result *adldap.EnumerationResult,
) []ACLFinding {
	var findings []ACLFinding

	targetDN := entry.DN
	targetName := entry.GetAttributeValue("sAMAccountName")
	targetType := getObjectType(entry)

	// отримуємо raw bytes nTSecurityDescriptor
	sdBytes := entry.GetRawAttributeValue("nTSecurityDescriptor")


	if len(sdBytes) == 0 {
		return findings
	}

	// парсимо security descriptor
	aces, err := parseSecurityDescriptor(sdBytes)
	if err != nil {
		return findings
	}


	for _, ace := range aces {

		// шукаємо principal в нашому nameMap
		principalInfo, exists := nameMap[ace.SID]
		if !exists {
			continue
		}


		// пропускаємо права на самого себе
		if strings.EqualFold(ace.SID, getSIDForDN(targetDN, result)) {
			continue
		}

		// перевіряємо кожне небезпечне право
		rights := detectDangerousRights(ace)


		for _, right := range rights {
			cvss, vec := calcACLCVSS(right, targetName)
			findings = append(findings, ACLFinding{
				PrincipalDN:   principalInfo.DN,
				PrincipalName: principalInfo.Name,
				PrincipalType: principalInfo.Type,
				TargetDN:      targetDN,
				TargetName:    targetName,
				TargetType:    targetType,
				Right:      right,
				CVSS:       cvss,
				CVSSVector: vec,
				Severity:   CVSSSeverity(cvss),
			})
		}
	}

	return findings
}


// ============================================================
// Парсинг Windows Security Descriptor
// ============================================================

// ACE — один запис в Access Control List
type ACE struct {
	SID        string // SID того хто має право (у форматі S-1-5-...)
	AccessMask uint32 // бітова маска прав
	ObjectType string // GUID для extended rights (може бути порожнім)
	ACEType    byte   // 0x00=Allow, 0x01=Deny, 0x05=ObjectAllow
}

// parseSecurityDescriptor парсить raw bytes Windows Security Descriptor
func parseSecurityDescriptor(data []byte) ([]ACE, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("security descriptor too short")
	}

	// Self-relative Security Descriptor (MS-DTYP 2.4.6):
	// Offset 0:  Revision (1 byte)
	// Offset 1:  Sbz1 (1 byte)
	// Offset 2:  Control (2 bytes, LE) — SE_DACL_PRESENT = 0x0004
	// Offset 4:  OffsetOwner (4 bytes, LE)
	// Offset 8:  OffsetGroup (4 bytes, LE)
	// Offset 12: OffsetSacl (4 bytes, LE)
	// Offset 16: OffsetDacl (4 bytes, LE)

	const seDACLPresent = 0x0004
	control := uint16(data[2]) | uint16(data[3])<<8
	if control&seDACLPresent == 0 {
		return nil, nil // SE_DACL_PRESENT not set — no DACL to parse
	}

	daclOffset := readUint32LE(data, 16)
	if daclOffset == 0 || int(daclOffset) >= len(data) {
		return nil, nil // no DACL
	}

	return parseACL(data, int(daclOffset))
}

// parseSDOwner extracts the Owner SID from a self-relative Security Descriptor.
// Returns empty string if the SD is too short or OffsetOwner is invalid.
func parseSDOwner(data []byte) string {
	if len(data) < 20 {
		return ""
	}
	ownerOffset := readUint32LE(data, 4)
	if ownerOffset == 0 || int(ownerOffset) >= len(data) {
		return ""
	}
	return parseSID(data, int(ownerOffset))
}

// parseACL парсить ACL структуру
func parseACL(data []byte, offset int) ([]ACE, error) {
	if offset+8 > len(data) {
		return nil, fmt.Errorf("ACL offset out of bounds")
	}

	// ACL Header:
	// Offset 0: AclRevision (1 byte)
	// Offset 1: Sbz1 (1 byte)
	// Offset 2: AclSize (2 bytes)
	// Offset 4: AceCount (2 bytes)
	// Offset 6: Sbz2 (2 bytes)

	aceCount := int(readUint16LE(data, offset+4))
	aceOffset := offset + 8

	var aces []ACE

	for i := 0; i < aceCount; i++ {
		if aceOffset+4 > len(data) {
			break
		}

		ace, size, err := parseACE(data, aceOffset)
		if err != nil {
			aceOffset += 4
			continue
		}

		// INHERIT_ONLY_ACE (0x08): applies only to child objects, not to this object itself.
		// Skipping these prevents inherited container ACEs from being reported as findings
		// on the object they propagate through.
		aceFlags := data[aceOffset+1]
		if aceFlags&0x08 != 0 {
			aceOffset += size
			continue
		}

		aces = append(aces, ace)
		aceOffset += size
	}

	return aces, nil
}

// parseACE парсить один ACE запис
func parseACE(data []byte, offset int) (ACE, int, error) {
	if offset+8 > len(data) {
		return ACE{}, 0, fmt.Errorf("ACE too short")
	}

	// ACE Header:
	// Offset 0: AceType (1 byte)
	// Offset 1: AceFlags (1 byte)
	// Offset 2: AceSize (2 bytes)

	aceType := data[offset]
	aceSize := int(readUint16LE(data, offset+2))

	if aceSize < 8 || offset+aceSize > len(data) {
		return ACE{}, aceSize, fmt.Errorf("invalid ACE size")
	}

	ace := ACE{ACEType: aceType}

	switch aceType {
	case 0x00, 0x01, // ACCESS_ALLOWED_ACE, ACCESS_DENIED_ACE
		0x09, 0x0A: // ACCESS_ALLOWED_CALLBACK_ACE, ACCESS_DENIED_CALLBACK_ACE (same layout, conditional ACEs)
		// Offset 4: AccessMask (4 bytes)
		// Offset 8: SID (condition data follows SID but we don't need it)
		ace.AccessMask = readUint32LE(data, offset+4)
		ace.SID = parseSID(data, offset+8)

	case 0x05, 0x06, // ACCESS_ALLOWED_OBJECT_ACE, ACCESS_DENIED_OBJECT_ACE
		0x0B, 0x0C: // ACCESS_ALLOWED_CALLBACK_OBJECT_ACE, ACCESS_DENIED_CALLBACK_OBJECT_ACE
		// Offset 4:  AccessMask (4 bytes)
		// Offset 8:  Flags (4 bytes)
		// Offset 12: ObjectType GUID (16 bytes, якщо є)
		// Offset 28: InheritedObjectType GUID (16 bytes, якщо є)
		// потім SID
		ace.AccessMask = readUint32LE(data, offset+4)
		flags := readUint32LE(data, offset+8)

		sidOffset := offset + 12
		if flags&0x01 != 0 { // ACE_OBJECT_TYPE_PRESENT
			if offset+28 <= len(data) {
				ace.ObjectType = formatGUID(data[offset+12 : offset+28])
				sidOffset = offset + 28
			}
		}
		if flags&0x02 != 0 { // ACE_INHERITED_OBJECT_TYPE_PRESENT
			sidOffset += 16
		}

		if sidOffset < offset+aceSize {
			ace.SID = parseSID(data, sidOffset)
		}
	}

	return ace, aceSize, nil
}

// ============================================================
// Допоміжні функції парсингу
// ============================================================

// parseSID конвертує raw bytes SID в рядок S-1-5-...
func parseSID(data []byte, offset int) string {
	if offset+8 > len(data) {
		return ""
	}

	revision := data[offset]
	subAuthorityCount := int(data[offset+1])

	if offset+8+subAuthorityCount*4 > len(data) {
		return ""
	}

	// identifier authority (6 bytes, big-endian)
	var authority uint64
	for i := 0; i < 6; i++ {
		authority = authority<<8 | uint64(data[offset+2+i])
	}

	sid := fmt.Sprintf("S-%d-%d", revision, authority)

	for i := 0; i < subAuthorityCount; i++ {
		subAuth := readUint32LE(data, offset+8+i*4)
		sid += fmt.Sprintf("-%d", subAuth)
	}

	return sid
}

// formatGUID конвертує 16 bytes GUID в рядок
func formatGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		readUint32LE(b, 0),
		readUint16LE(b, 4),
		readUint16LE(b, 6),
		[]byte{b[8], b[9]},
		b[10:16],
	)
}

func readUint32LE(data []byte, offset int) uint32 {
	if offset+4 > len(data) {
		return 0
	}
	return uint32(data[offset]) |
		uint32(data[offset+1])<<8 |
		uint32(data[offset+2])<<16 |
		uint32(data[offset+3])<<24
}

func readUint16LE(data []byte, offset int) uint16 {
	if offset+2 > len(data) {
		return 0
	}
	return uint16(data[offset]) | uint16(data[offset+1])<<8
}

// ============================================================
// Детектування небезпечних прав
// ============================================================

// detectDangerousRights перевіряє ACE на небезпечні права
func detectDangerousRights(ace ACE) []ACLRight {
	// deny ACE types: 0x01, 0x06, 0x0A (callback deny), 0x0C (callback object deny)
	if ace.ACEType == 0x01 || ace.ACEType == 0x06 || ace.ACEType == 0x0A || ace.ACEType == 0x0C {
		return nil
	}


	var rights []ACLRight

	// Generic права
	if ace.AccessMask&ADS_RIGHT_GENERIC_ALL != 0 {
		rights = append(rights, RightGenericAll)
	}
	if ace.AccessMask&ADS_RIGHT_WRITE_DACL != 0 {
		rights = append(rights, RightWriteDACL)
	}
	if ace.AccessMask&ADS_RIGHT_WRITE_OWNER != 0 {
		rights = append(rights, RightWriteOwner)
	}
	if ace.AccessMask&ADS_RIGHT_GENERIC_WRITE != 0 {
		rights = append(rights, RightGenericWrite)
	}

	// специфічні AD права — повний доступ
	if ace.AccessMask&0x000F01FF == 0x000F01FF {
		rights = append(rights, RightGenericAll)
	}
	// WriteDACL специфічний
	if ace.AccessMask&0x00040000 != 0 {
		if !containsRight(rights, RightWriteDACL) {
			rights = append(rights, RightWriteDACL)
		}
	}
	// WriteOwner специфічний
	if ace.AccessMask&0x00080000 != 0 {
		if !containsRight(rights, RightWriteOwner) {
			rights = append(rights, RightWriteOwner)
		}
	}

	// Extended rights via GUID — must also verify the correct access-mask bit.
	// ForceChangePassword is a Control Access right (DS_CONTROL_ACCESS = 0x100).
	// AddMember (Self-Membership) is a Validated Write right (DS_SELF = 0x8).
	if ace.ObjectType != "" {
		switch strings.ToLower(ace.ObjectType) {
		case guidForceChangePassword:
			if ace.AccessMask&ADS_RIGHT_DS_CONTROL_ACCESS != 0 {
				rights = append(rights, RightForceChangePassword)
			}
		case guidAddMember:
			if ace.AccessMask&ADS_RIGHT_DS_SELF != 0 {
				rights = append(rights, RightAddMember)
			}
		}
	}

	return rights
}

// containsRight перевіряє чи є право вже в списку
func containsRight(rights []ACLRight, right ACLRight) bool {
	for _, r := range rights {
		if r == right {
			return true
		}
	}
	return false
}

// ============================================================
// Допоміжні структури і функції
// ============================================================

type nameInfo struct {
	DN   string
	Name string
	Type string
}

// buildNameMap будує map SID → nameInfo з EnumerationResult
func buildNameMap(result *adldap.EnumerationResult) map[string]nameInfo {
	m := make(map[string]nameInfo)
	for _, u := range result.Users {
		if u.ObjectSid != "" {
			m[u.ObjectSid] = nameInfo{DN: u.DN, Name: u.SAMAccountName, Type: "user"}
		}
	}
	for _, g := range result.Groups {
		if g.ObjectSid != "" {
			m[g.ObjectSid] = nameInfo{DN: g.DN, Name: g.SAMAccountName, Type: "group"}
		}
	}
	for _, c := range result.Computers {
		if c.ObjectSid != "" {
			m[c.ObjectSid] = nameInfo{DN: c.DN, Name: c.SAMAccountName, Type: "computer"}
		}
	}
	return m
}

// getObjectType визначає тип об'єкта з objectClass
func getObjectType(entry *goldap.Entry) string {
	classes := entry.GetAttributeValues("objectClass")
	for _, c := range classes {
		switch strings.ToLower(c) {
		case "user":
			return "user"
		case "group":
			return "group"
		case "computer":
			return "computer"
		}
	}
	return "object"
}

// getSIDForDN повертає SID об'єкта за його DN
func getSIDForDN(dn string, result *adldap.EnumerationResult) string {
	for _, u := range result.Users {
		if strings.EqualFold(u.DN, dn) {
			return u.ObjectSid
		}
	}
	for _, g := range result.Groups {
		if strings.EqualFold(g.DN, dn) {
			return g.ObjectSid
		}
	}
	for _, c := range result.Computers {
		if strings.EqualFold(c.DN, dn) {
			return c.ObjectSid
		}
	}
	return ""
}


// filterSystemACL прибирає стандартні системні ACL
func filterSystemACL(findings []ACLFinding) []ACLFinding {
	// показуємо тільки знахідки де principal — звичайний user
	// або кастомна група (не вбудована системна)
	builtinGroups := map[string]bool{
		"Administrators":                          true,
		"Account Operators":                       true,
		"Server Operators":                        true,
		"Print Operators":                         true,
		"Backup Operators":                        true,
		"Domain Admins":                           true,
		"Enterprise Admins":                       true,
		"Schema Admins":                           true,
		"Group Policy Creator Owners":             true,
		"SYSTEM":                                  true,
		"Administrator":                           true,
		"Domain Controllers":                      true,
		"Read-only Domain Controllers":            true,
		"Cloneable Domain Controllers":            true,
		"Key Admins":                              true,
		"Enterprise Key Admins":                   true,
	}

	var filtered []ACLFinding
	for _, f := range findings {
		if builtinGroups[f.PrincipalName] {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// calcACLCVSS returns the CVSS 3.1 base score for an ACL finding.
// Vectors derived from CVSS 3.1 calculator using AD attacker context (PR:L = domain user).
func calcACLCVSS(right ACLRight, targetName string) (float64, string) {
	privileged := isPrivilegedTarget(targetName)
	var vec string
	switch right {
	case RightGenericAll, RightWriteDACL, RightWriteOwner:
		if privileged {
			vec = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
		} else {
			vec = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
		}
	case RightAddMember:
		if privileged {
			vec = "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
		} else {
			vec = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
		}
	case RightForceChangePassword:
		vec = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
	case RightGenericWrite:
		vec = "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
	default:
		vec = "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
	}
	return CVSSScore(vec), vec
}

// isPrivilegedTarget returns true if the target is a high-value AD object
func isPrivilegedTarget(name string) bool {
	lower := strings.ToLower(name)
	privileged := []string{
		"domain admins", "enterprise admins", "schema admins",
		"administrators", "domain controllers", "krbtgt",
		"account operators", "backup operators", "print operators",
		"server operators", "group policy creator owners",
	}
	for _, p := range privileged {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// ============================================================
// Вивід результатів
// ============================================================

// PrintACLResult виводить результати ACL аналізу
func PrintACLResult(aclResult *ACLResult) {
	color.Cyan("\n  ACL FINDINGS")
	if len(aclResult.Findings) == 0 {
		color.White("  none found")
		return
	}

	critical := filterBySeverity(aclResult.Findings, "Critical")
	high := filterBySeverity(aclResult.Findings, "High")
	medium := filterBySeverity(aclResult.Findings, "Medium")

	if len(critical) > 0 {
		color.Red("  CRITICAL (%d)", len(critical))
		for _, f := range critical {
			printACLFinding(f)
		}
	}
	if len(high) > 0 {
		color.Yellow("\n  HIGH (%d)", len(high))
		for _, f := range high {
			printACLFinding(f)
		}
	}
	if len(medium) > 0 {
		color.White("\n  MEDIUM (%d)", len(medium))
		for _, f := range medium {
			printACLFinding(f)
		}
	}
	printACLExploitHints(aclResult)

	if len(aclResult.OwnerFindings) > 0 {
		color.Cyan("\n  NON-DEFAULT OWNERS")
		color.Red("  %-28s %d — privileged objects with unexpected owners", "owner risks", len(aclResult.OwnerFindings))
		color.White("  %-30s %-24s %s", "target object", "owner", "owner sid")
		color.White("  " + strings.Repeat("-", 72))
		for _, f := range aclResult.OwnerFindings {
			color.Red("  %-30s %-24s %s", f.TargetName, f.OwnerName, f.OwnerSID)
		}
	}
}

func printACLFinding(f ACLFinding) {
	color.White("  %-20s %-22s -> %s  (%s)",
		f.PrincipalName,
		"["+string(f.Right)+"]",
		f.TargetName,
		f.TargetType,
	)
}

func printACLExploitHints(aclResult *ACLResult) {
	color.Cyan("\n  EXPLOITATION HINTS")

	seen := make(map[ACLRight]bool)
	for _, f := range aclResult.Findings {
		if seen[f.Right] {
			continue
		}
		seen[f.Right] = true

		switch f.Right {
		case RightGenericAll:
			color.White("  GenericAll      bloodyAD -u %s -p <pass> -d %s --host <DC> add groupMember 'Domain Admins' %s",
				f.PrincipalName, aclResult.Domain, f.PrincipalName)
		case RightForceChangePassword:
			color.White("  ForcePwdChange  bloodyAD -u %s -p <pass> -d %s --host <DC> set password %s 'NewPass123!'",
				f.PrincipalName, aclResult.Domain, f.TargetName)
		case RightWriteDACL:
			color.White("  WriteDACL       bloodyAD -u %s -p <pass> -d %s --host <DC> add genericAll %s",
				f.PrincipalName, aclResult.Domain, f.TargetName)
		case RightAddMember:
			color.White("  AddMember       bloodyAD -u %s -p <pass> -d %s --host <DC> add groupMember '%s' %s",
				f.PrincipalName, aclResult.Domain, f.TargetName, f.PrincipalName)
		}
	}
}

func filterBySeverity(findings []ACLFinding, severity string) []ACLFinding {
	var result []ACLFinding
	for _, f := range findings {
		if f.Severity == severity {
			result = append(result, f)
		}
	}
	return result
}