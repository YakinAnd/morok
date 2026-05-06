// gendemo generates a realistic fake adpath HTML report for design review.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/YakinAnd/morok/internal/analysis"
	"github.com/YakinAnd/morok/internal/graph"
	adldap "github.com/YakinAnd/morok/internal/ldap"
	"github.com/YakinAnd/morok/internal/report"
)

const domain = "sevenkingdoms.local"
const baseDN = "DC=sevenkingdoms,DC=local"

func main() {
	out := "demo-report.html"
	if len(os.Args) > 1 {
		out = os.Args[1]
	}

	result := buildEnumResult()
	g, paths := buildGraph(result)

	err := report.Generate(
		out,
		result,
		g,
		paths,
		buildKerberos(),
		buildACL(),
		buildDelegation(),
		buildGPO(),
		buildHygiene(result),
		buildPSO(),
		buildADCS(),
		buildProtectedUsers(),
		buildAdminSDHolder(),
		buildTrusts(),
		buildShadowCreds(),
		buildLDAPSecurity(),
		buildAudit(),
		buildSMBSigning(),
		buildSYSVOL(),
		buildLAPSACL(),
		"Password",
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Report written to", out)
}

// ── Enumeration ───────────────────────────────────────────────

func buildEnumResult() *adldap.EnumerationResult {
	return &adldap.EnumerationResult{
		Domain:      domain,
		BaseDN:      baseDN,
		CollectedAt: time.Now(),
		Users:       fakeUsers(),
		Groups:      fakeGroups(),
		Computers:   fakeComputers(),
	}
}

func fakeUsers() []adldap.LDAPUser {
	return []adldap.LDAPUser{
		{
			DN: "CN=Administrator,CN=Users," + baseDN,
			SAMAccountName: "Administrator", CN: "Administrator",
			DisplayName: "Built-in Administrator", Mail: "admin@sevenkingdoms.local",
			Description:          "Built-in account for administering the computer/domain",
			Enabled: true, AdminCount: true, PasswordNeverExpires: true,
			LastLogon: "2026-04-28 09:12:34", PasswordLastSet: "2025-11-01 08:00:00",
			ObjectSid:   "S-1-5-21-3850359155-1265902998-2437639109-500",
			CreatedOn:   "2023-01-10 10:00:00", ChangedOn: "2026-04-28 09:12:34",
			PrimaryGroup: "Domain Users",
			MemberOf: []string{
				"CN=Domain Admins,CN=Users," + baseDN,
				"CN=Enterprise Admins,CN=Users," + baseDN,
				"CN=Schema Admins,CN=Users," + baseDN,
				"CN=Group Policy Creator Owners,CN=Users," + baseDN,
			},
		},
		{
			DN: "CN=jsnow,CN=Users," + baseDN,
			SAMAccountName: "jsnow", CN: "jsnow",
			DisplayName: "Jon Snow", Mail: "j.snow@sevenkingdoms.local",
			Description: "",
			Enabled: true, AdminCount: false, PasswordNeverExpires: false,
			SPNs: []string{"HTTP/winterfell.sevenkingdoms.local", "HTTP/winterfell"},
			LastLogon: "2026-04-29 07:44:11", PasswordLastSet: "2025-06-12 14:22:00",
			ObjectSid:   "S-1-5-21-3850359155-1265902998-2437639109-1103",
			CreatedOn:   "2023-03-15 11:30:00", ChangedOn: "2026-01-20 09:05:12",
			PrimaryGroup: "Domain Users",
			MemberOf: []string{
				"CN=Night's Watch,CN=Users," + baseDN,
				"CN=Wildlings,CN=Users," + baseDN,
			},
		},
		{
			DN: "CN=cersei,CN=Users," + baseDN,
			SAMAccountName: "cersei", CN: "cersei",
			DisplayName: "Cersei Lannister", Mail: "c.lannister@sevenkingdoms.local",
			Description: "Password: Cersei2024!",
			Enabled: true, AdminCount: true, PasswordNeverExpires: true,
			LastLogon: "2026-04-27 16:01:55", PasswordLastSet: "2024-01-08 08:30:00",
			ObjectSid:   "S-1-5-21-3850359155-1265902998-2437639109-1104",
			CreatedOn:   "2023-03-15 11:31:00", ChangedOn: "2026-03-01 12:44:00",
			PrimaryGroup: "Domain Users",
			MemberOf: []string{
				"CN=Domain Admins,CN=Users," + baseDN,
				"CN=Remote Desktop Users,CN=Builtin," + baseDN,
			},
		},
		{
			DN: "CN=tyrion,CN=Users," + baseDN,
			SAMAccountName: "tyrion", CN: "tyrion",
			DisplayName: "Tyrion Lannister", Mail: "t.lannister@sevenkingdoms.local",
			Description: "",
			Enabled: true, DontReqPreauth: true,
			LastLogon: "2026-04-26 11:22:00", PasswordLastSet: "2025-09-14 10:00:00",
			ObjectSid:   "S-1-5-21-3850359155-1265902998-2437639109-1105",
			CreatedOn:   "2023-03-16 09:00:00", ChangedOn: "2026-02-14 15:30:00",
			PrimaryGroup: "Domain Users",
			MemberOf:     []string{"CN=Small Council,CN=Users," + baseDN},
		},
		{
			DN: "CN=svc_sql,CN=Users," + baseDN,
			SAMAccountName: "svc_sql", CN: "svc_sql",
			DisplayName: "SQL Service Account", Mail: "",
			Description: "",
			Enabled: true, AdminCount: false, PasswordNeverExpires: true,
			SPNs: []string{"MSSQLSvc/kingslanding.sevenkingdoms.local:1433", "MSSQLSvc/kingslanding:1433"},
			LastLogon: "2026-04-29 04:00:00", PasswordLastSet: "2022-07-01 09:00:00",
			ObjectSid:   "S-1-5-21-3850359155-1265902998-2437639109-1120",
			CreatedOn:   "2022-07-01 09:00:00", ChangedOn: "2026-04-29 04:00:00",
			PrimaryGroup: "Domain Users",
			MemberOf:     []string{"CN=Service Accounts,CN=Users," + baseDN},
		},
		{
			DN: "CN=svc_backup,CN=Users," + baseDN,
			SAMAccountName: "svc_backup", CN: "svc_backup",
			DisplayName: "Backup Service", Mail: "",
			Description: "backup service - do not disable",
			Enabled: true, PasswordNeverExpires: true,
			SPNs: []string{"backup/kingslanding.sevenkingdoms.local"},
			LastLogon: "2026-04-28 23:00:11", PasswordLastSet: "2021-03-10 08:00:00",
			ObjectSid:   "S-1-5-21-3850359155-1265902998-2437639109-1121",
			CreatedOn:   "2021-03-10 08:00:00", ChangedOn: "2026-04-28 23:00:11",
			PrimaryGroup: "Domain Users",
			MemberOf: []string{
				"CN=Backup Operators,CN=Builtin," + baseDN,
				"CN=Service Accounts,CN=Users," + baseDN,
			},
		},
		{
			DN: "CN=arya",
			SAMAccountName: "arya", CN: "arya",
			DisplayName: "Arya Stark", Mail: "a.stark@sevenkingdoms.local",
			Enabled: false,
			LastLogon: "2025-11-03 08:10:00", PasswordLastSet: "2025-01-01 00:00:00",
			ObjectSid:   "S-1-5-21-3850359155-1265902998-2437639109-1110",
			CreatedOn:   "2023-03-20 10:00:00", ChangedOn: "2025-11-03 08:10:00",
			PrimaryGroup: "Domain Users",
			MemberOf:     []string{"CN=Night's Watch,CN=Users," + baseDN},
		},
		{
			DN: "CN=stannis,CN=Users," + baseDN,
			SAMAccountName: "stannis", CN: "stannis",
			DisplayName: "Stannis Baratheon", Mail: "stannis@sevenkingdoms.local",
			Enabled: true, AdminCount: true, PasswordNeverExpires: false,
			LastLogon: "2025-06-15 09:00:00", PasswordLastSet: "2024-06-15 09:00:00",
			ObjectSid:   "S-1-5-21-3850359155-1265902998-2437639109-1115",
			CreatedOn:   "2023-04-01 08:00:00", ChangedOn: "2025-06-15 09:00:00",
			PrimaryGroup: "Domain Users",
			MemberOf: []string{
				"CN=Domain Admins,CN=Users," + baseDN,
			},
		},
		{
			DN: "CN=krbtgt,CN=Users," + baseDN,
			SAMAccountName: "krbtgt", CN: "krbtgt",
			DisplayName: "krbtgt", Mail: "",
			Description: "Key Distribution Center Service Account",
			Enabled: false,
			LastLogon: "Never", PasswordLastSet: "2023-01-10 10:00:00",
			ObjectSid:   "S-1-5-21-3850359155-1265902998-2437639109-502",
			CreatedOn:   "2023-01-10 10:00:00", ChangedOn: "2023-01-10 10:00:00",
			PrimaryGroup: "Domain Users",
			MemberOf:     []string{"CN=Denied RODC Password Replication Group,CN=Users," + baseDN},
		},
	}
}

func fakeGroups() []adldap.LDAPGroup {
	return []adldap.LDAPGroup{
		{
			DN: "CN=Domain Admins,CN=Users," + baseDN,
			SAMAccountName: "Domain Admins", CN: "Domain Admins",
			Description: "Designated administrators of the domain",
			GroupType:   "Security/Global", AdminCount: true,
			ObjectSid: "S-1-5-21-3850359155-1265902998-2437639109-512",
			CreatedOn: "2023-01-10 10:00:00", ChangedOn: "2026-03-01 12:44:00",
			Members: []string{
				"CN=Administrator,CN=Users," + baseDN,
				"CN=cersei,CN=Users," + baseDN,
				"CN=stannis,CN=Users," + baseDN,
			},
		},
		{
			DN: "CN=Enterprise Admins,CN=Users," + baseDN,
			SAMAccountName: "Enterprise Admins", CN: "Enterprise Admins",
			Description: "Designated administrators of the enterprise",
			GroupType:   "Security/Universal", AdminCount: true,
			ObjectSid: "S-1-5-21-3850359155-1265902998-2437639109-519",
			CreatedOn: "2023-01-10 10:00:00", ChangedOn: "2023-01-10 10:00:00",
			Members: []string{"CN=Administrator,CN=Users," + baseDN},
		},
		{
			DN: "CN=Backup Operators,CN=Builtin," + baseDN,
			SAMAccountName: "Backup Operators", CN: "Backup Operators",
			Description: "Backup Operators can override security restrictions for the sole purpose of backing up or restoring files",
			GroupType:   "Security/Local", AdminCount: true,
			ObjectSid: "S-1-5-21-3850359155-1265902998-2437639109-551",
			CreatedOn: "2023-01-10 10:00:00", ChangedOn: "2024-01-15 09:30:00",
			Members: []string{"CN=svc_backup,CN=Users," + baseDN},
		},
		{
			DN: "CN=Domain Users,CN=Users," + baseDN,
			SAMAccountName: "Domain Users", CN: "Domain Users",
			Description: "All domain users", GroupType: "Security/Global",
			ObjectSid: "S-1-5-21-3850359155-1265902998-2437639109-513",
			CreatedOn: "2023-01-10 10:00:00", ChangedOn: "2023-01-10 10:00:00",
			Members: []string{},
		},
		{
			DN: "CN=Night's Watch,CN=Users," + baseDN,
			SAMAccountName: "Night's Watch", CN: "Night's Watch",
			Description: "Castle Black operations",
			GroupType:   "Security/Global",
			ObjectSid:   "S-1-5-21-3850359155-1265902998-2437639109-1200",
			CreatedOn:   "2023-03-15 11:35:00", ChangedOn: "2026-01-10 08:00:00",
			Members: []string{
				"CN=jsnow,CN=Users," + baseDN,
				"CN=arya,CN=Users," + baseDN,
			},
			MemberOf: []string{"CN=Castle Black Staff,CN=Users," + baseDN},
		},
		{
			DN: "CN=Small Council,CN=Users," + baseDN,
			SAMAccountName: "Small Council", CN: "Small Council",
			Description: "King's Landing administration",
			GroupType:   "Security/Global",
			ObjectSid:   "S-1-5-21-3850359155-1265902998-2437639109-1201",
			CreatedOn:   "2023-03-16 09:05:00", ChangedOn: "2026-02-20 14:00:00",
			Members: []string{"CN=tyrion,CN=Users," + baseDN},
		},
		{
			DN: "CN=Service Accounts,CN=Users," + baseDN,
			SAMAccountName: "Service Accounts", CN: "Service Accounts",
			Description: "Service accounts — do not add users",
			GroupType:   "Security/Global",
			ObjectSid:   "S-1-5-21-3850359155-1265902998-2437639109-1202",
			CreatedOn:   "2022-06-01 08:00:00", ChangedOn: "2024-03-10 11:00:00",
			Members: []string{
				"CN=svc_sql,CN=Users," + baseDN,
				"CN=svc_backup,CN=Users," + baseDN,
			},
		},
		{
			DN: "CN=Remote Desktop Users,CN=Builtin," + baseDN,
			SAMAccountName: "Remote Desktop Users", CN: "Remote Desktop Users",
			Description: "Members in this group are granted the right to logon remotely",
			GroupType:   "Security/Local",
			ObjectSid:   "S-1-5-21-3850359155-1265902998-2437639109-555",
			CreatedOn:   "2023-01-10 10:00:00", ChangedOn: "2026-03-01 12:44:00",
			Members: []string{"CN=cersei,CN=Users," + baseDN},
		},
	}
}

func fakeComputers() []adldap.LDAPComputer {
	return []adldap.LDAPComputer{
		{
			DN: "CN=KINGSLANDING,OU=Domain Controllers," + baseDN,
			SAMAccountName: "KINGSLANDING$", CN: "KINGSLANDING",
			DNSHostName: "kingslanding.sevenkingdoms.local",
			OperatingSystem: "Windows Server 2019 Datacenter",
			OperatingSystemVersion: "10.0 (17763)",
			Enabled: true, LAPSEnabled: false, UnconstrainedDelegation: true,
			LastLogon: "2026-04-29 08:00:01", WhenCreated: "2023-01-10",
			ChangedOn: "2026-04-29 08:00:01",
			ObjectSid: "S-1-5-21-3850359155-1265902998-2437639109-1000",
			Description: "Primary Domain Controller", Domain: domain,
		},
		{
			DN: "CN=WINTERFELL,OU=Servers," + baseDN,
			SAMAccountName: "WINTERFELL$", CN: "WINTERFELL",
			DNSHostName: "winterfell.sevenkingdoms.local",
			OperatingSystem: "Windows Server 2016 Standard",
			OperatingSystemVersion: "10.0 (14393)",
			Enabled: true, LAPSEnabled: true, UnconstrainedDelegation: false,
			LastLogon: "2026-04-28 22:10:33", WhenCreated: "2023-03-20",
			ChangedOn: "2026-04-01 06:30:00",
			ObjectSid: "S-1-5-21-3850359155-1265902998-2437639109-1001",
			Description: "Application server", Domain: domain,
		},
		{
			DN: "CN=CASTLEBLACK,OU=Servers," + baseDN,
			SAMAccountName: "CASTLEBLACK$", CN: "CASTLEBLACK",
			DNSHostName: "castleblack.sevenkingdoms.local",
			OperatingSystem: "Windows Server 2012 R2 Standard",
			OperatingSystemVersion: "6.3 (9600)",
			Enabled: true, LAPSEnabled: false, UnconstrainedDelegation: false,
			LastLogon: "2026-04-25 04:01:44", WhenCreated: "2023-03-20",
			ChangedOn: "2026-03-10 09:00:00",
			ObjectSid: "S-1-5-21-3850359155-1265902998-2437639109-1002",
			Domain: domain,
		},
		{
			DN: "CN=DRAGONSTONE,OU=Workstations," + baseDN,
			SAMAccountName: "DRAGONSTONE$", CN: "DRAGONSTONE",
			DNSHostName: "dragonstone.sevenkingdoms.local",
			OperatingSystem: "Windows 10 Enterprise",
			OperatingSystemVersion: "10.0 (19044)",
			Enabled: true, LAPSEnabled: false, UnconstrainedDelegation: false,
			LastLogon: "2025-09-01 14:55:00", WhenCreated: "2023-06-01",
			ChangedOn: "2025-09-01 14:55:00",
			ObjectSid: "S-1-5-21-3850359155-1265902998-2437639109-1010",
			Description: "Stale workstation", Domain: domain,
		},
		{
			DN: "CN=REDKEEP,OU=Servers," + baseDN,
			SAMAccountName: "REDKEEP$", CN: "REDKEEP",
			DNSHostName: "redkeep.sevenkingdoms.local",
			OperatingSystem: "Windows Server 2022 Datacenter",
			OperatingSystemVersion: "10.0 (20348)",
			Enabled: true, LAPSEnabled: true, UnconstrainedDelegation: false,
			LastLogon: "2026-04-29 07:45:00", WhenCreated: "2024-02-10",
			ChangedOn: "2026-04-10 10:00:00",
			ObjectSid: "S-1-5-21-3850359155-1265902998-2437639109-1003",
			Description: "File server", Domain: domain,
		},
	}
}

// ── Graph & Attack Paths ──────────────────────────────────────

func buildGraph(result *adldap.EnumerationResult) (*graph.Graph, []graph.AttackPath) {
	g := graph.NewGraph()

	userMap := map[string]adldap.LDAPUser{}
	for _, u := range result.Users {
		userMap[u.DN] = u
	}

	for _, u := range result.Users {
		g.AddNode(&graph.Node{
			DN: u.DN, SAMAccountName: u.SAMAccountName, DisplayName: u.DisplayName,
			Type: graph.NodeUser, AdminCount: u.AdminCount, Enabled: u.Enabled,
			Kerberoastable: len(u.SPNs) > 0, ASREPRoastable: u.DontReqPreauth,
			PasswordNeverExpires: u.PasswordNeverExpires,
		})
	}
	for _, grp := range result.Groups {
		g.AddNode(&graph.Node{
			DN: grp.DN, SAMAccountName: grp.SAMAccountName,
			Type: graph.NodeGroup, AdminCount: grp.AdminCount, Enabled: true,
		})
	}
	for _, c := range result.Computers {
		g.AddNode(&graph.Node{
			DN: c.DN, SAMAccountName: c.SAMAccountName,
			Type: graph.NodeComputer, Enabled: c.Enabled,
			UnconstrainedDelegation: c.UnconstrainedDelegation,
		})
	}
	for _, u := range result.Users {
		for _, gDN := range u.MemberOf {
			g.AddEdge(graph.Edge{From: u.DN, To: gDN, Type: graph.EdgeMemberOf})
		}
	}

	daNode := g.Nodes["CN=Domain Admins,CN=Users,"+baseDN]
	jsnowNode := g.Nodes["CN=jsnow,CN=Users,"+baseDN]
	backupNode := g.Nodes["CN=Backup Operators,CN=Builtin,"+baseDN]
	svcBackupNode := g.Nodes["CN=svc_backup,CN=Users,"+baseDN]
	tyrionNode := g.Nodes["CN=tyrion,CN=Users,"+baseDN]
	councilNode := g.Nodes["CN=Small Council,CN=Users,"+baseDN]

	var paths []graph.AttackPath

	if jsnowNode != nil && daNode != nil {
		paths = append(paths, graph.AttackPath{
			Nodes: []graph.Node{*jsnowNode, {
				DN: "CN=Night's Watch,CN=Users," + baseDN,
				SAMAccountName: "Night's Watch", Type: graph.NodeGroup,
			}, *daNode},
			Edges: []graph.Edge{
				{From: jsnowNode.DN, To: "CN=Night's Watch,CN=Users," + baseDN, Type: graph.EdgeMemberOf},
				{From: "CN=Night's Watch,CN=Users," + baseDN, To: daNode.DN, Type: "GenericAll"},
			},
			Depth:       2,
			TargetGroup: "Domain Admins",
		})
	}

	if svcBackupNode != nil && backupNode != nil {
		paths = append(paths, graph.AttackPath{
			Nodes: []graph.Node{*svcBackupNode, *backupNode},
			Edges: []graph.Edge{
				{From: svcBackupNode.DN, To: backupNode.DN, Type: graph.EdgeMemberOf},
			},
			Depth:       1,
			TargetGroup: "Backup Operators",
		})
	}

	if tyrionNode != nil && councilNode != nil && daNode != nil {
		paths = append(paths, graph.AttackPath{
			Nodes: []graph.Node{*tyrionNode, *councilNode, {
				DN: "CN=Remote Desktop Users,CN=Builtin," + baseDN,
				SAMAccountName: "Remote Desktop Users", Type: graph.NodeGroup,
			}, *daNode},
			Edges: []graph.Edge{
				{From: tyrionNode.DN, To: councilNode.DN, Type: graph.EdgeMemberOf},
				{From: councilNode.DN, To: "CN=Remote Desktop Users,CN=Builtin," + baseDN, Type: "WriteDACL"},
				{From: "CN=Remote Desktop Users,CN=Builtin," + baseDN, To: daNode.DN, Type: "AddMember"},
			},
			Depth:       3,
			TargetGroup: "Domain Admins",
		})
	}

	return g, paths
}

// ── Analysis results ──────────────────────────────────────────

func buildKerberos() *analysis.KerberosResult {
	return &analysis.KerberosResult{
		Domain: domain,
		KerberoastableAccounts: []analysis.KerberoastableAccount{
			{
				SAMAccountName: "svc_sql", DN: "CN=svc_sql,CN=Users," + baseDN,
				SPNs: []string{"MSSQLSvc/kingslanding.sevenkingdoms.local:1433", "MSSQLSvc/kingslanding:1433"},
				AdminCount: false, PasswordLastSet: "2022-07-01 09:00:00",
				LastLogon: "2026-04-29 04:00:00", CVSS: 8.8, CVSSVector: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", Severity: "High",
			},
			{
				SAMAccountName: "svc_backup", DN: "CN=svc_backup,CN=Users," + baseDN,
				SPNs: []string{"backup/kingslanding.sevenkingdoms.local"},
				AdminCount: false, PasswordLastSet: "2021-03-10 08:00:00",
				LastLogon: "2026-04-28 23:00:11",
				Description: "backup service - do not disable",
				CVSS: 9.1, CVSSVector: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", Severity: "Critical",
			},
			{
				SAMAccountName: "jsnow", DN: "CN=jsnow,CN=Users," + baseDN,
				SPNs: []string{"HTTP/winterfell.sevenkingdoms.local", "HTTP/winterfell"},
				AdminCount: false, PasswordLastSet: "2025-06-12 14:22:00",
				LastLogon: "2026-04-29 07:44:11", CVSS: 7.5, CVSSVector: "AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H", Severity: "High",
			},
		},
		ASREPAccounts: []analysis.ASREPAccount{
			{
				SAMAccountName: "tyrion", DN: "CN=tyrion,CN=Users," + baseDN,
				AdminCount: false, PasswordLastSet: "2025-09-14 10:00:00",
				LastLogon: "2026-04-26 11:22:00", CVSS: 7.5, CVSSVector: "AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", Severity: "High",
			},
		},
		AnalyzedAt: time.Now(),
	}
}

func buildACL() *analysis.ACLResult {
	return &analysis.ACLResult{
		Domain: domain,
		Findings: []analysis.ACLFinding{
			{
				PrincipalDN: "CN=Night's Watch,CN=Users," + baseDN,
				PrincipalName: "Night's Watch", PrincipalType: "group",
				TargetDN: "CN=Domain Admins,CN=Users," + baseDN,
				TargetName: "Domain Admins", TargetType: "group",
				Right: analysis.RightGenericAll, Severity: "Critical", CVSS: 9.9, CVSSVector: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
			},
			{
				PrincipalDN: "CN=tyrion,CN=Users," + baseDN,
				PrincipalName: "tyrion", PrincipalType: "user",
				TargetDN: "CN=Small Council,CN=Users," + baseDN,
				TargetName: "Small Council", TargetType: "group",
				Right: analysis.RightWriteDACL, Severity: "Critical", CVSS: 9.1, CVSSVector: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
			},
			{
				PrincipalDN: "CN=cersei,CN=Users," + baseDN,
				PrincipalName: "cersei", PrincipalType: "user",
				TargetDN: "CN=jsnow,CN=Users," + baseDN,
				TargetName: "jsnow", TargetType: "user",
				Right: analysis.RightForceChangePassword, Severity: "High", CVSS: 8.1, CVSSVector: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
			},
			{
				PrincipalDN: "CN=Small Council,CN=Users," + baseDN,
				PrincipalName: "Small Council", PrincipalType: "group",
				TargetDN: "CN=Remote Desktop Users,CN=Builtin," + baseDN,
				TargetName: "Remote Desktop Users", TargetType: "group",
				Right: analysis.RightAddMember, Severity: "High", CVSS: 8.0, CVSSVector: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
			},
		},
		DCSyncFindings: []analysis.DCSyncFinding{
			{
				PrincipalDN:   "CN=cersei,CN=Users," + baseDN,
				PrincipalName: "cersei", PrincipalType: "user",
				Severity: "Critical", CVSS: 10.0, CVSSVector: "AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H",
			},
		},
	}
}

func buildDelegation() *analysis.DelegationResult {
	return &analysis.DelegationResult{
		Domain: domain,
		Findings: []analysis.DelegationFinding{
			{
				SAMAccountName: "KINGSLANDING$",
				DN: "CN=KINGSLANDING,OU=Domain Controllers," + baseDN,
				ObjectType: "computer", DelegationType: analysis.DelegationUnconstrained,
				AllowedServices: []string{}, IsHighRisk: true,
				RiskReason: "Unconstrained delegation on DC — any user authenticating triggers TGT cache exposure.",
				Severity: "Critical", CVSS: 9.0, CVSSVector: "AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H",
			},
			{
				SAMAccountName: "svc_sql",
				DN: "CN=svc_sql,CN=Users," + baseDN,
				ObjectType: "user", DelegationType: analysis.DelegationConstrained,
				AllowedServices: []string{"MSSQLSvc/redkeep.sevenkingdoms.local:1433"},
				AllowedTo:       []string{"REDKEEP$"},
				IsHighRisk: false,
				RiskReason: "Constrained delegation permits service impersonation to REDKEEP SQL.",
				Severity: "Medium", CVSS: 6.5, CVSSVector: "AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
			},
		},
	}
}

func buildGPO() *analysis.GPOResult {
	return &analysis.GPOResult{
		Domain: domain,
		GPOFindings: []analysis.GPOFinding{
			{
				Name:     "Default Domain Policy",
				GUID:     "{31B2F340-016D-11D2-945F-00C04FB984F9}",
				LinkedTo: []string{baseDN},
			},
			{
				Name:        "Disable Windows Defender",
				GUID:        "{A3B2C1D0-0000-0000-0000-000000000001}",
				LinkedTo:    []string{"OU=Workstations," + baseDN},
				IsHighRisk:  true,
				RiskReasons: []string{"GPO disables Windows Defender via registry preference"},
				ACLFindings: []analysis.GPOACLFinding{
					{
						GPOName:       "Disable Windows Defender",
						PrincipalName: "Night's Watch", PrincipalSID: "S-1-5-21-3850359155-1265902998-2437639109-1200",
						Rights:    []string{"GpoApply"},
						GPOLinkedTo: []string{"OU=Workstations," + baseDN},
						Severity:  "High", CVSS: 7.8, CVSSVector: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
					},
				},
			},
		},
		GPOACLFindings: []analysis.GPOACLFinding{
			{
				GPOName:       "Disable Windows Defender",
				PrincipalName: "Night's Watch", PrincipalSID: "S-1-5-21-3850359155-1265902998-2437639109-1200",
				Rights:    []string{"GpoApply"},
				GPOLinkedTo: []string{"OU=Workstations," + baseDN},
				Severity:  "High", CVSS: 7.8,
			},
		},
		PasswordPolicy: &analysis.PasswordPolicy{
			MinLength: 7, Complexity: false, MaxAge: 42,
			LockoutThreshold: 0,
		},
	}
}

func buildHygiene(result *adldap.EnumerationResult) *analysis.HygieneResult {
	staleUsers := []adldap.LDAPUser{}
	staleComputers := []adldap.LDAPComputer{}
	for _, u := range result.Users {
		if u.SAMAccountName == "stannis" {
			staleUsers = append(staleUsers, u)
		}
	}
	for _, c := range result.Computers {
		if c.SAMAccountName == "DRAGONSTONE$" {
			staleComputers = append(staleComputers, c)
		}
	}

	return &analysis.HygieneResult{
		StaleUsers:     staleUsers,
		StaleComputers: staleComputers,
		PasswordInDesc: []analysis.PasswordInDescFinding{
			{SAMAccountName: "cersei", ObjectType: "user", Description: "Password: Cersei2024!"},
		},
		KrbtgtPwdAgeDays: 475,
		KrbtgtLastSet:    "2023-01-10 10:00:00",
		KrbtgtAtRisk:     true,
		NoLAPSCount:      3,
		TotalComputers:   5,
		NoLAPSComputers:  []adldap.LDAPComputer{result.Computers[0], result.Computers[2], result.Computers[3]},
	}
}

func buildPSO() *analysis.PSOResult {
	return &analysis.PSOResult{
		PSOs: []analysis.PSO{
			{
				Name: "ServiceAccounts-PSO", Precedence: 10,
				MinLength: 8, Complexity: true,
				MaxAgeDays: 180, LockoutThreshold: 0,
				AppliesTo: []string{"Service Accounts"},
				IsWeak: true, WeakReasons: []string{"MinLength < 12", "LockoutThreshold = 0"},
			},
		},
	}
}

func buildADCS() *analysis.ADCSResult {
	return &analysis.ADCSResult{
		Domain: domain,
		CAs: []analysis.CAInfo{
			{
				Name:   "SEVENKINGDOMS-CA",
				DN:     "CN=SEVENKINGDOMS-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + baseDN,
				Server: "kingslanding.sevenkingdoms.local",
			},
		},
		TemplateFindings: []analysis.CertTemplateFinding{
			{
				TemplateName: "UserTemplate", CAName: "SEVENKINGDOMS-CA",
				VulnTypes:       []analysis.ADCSVulnType{analysis.ESC1},
				EnrollableBy:    []string{"Domain Users"},
				AllowsSANInject: true, AuthEnabled: true,
				EKUs:     []string{"Client Authentication"},
				Severity: "Critical", CVSS: 9.8, CVSSVector: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
			},
			{
				TemplateName: "WebServer", CAName: "SEVENKINGDOMS-CA",
				VulnTypes:    []analysis.ADCSVulnType{analysis.ESC3},
				EnrollableBy: []string{"Night's Watch"},
				AuthEnabled:  true,
				EKUs:         []string{"Certificate Request Agent"},
				Severity:     "High", CVSS: 8.1, CVSSVector: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
			},
		},
		CAFindings: []analysis.CAFinding{
			{
				CAName:    "SEVENKINGDOMS-CA",
				CADN:      "CN=SEVENKINGDOMS-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration," + baseDN,
				VulnTypes: []analysis.ADCSVulnType{analysis.ESC8},
				WebEnroll: true, Details: "HTTP enrollment endpoint exposed without HTTPS",
				Severity: "High", CVSS: 8.0, CVSSVector: "AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
			},
		},
	}
}

func buildProtectedUsers() *analysis.ProtectedUsersResult {
	return &analysis.ProtectedUsersResult{
		ProtectedUsersExists: true,
		Members:              []string{"Administrator"},
		PrivilegedNotProtected: []analysis.PrivNotProtectedFinding{
			{SAMAccountName: "cersei", Groups: []string{"Domain Admins"}, Severity: "High"},
			{SAMAccountName: "stannis", Groups: []string{"Domain Admins"}, Severity: "High"},
		},
	}
}

func buildAdminSDHolder() *analysis.AdminSDHolderResult {
	return &analysis.AdminSDHolderResult{
		OrphanedAdminCount: []analysis.OrphanedAdminCountFinding{
			{SAMAccountName: "stannis", DN: "CN=stannis,CN=Users," + baseDN, Enabled: true},
		},
		CustomACEs: []analysis.AdminSDHolderACEFinding{
			{
				PrincipalName: "Night's Watch",
				PrincipalSID:  "S-1-5-21-3850359155-1265902998-2437639109-1200",
				Rights:        []string{"GenericAll"},
				Severity:      "Critical", CVSS: 9.9, CVSSVector: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
			},
		},
	}
}

func buildTrusts() *analysis.TrustResult {
	return &analysis.TrustResult{
		Domain: domain,
		Trusts: []analysis.Trust{
			{
				Name: "north.sevenkingdoms.local", FlatName: "NORTH",
				Direction:      analysis.TrustDirectionBidirectional,
				TrustType:      analysis.TrustTypeUplevel,
				SIDFilteringOn: false, IsForest: false, IsWithinForest: true,
				Risks:    []string{"SID filtering disabled — SID history abuse possible"},
				Severity: "High",
			},
			{
				Name: "essos.local", FlatName: "ESSOS",
				Direction:      analysis.TrustDirectionOutbound,
				TrustType:      analysis.TrustTypeUplevel,
				SIDFilteringOn: true, IsForest: false, IsWithinForest: false,
				Risks:    []string{"Outbound trust — essos.local users can authenticate here"},
				Severity: "Low",
			},
		},
		FSPs: []analysis.FSPFinding{
			{
				FSPDN:          "CN=S-1-5-21-1111111111-2222222222-3333333333-1104,CN=ForeignSecurityPrincipals," + baseDN,
				ExternalSID:    "S-1-5-21-1111111111-2222222222-3333333333-1104",
				MemberOfGroups: []string{"Backup Operators"},
				Severity:       "High", CVSS: 8.0, CVSSVector: "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
			},
		},
	}
}

func buildShadowCreds() *analysis.ShadowCredentialsResult {
	return &analysis.ShadowCredentialsResult{
		Domain: domain,
		Findings: []analysis.ShadowCredentialFinding{
			{
				PrincipalName: "Night's Watch", PrincipalType: "group",
				PrincipalDN: "CN=Night's Watch,CN=Users," + baseDN,
				TargetName: "KINGSLANDING$", TargetType: "computer",
				TargetDN: "CN=KINGSLANDING,OU=Domain Controllers," + baseDN,
				Right: "WriteProperty(msDS-KeyCredentialLink)", Severity: "Critical", CVSS: 9.0, CVSSVector: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
			},
		},
	}
}

func buildLDAPSecurity() *analysis.LDAPSecurityResult {
	return &analysis.LDAPSecurityResult{
		Domain:          domain,
		PlainLDAP:       true,
		SigningChecked:  true,
		SigningEnforced: false,
		AnonReadEnabled: false,
		Capabilities:    []string{"LDAP_CAP_ACTIVE_DIRECTORY_OID", "LDAP_CAP_ACTIVE_DIRECTORY_LDAP_INTEG_OID"},
		SASLMechanisms:  []string{"GSSAPI", "GSS-SPNEGO", "EXTERNAL", "DIGEST-MD5"},
		Findings: []analysis.LDAPSecurityFinding{
			{
				Title:    "LDAP signing not enforced",
				Detail:   "Domain controller does not require LDAP signing. Allows relay attacks (LDAP relay via NTLM coercion).",
				Severity: "High", CVSS: 8.1, CVSSVector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
			},
		},
	}
}

func buildAudit() *analysis.AuditResult {
	return &analysis.AuditResult{
		Domain:              domain,
		RecycleBinEnabled:   false,
		RecycleBinSupported: true,
		AuditingEnabled:     true,
		MachineAccountQuota: 10,
		AuditCategories: []analysis.AuditCategory{
			{Name: "Account Logon", Success: true, Failure: true},
			{Name: "Account Management", Success: true, Failure: false},
			{Name: "Logon/Logoff", Success: true, Failure: true},
			{Name: "Object Access", Success: false, Failure: false},
			{Name: "Privilege Use", Success: false, Failure: false},
		},
		Findings: []analysis.AuditFinding{
			{Title: "AD Recycle Bin disabled", Detail: "Deleted objects are unrecoverable. Enable via Enable-ADOptionalFeature.", Severity: "Medium"},
			{Title: "Machine Account Quota = 10", Detail: "Any domain user can create up to 10 machine accounts, enabling noPac and sAMAccountName spoofing attacks.", Severity: "High"},
		},
	}
}

func buildSMBSigning() *analysis.SMBSigningResult {
	return &analysis.SMBSigningResult{
		Host:      "kingslanding.sevenkingdoms.local",
		Reachable: true,
		Findings: []analysis.SMBSigningFinding{
			{Title: "SMB signing not required on CASTLEBLACK", Detail: "castleblack.sevenkingdoms.local (192.168.56.22) — signing not required, relay attack possible.", Severity: "High", CVSS: 8.1, CVSSVector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
			{Title: "SMB signing not required on DRAGONSTONE", Detail: "dragonstone.sevenkingdoms.local (192.168.56.25) — signing not required.", Severity: "High", CVSS: 8.1, CVSSVector: "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"},
		},
	}
}

func buildSYSVOL() *analysis.SYSVOLResult {
	return &analysis.SYSVOLResult{
		Domain:  "sevenkingdoms.local",
		Scanned: true,
		Findings: []analysis.SYSVOLFinding{
			{
				Path:     `sevenkingdoms.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml`,
				FileType: analysis.SYSVOLFileGPPXML,
				Size:     1024,
				Detail:   "GPP Preferences XML — may contain cPassword (AES-256 key is public, MS14-025).",
				Severity: "High",
			},
			{
				Path:     `sevenkingdoms.local\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\Machine\Preferences\Services\Services.xml`,
				FileType: analysis.SYSVOLFileGPPXML,
				Size:     512,
				Detail:   "GPP Preferences XML — may contain cPassword (AES-256 key is public, MS14-025).",
				Severity: "High",
			},
			{
				Path:     `sevenkingdoms.local\Policies\{A1B2C3D4-0000-0000-0000-000000000001}\Machine\deploy.ps1`,
				FileType: analysis.SYSVOLFileScript,
				Size:     2048,
				Detail:   "Script file outside standard Scripts\\ subdirectory — may contain hardcoded credentials.",
				Severity: "Medium",
			},
		},
	}
}

func buildLAPSACL() *analysis.LAPSACLResult {
	return &analysis.LAPSACLResult{
		Domain:       "sevenkingdoms.local",
		LAPSAttrGUID: "f0c8c3d5-3b6e-4f97-9b6d-0e8a4d8b4c2c",
		LAPSFound:    true,
		Findings: []analysis.LAPSACLFinding{
			{
				PrincipalName: "jorah.mormont",
				PrincipalType: "user",
				PrincipalDN:   "CN=jorah.mormont,CN=Users,DC=sevenkingdoms,DC=local",
				ComputerName:  "KINGSLANDING$",
				ComputerDN:    "CN=KINGSLANDING,OU=Domain Controllers,DC=sevenkingdoms,DC=local",
				Right:         "ReadProperty(ms-Mcs-AdmPwd)",
				CVSS:          7.7,
				CVSSVector:    "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
				Severity:      "High",
			},
			{
				PrincipalName: "Spys",
				PrincipalType: "group",
				PrincipalDN:   "CN=Spys,CN=Users,DC=sevenkingdoms,DC=local",
				ComputerName:  "CASTLEBLACK$",
				ComputerDN:    "CN=CASTLEBLACK,OU=Servers,DC=north,DC=sevenkingdoms,DC=local",
				Right:         "ReadProperty(ms-Mcs-AdmPwd)",
				CVSS:          7.7,
				CVSSVector:    "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
				Severity:      "High",
			},
			{
				PrincipalName: "samwell.tarly",
				PrincipalType: "user",
				PrincipalDN:   "CN=samwell.tarly,CN=Users,DC=north,DC=sevenkingdoms,DC=local",
				ComputerName:  "CASTLEBLACK$",
				ComputerDN:    "CN=CASTLEBLACK,OU=Servers,DC=north,DC=sevenkingdoms,DC=local",
				Right:         "GenericAll",
				CVSS:          7.7,
				CVSSVector:    "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
				Severity:      "High",
			},
		},
	}
}
