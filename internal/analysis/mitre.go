package analysis

import "fmt"

// MitreTechnique represents a single ATT&CK technique reference.
type MitreTechnique struct {
	ID   string // e.g. "T1558.003"
	Name string // e.g. "Kerberoasting"
}

// URL returns the attack.mitre.org link for this technique.
func (t MitreTechnique) URL() string {
	return fmt.Sprintf("https://attack.mitre.org/techniques/%s/", t.ID[:5])
}

// MitreKey is a canonical identifier for a finding category.
type MitreKey string

const (
	MitreKerberoasting    MitreKey = "kerberoasting"
	MitreASREP            MitreKey = "asrep"
	MitreDCSync           MitreKey = "dcsync"
	MitreACLAbuse         MitreKey = "acl_abuse"
	MitreForceChangePwd   MitreKey = "force_change_password"
	MitreAddMember        MitreKey = "add_member"
	MitreUnconstrainedDel MitreKey = "unconstrained_delegation"
	MitreConstrainedDel   MitreKey = "constrained_delegation"
	MitreRBCD             MitreKey = "rbcd"
	MitreADCS             MitreKey = "adcs"
	MitreGPOAbuse         MitreKey = "gpo_abuse"
	MitreShadowCreds      MitreKey = "shadow_credentials"
	MitreLDAPRelay        MitreKey = "ldap_relay"
	MitreAnonLDAP         MitreKey = "anon_ldap"
	MitreTrustAbuse       MitreKey = "trust_abuse"
	MitreAuditDefense     MitreKey = "audit_defense"
	MitreMachineAccountQ  MitreKey = "machine_account_quota"
)

// mitreMappings maps each key to one or more ATT&CK techniques.
var mitreMappings = map[MitreKey][]MitreTechnique{
	MitreKerberoasting: {
		{"T1558.003", "Kerberoasting"},
	},
	MitreASREP: {
		{"T1558.004", "AS-REP Roasting"},
	},
	MitreDCSync: {
		{"T1003.006", "DCSync"},
	},
	MitreACLAbuse: {
		{"T1222", "Permission Modification"},
		{"T1484", "Domain Policy Modification"},
	},
	MitreForceChangePwd: {
		{"T1098", "Account Manipulation"},
	},
	MitreAddMember: {
		{"T1098", "Account Manipulation"},
	},
	MitreUnconstrainedDel: {
		{"T1558", "Steal/Forge Kerberos Tickets"},
		{"T1550.003", "Pass the Ticket"},
	},
	MitreConstrainedDel: {
		{"T1550.003", "Pass the Ticket"},
	},
	MitreRBCD: {
		{"T1134.001", "Token Impersonation"},
		{"T1550.003", "Pass the Ticket"},
	},
	MitreADCS: {
		{"T1649", "Steal/Forge Auth Certificates"},
	},
	MitreGPOAbuse: {
		{"T1484.001", "GPO Modification"},
	},
	MitreShadowCreds: {
		{"T1556", "Modify Authentication Process"},
		{"T1649", "Steal/Forge Auth Certificates"},
	},
	MitreLDAPRelay: {
		{"T1557", "Adversary-in-the-Middle"},
	},
	MitreAnonLDAP: {
		{"T1087.002", "Account Discovery: Domain Account"},
	},
	MitreTrustAbuse: {
		{"T1482", "Domain Trust Discovery"},
		{"T1199", "Trusted Relationship"},
	},
	MitreAuditDefense: {
		{"T1562.002", "Disable Windows Event Logging"},
	},
	MitreMachineAccountQ: {
		{"T1136.002", "Create Account: Domain Account"},
	},
}

// LookupTechniques returns ATT&CK techniques for a given canonical key.
// Returns nil if the key is not mapped.
func LookupTechniques(key MitreKey) []MitreTechnique {
	return mitreMappings[key]
}
