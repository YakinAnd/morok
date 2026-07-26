package report

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strings"

	"github.com/YakinAnd/morok/internal/analysis"
)

// Snapshot is the schema for the embedded `morok-data` JSON block in every
// HTML report. It has two consumers: the History tab's JS-side diffing
// (interested only in per-category counts — see _HIST_CATEGORIES in
// html.go, which only ever calls .length on findings[category]) and the
// `morok mcp` reader (internal/mcpserver), interested in the full
// structured fields. Bumping V does not break old (v1) reports loaded as
// History-tab baselines — the JS loader never inspects individual entries.
type Snapshot struct {
	V           int                          `json:"v"`
	GeneratedAt string                       `json:"generated_at"`
	Domain      string                       `json:"domain"`
	Version     string                       `json:"version"`
	Score       SnapshotScore                `json:"score"`
	Counts      SnapshotCounts               `json:"counts"`
	Findings    map[string][]SnapshotFinding `json:"findings"`
	AttackPaths []SnapshotAttackPath         `json:"attack_paths,omitempty"`
}

type SnapshotScore struct {
	Grade string `json:"grade"`
	Value int    `json:"value"`
}

type SnapshotCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
}

// SnapshotFinding is one structured finding entry. Severity/CVSS/Detail/
// Remediation are populated only where the source finding struct actually
// carries that data (see field comments below in buildSnapshot) — omitted
// rather than fabricated where it doesn't exist yet.
type SnapshotFinding struct {
	Summary     string  `json:"summary"`
	Severity    string  `json:"severity,omitempty"`
	CVSS        float64 `json:"cvss,omitempty"`
	Detail      string  `json:"detail,omitempty"`
	Remediation string  `json:"remediation,omitempty"`
}

type SnapshotAttackPath struct {
	Summary     string         `json:"summary"`
	TargetGroup string         `json:"target_group"`
	Depth       int            `json:"depth"`
	Edges       []SnapshotEdge `json:"edges"`
}

type SnapshotEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Type string `json:"type"`
}

// buildSnapshot serializes a compact-but-structured fingerprint of all
// findings into JSON, embedded in the HTML report so that (a) other reports
// can load this file as a History-tab baseline, and (b) `morok mcp` can
// read a single report's findings without parsing HTML.
func buildSnapshot(d *ReportData) template.JS {
	snap := Snapshot{
		V:           2,
		GeneratedAt: d.GeneratedAt,
		Domain:      d.Domain,
		Version:     d.Version,
		Score:       SnapshotScore{Grade: d.RiskScore.Grade, Value: d.RiskScore.Total},
		Counts:      SnapshotCounts{Critical: d.TotalCritical, High: d.TotalHigh, Medium: d.TotalMedium},
		Findings:    make(map[string][]SnapshotFinding),
	}
	f := snap.Findings

	if d.KerberosResult != nil {
		for _, acc := range d.KerberosResult.KerberoastableAccounts {
			f["kerberoastable"] = append(f["kerberoastable"], SnapshotFinding{
				Summary: acc.SAMAccountName, Severity: acc.Severity, CVSS: acc.CVSS,
			})
		}
		for _, acc := range d.KerberosResult.ASREPAccounts {
			f["asrep"] = append(f["asrep"], SnapshotFinding{
				Summary: acc.SAMAccountName, Severity: acc.Severity, CVSS: acc.CVSS,
			})
		}
	}

	if d.ACLResult != nil {
		for _, af := range d.ACLResult.Findings {
			f["acl"] = append(f["acl"], SnapshotFinding{
				Summary:  af.PrincipalName + "|" + string(af.Right) + "|" + af.TargetName,
				Severity: af.Severity, CVSS: af.CVSS,
			})
		}
	}

	if d.DelegationResult != nil {
		for _, df := range d.DelegationResult.Findings {
			switch df.DelegationType {
			case analysis.DelegationUnconstrained:
				f["unconstrained_deleg"] = append(f["unconstrained_deleg"], SnapshotFinding{
					Summary: df.SAMAccountName, Severity: df.Severity, CVSS: df.CVSS,
				})
			case analysis.DelegationConstrained:
				f["constrained_deleg"] = append(f["constrained_deleg"], SnapshotFinding{
					Summary:  df.SAMAccountName + "|" + strings.Join(df.AllowedServices, ","),
					Severity: df.Severity, CVSS: df.CVSS,
				})
			case analysis.DelegationRBCD:
				f["rbcd"] = append(f["rbcd"], SnapshotFinding{
					Summary:  df.SAMAccountName + "|" + strings.Join(df.TrusteeNames, ","),
					Severity: df.Severity, CVSS: df.CVSS,
				})
			}
		}
	}

	for _, path := range d.AttackPaths {
		if len(path.Nodes) == 0 {
			continue
		}
		summary := fmt.Sprintf("%s→%s(%dhops)", path.Nodes[0].SAMAccountName, path.TargetGroup, path.Depth)
		edges := make([]SnapshotEdge, len(path.Edges))
		for i, e := range path.Edges {
			edges[i] = SnapshotEdge{From: e.From, To: e.To, Type: string(e.Type)}
		}
		snap.AttackPaths = append(snap.AttackPaths, SnapshotAttackPath{
			Summary: summary, TargetGroup: path.TargetGroup, Depth: path.Depth, Edges: edges,
		})
		f["attack_paths"] = append(f["attack_paths"], SnapshotFinding{Summary: summary})
	}

	if d.ADCSResult != nil {
		for _, tf := range d.ADCSResult.TemplateFindings {
			vulnTypes := make([]string, len(tf.VulnTypes))
			for i, v := range tf.VulnTypes {
				vulnTypes[i] = string(v)
			}
			f["adcs_templates"] = append(f["adcs_templates"], SnapshotFinding{
				Summary:  tf.TemplateName + "|" + strings.Join(vulnTypes, "/"),
				Severity: tf.Severity, CVSS: tf.CVSS,
			})
		}
	}

	if d.ShadowCredentialsResult != nil {
		for _, sf := range d.ShadowCredentialsResult.Findings {
			f["shadow_creds"] = append(f["shadow_creds"], SnapshotFinding{
				Summary:  sf.PrincipalName + "|" + sf.TargetName,
				Severity: sf.Severity, CVSS: sf.CVSS,
			})
		}
	}

	if d.GPOResult != nil {
		for _, af := range d.GPOResult.GPOACLFindings {
			f["gpo_write"] = append(f["gpo_write"], SnapshotFinding{
				Summary:  af.PrincipalName + "|" + af.GPOName,
				Severity: af.Severity, CVSS: af.CVSS,
			})
		}
		for _, gpo := range d.GPOResult.GPOFindings {
			if gpo.HasCPassword {
				f["gpp_passwords"] = append(f["gpp_passwords"], SnapshotFinding{Summary: gpo.Name})
			}
		}
	}

	if d.VulnResult != nil {
		for _, vf := range d.VulnResult.Findings {
			status := "candidate"
			switch vf.Status {
			case analysis.VulnConfirmed:
				status = "confirmed"
			case analysis.VulnUnreachable:
				status = "unreachable"
			}
			f["vulns"] = append(f["vulns"], SnapshotFinding{
				Summary:     vf.CVE + "|" + vf.Name + "|" + status + "|" + vf.Host,
				Detail:      vf.Detail,
				Remediation: vf.Remediation,
			})
		}
	}

	b, _ := json.Marshal(snap)
	return template.JS(b)
}
