package analysis

import (
	"fmt"
	"io/fs"
	"net"
	"path"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/hirochachacha/go-smb2"

	adldap "github.com/YakinAnd/adpath/internal/ldap"
)

// SYSVOLFileType classifies why a file is considered suspicious.
type SYSVOLFileType string

const (
	SYSVOLFileGPPXML     SYSVOLFileType = "GPP Preferences XML"    // potential cPassword (MS14-025)
	SYSVOLFileExecutable SYSVOLFileType = "Executable"              // .exe/.dll/.msi in SYSVOL
	SYSVOLFileScript     SYSVOLFileType = "Script outside Scripts/" // .ps1/.bat/.cmd/.vbs not in Scripts\
	SYSVOLFileArchive    SYSVOLFileType = "Archive"                 // .zip/.7z/.tar
)

// gppPrefXMLFiles — file names in Preferences subfolders that are known cPassword carriers.
var gppPrefXMLFiles = map[string]bool{
	"groups.xml":         true,
	"services.xml":       true,
	"scheduledtasks.xml": true,
	"datasources.xml":    true,
	"printers.xml":       true,
	"drives.xml":         true,
}

type SYSVOLFinding struct {
	Path     string
	FileType SYSVOLFileType
	Size     int64
	ModTime  time.Time
	Detail   string
	Severity string
}

type SYSVOLResult struct {
	Domain   string
	Scanned  bool
	Error    string
	Findings []SYSVOLFinding
}

// ScanSYSVOL connects to \\<DC>\SYSVOL via SMB2/NTLM and walks the share,
// flagging non-standard files without reading their content.
func ScanSYSVOL(client *adldap.Client) *SYSVOLResult {
	r := &SYSVOLResult{Domain: client.GetDomain()}

	conn, err := net.DialTimeout("tcp", client.GetHost()+":445", 8*time.Second)
	if err != nil {
		r.Error = fmt.Sprintf("port 445 not reachable on %s: %v", client.GetHost(), err)
		return r
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     client.Username,
			Password: client.Password,
			Domain:   client.Domain,
		},
	}

	session, err := d.Dial(conn)
	if err != nil {
		r.Error = fmt.Sprintf("SMB auth failed: %v", err)
		return r
	}
	defer session.Logoff()

	share, err := session.Mount("SYSVOL")
	if err != nil {
		r.Error = fmt.Sprintf("cannot mount SYSVOL: %v", err)
		return r
	}
	defer share.Umount()

	r.Scanned = true

	// Walk under <domain>\ — SYSVOL root contains one folder per domain
	domainRoot := client.GetDomain()
	err = fs.WalkDir(share.DirFS("."), domainRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		checkSYSVOLFile(p, info, r)
		return nil
	})
	if err != nil {
		// Fallback: walk from root if domain subfolder walk failed
		_ = fs.WalkDir(share.DirFS("."), ".", func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			checkSYSVOLFile(p, info, r)
			return nil
		})
	}

	return r
}

// checkSYSVOLFile inspects a single file path from SYSVOL and appends a finding if suspicious.
func checkSYSVOLFile(p string, info fs.FileInfo, r *SYSVOLResult) {
	lower := strings.ToLower(p)
	ext := strings.ToLower(path.Ext(p))
	base := strings.ToLower(path.Base(p))

	// ── GPP Preferences XML (cPassword risk) ─────────────────
	// Path pattern: Policies\{GUID}\Machine\Preferences\<category>\*.xml
	//               Policies\{GUID}\User\Preferences\<category>\*.xml
	if ext == ".xml" && strings.Contains(lower, "preferences") {
		if gppPrefXMLFiles[base] {
			r.Findings = append(r.Findings, SYSVOLFinding{
				Path:     p,
				FileType: SYSVOLFileGPPXML,
				Size:     info.Size(),
				ModTime:  info.ModTime(),
				Detail:   "GPP Preferences XML — may contain cPassword (AES-256 key is public, MS14-025). Use: Get-GPPPassword or gpp-decrypt.",
				Severity: "High",
			})
		}
		return
	}

	// ── Executables ───────────────────────────────────────────
	switch ext {
	case ".exe", ".dll", ".msi", ".scr", ".cpl":
		r.Findings = append(r.Findings, SYSVOLFinding{
			Path:     p,
			FileType: SYSVOLFileExecutable,
			Size:     info.Size(),
			ModTime:  info.ModTime(),
			Detail:   "Executable file in SYSVOL — unexpected; investigate for malware persistence or unauthorized software deployment.",
			Severity: "High",
		})
		return
	}

	// ── Archives ──────────────────────────────────────────────
	switch ext {
	case ".zip", ".7z", ".tar", ".gz", ".rar":
		r.Findings = append(r.Findings, SYSVOLFinding{
			Path:     p,
			FileType: SYSVOLFileArchive,
			Size:     info.Size(),
			ModTime:  info.ModTime(),
			Detail:   "Archive in SYSVOL — may contain tools, scripts, or credentials.",
			Severity: "Medium",
		})
		return
	}

	// ── Scripts outside expected script directories ───────────
	// Expected: Policies\{GUID}\Machine\Scripts\{Startup|Shutdown}\
	//           Policies\{GUID}\User\Scripts\{Logon|Logoff}\
	//           scripts\ (NETLOGON-style)
	switch ext {
	case ".ps1", ".bat", ".cmd", ".vbs", ".js", ".wsf", ".hta":
		inScriptsDir := strings.Contains(lower, "\\scripts\\") ||
			strings.HasPrefix(lower, "scripts/") ||
			strings.HasPrefix(lower, "scripts\\")
		if !inScriptsDir {
			r.Findings = append(r.Findings, SYSVOLFinding{
				Path:     p,
				FileType: SYSVOLFileScript,
				Size:     info.Size(),
				ModTime:  info.ModTime(),
				Detail:   "Script file outside standard Scripts\\ subdirectory — may contain hardcoded credentials or unauthorized automation.",
				Severity: "Medium",
			})
		}
	}
}

// ============================================================
// Terminal output
// ============================================================

func PrintSYSVOLResult(r *SYSVOLResult) {
	if r == nil {
		return
	}

	color.Cyan("\n  SYSVOL AUDIT")

	if r.Error != "" {
		color.White("  %-28s %s", "status", "skipped — "+r.Error)
		return
	}
	if !r.Scanned {
		color.White("  %-28s not reachable", "status")
		return
	}

	if len(r.Findings) == 0 {
		color.White("  %-28s no non-standard files found", "status")
		return
	}

	color.Red("  %-28s %d non-standard file(s)", "findings", len(r.Findings))
	color.White("  %-50s %-22s %s", "path", "type", "size")
	color.White("  " + strings.Repeat("-", 82))

	for _, f := range r.Findings {
		displayPath := f.Path
		if len(displayPath) > 50 {
			displayPath = "…" + displayPath[len(displayPath)-49:]
		}
		line := fmt.Sprintf("  %-50s %-22s %d B", displayPath, string(f.FileType), f.Size)
		switch f.Severity {
		case "High":
			color.Red(line)
		case "Medium":
			color.Yellow(line)
		default:
			color.White(line)
		}
	}

	color.Cyan("\n  NEXT STEPS")
	color.White("  Check GPP Preferences XML for cPassword:")
	color.White("    Get-GPPPassword  (PowerSploit)")
	color.White("    python3 gpp-decrypt.py <cpassword>")
	color.White("  Check scripts for hardcoded credentials:")
	color.White("    findstr /S /I \"password pass pwd\" \\\\%s\\SYSVOL\\*.ps1 *.bat *.cmd", r.Domain)
}

// SYSVOLSummaryLine prints a one-liner for the enum command output.
func SYSVOLSummaryLine(r *SYSVOLResult) {
	if r == nil || !r.Scanned || len(r.Findings) == 0 {
		return
	}
	color.Yellow("  %-28s %d non-standard file(s) in SYSVOL", "sysvol", len(r.Findings))
}
