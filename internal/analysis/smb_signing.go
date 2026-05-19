package analysis

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"

	"github.com/fatih/color"
	"golang.org/x/net/proxy"
)

const (
	smb2SigningEnabled  = 0x0001
	smb2SigningRequired = 0x0002
)

type SMBSigningResult struct {
	Host            string
	ProxyURL        string
	Reachable       bool
	SigningEnabled  bool
	SigningRequired bool
	Dialect         uint16
	Findings        []SMBSigningFinding
}

type SMBSigningFinding struct {
	Title    string
	Detail   string
	Severity string
	CVSS       float64
	CVSSVector string
}

// CheckSMBSigning sends an SMB2 Negotiate to host:445 and reads the SecurityMode field.
// No credentials are required — the check is performed during protocol negotiation.
// proxyURL may be empty or a socks5:// URL to route the connection through a SOCKS5 proxy.
func CheckSMBSigning(host, proxyURL string) *SMBSigningResult {
	r := &SMBSigningResult{Host: host, ProxyURL: proxyURL}

	dialer, err := smbBuildDialer(proxyURL)
	if err != nil {
		r.Reachable = false
		return r
	}

	conn, err := dialer.Dial("tcp", host+":445")
	if err != nil {
		r.Reachable = false
		return r
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	r.Reachable = true

	if _, err := conn.Write(buildSMB2Negotiate()); err != nil {
		return r
	}

	// NetBIOS Session Service header: 1 byte type + 3 bytes length
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return r
	}
	length := uint32(hdr[1])<<16 | uint32(hdr[2])<<8 | uint32(hdr[3])
	if length < 68 || length > 65536 {
		return r
	}

	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return r
	}

	// Validate SMB2 signature: bytes 0-3 must be 0xFE 'S' 'M' 'B'
	if len(body) < 68 || body[0] != 0xFE || body[1] != 'S' || body[2] != 'M' || body[3] != 'B' {
		return r
	}

	// SMB2 Header is 64 bytes. Negotiate Response starts at offset 64.
	// Negotiate Response layout:
	//   [0-1]  StructureSize (65)
	//   [2-3]  SecurityMode  ← signing flags
	//   [4-5]  DialectRevision
	resp := body[64:]
	if len(resp) < 6 {
		return r
	}

	secMode := binary.LittleEndian.Uint16(resp[2:4])
	dialect := binary.LittleEndian.Uint16(resp[4:6])

	r.SigningEnabled = secMode&smb2SigningEnabled != 0
	r.SigningRequired = secMode&smb2SigningRequired != 0
	r.Dialect = dialect

	if !r.SigningRequired {
		detail := fmt.Sprintf(
			"SMB signing is not required on %s (SecurityMode=0x%04x). An attacker with network position can perform NTLM relay attacks: capture authentication via PetitPotam/PrinterBug and relay to SMB (e.g. impacket ntlmrelayx.py -t smb://%s). "+
				"Mitigate: GPO → Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → \"Microsoft network server: Digitally sign communications (always)\" = Enabled.",
			host, secMode, host,
		)
		var smbVector string
		if !r.SigningEnabled {
			// signing disabled entirely — easier relay: AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H
			smbVector = "AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H"
		} else {
			// signing enabled but not required — relay still possible: AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N
			smbVector = "AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"
		}
		smbScore := CVSSScore(smbVector)
		r.Findings = append(r.Findings, SMBSigningFinding{
			Title:      "SMB signing not required",
			Detail:     detail,
			CVSS:       smbScore,
			CVSSVector: smbVector,
			Severity:   CVSSSeverity(smbScore),
		})
	}

	return r
}

// PrintSMBSigningResult prints the SMB signing check result to the terminal.
func PrintSMBSigningResult(r *SMBSigningResult) {
	if r == nil {
		return
	}

	color.Cyan("\n  SMB SIGNING")
	color.White("  %-28s %s", "host", r.Host)
	if r.ProxyURL != "" {
		color.White("  %-28s %s", "proxy", r.ProxyURL)
	}

	if !r.Reachable {
		color.White("  %-28s port 445 not reachable", "status")
		return
	}

	dialectStr := dialectName(r.Dialect)
	color.White("  %-28s %s", "dialect", dialectStr)

	signingStr := "not enabled"
	if r.SigningEnabled {
		signingStr = "enabled"
	}
	if r.SigningRequired {
		signingStr = "required ✓"
	}
	color.White("  %-28s %s", "signing", signingStr)

	if len(r.Findings) == 0 {
		color.Green("  %-28s no issues", "smb signing")
		return
	}

	fmt.Println()
	for _, f := range r.Findings {
		line := fmt.Sprintf("  [%s] %s", f.Severity, f.Title)
		switch f.Severity {
		case "High":
			color.Red(line)
		case "Medium":
			color.Yellow(line)
		default:
			color.White(line)
		}
		color.White("         %s", f.Detail)
	}
}

// SMBSigningSummaryLine prints a one-line summary for the enum output.
func SMBSigningSummaryLine(r *SMBSigningResult) {
	if r == nil || !r.Reachable || r.SigningRequired {
		return
	}
	color.Red("  %-28s NOT required — NTLM relay possible (port 445)", "smb signing")
}

// smbBuildDialer returns a plain TCP dialer or a SOCKS5 proxy dialer.
func smbBuildDialer(proxyURL string) (proxy.Dialer, error) {
	if proxyURL == "" {
		return &smbTimeoutDialer{timeout: 5 * time.Second}, nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL %q: %w", proxyURL, err)
	}
	if u.Scheme != "socks5" {
		return nil, fmt.Errorf("unsupported proxy scheme %q (only socks5 supported)", u.Scheme)
	}
	var auth *proxy.Auth
	if u.User != nil {
		pass, _ := u.User.Password()
		auth = &proxy.Auth{User: u.User.Username(), Password: pass}
	}
	return proxy.SOCKS5("tcp", u.Host, auth, proxy.Direct)
}

type smbTimeoutDialer struct{ timeout time.Duration }

func (d *smbTimeoutDialer) Dial(network, addr string) (net.Conn, error) {
	return net.DialTimeout(network, addr, d.timeout)
}

// buildSMB2Negotiate constructs a minimal SMB2 Negotiate request packet.
func buildSMB2Negotiate() []byte {
	// Dialects: SMB 2.0.2, 2.1, 3.0
	dialects := []uint16{0x0202, 0x0210, 0x0300}
	dialectCount := len(dialects)

	// Negotiate body size: 36 (fixed) + 2*dialectCount
	bodySize := 36 + dialectCount*2

	// SMB2 Header (64) + body
	smbLen := 64 + bodySize

	// NetBIOS header (4) + SMB payload
	pkt := make([]byte, 4+smbLen)

	// NetBIOS Session Service: type=0x00, 3-byte big-endian length
	pkt[0] = 0x00
	pkt[1] = byte(smbLen >> 16)
	pkt[2] = byte(smbLen >> 8)
	pkt[3] = byte(smbLen)

	// SMB2 Header at offset 4
	h := pkt[4:]
	copy(h[0:4], []byte{0xFE, 'S', 'M', 'B'}) // ProtocolId
	binary.LittleEndian.PutUint16(h[4:6], 64)   // StructureSize
	// CreditCharge, Status, Command=0, CreditRequest=1, rest=0
	binary.LittleEndian.PutUint16(h[14:16], 1) // CreditRequest

	// Negotiate Request body at offset 68
	b := pkt[68:]
	binary.LittleEndian.PutUint16(b[0:2], 36)                    // StructureSize
	binary.LittleEndian.PutUint16(b[2:4], uint16(dialectCount))  // DialectCount
	// SecurityMode=0, Reserved=0, Capabilities=0, ClientGuid=0, ClientStartTime=0
	for i, d := range dialects {
		binary.LittleEndian.PutUint16(b[36+i*2:], d)
	}

	return pkt
}

func dialectName(d uint16) string {
	switch d {
	case 0x0202:
		return "SMB 2.0.2"
	case 0x0210:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	default:
		return fmt.Sprintf("0x%04x", d)
	}
}
