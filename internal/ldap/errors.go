package ldap

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

// reData matches the hex "data XXXX" sub-code in Windows AD LDAP error strings.
// (?i) for Samba 4 compat (ADP-146).
var reData = regexp.MustCompile(`(?i)\bdata\s+([0-9a-fA-F]+)\b`)

// friendlyLDAPError converts a raw go-ldap error into a human-readable message.
// It recognises the most common Windows Active Directory LDAP error patterns.
func friendlyLDAPError(err error) error {
	if err == nil {
		return nil
	}

	var ldapErr *goldap.Error
	if errors.As(err, &ldapErr) {
		switch ldapErr.ResultCode {
		case goldap.LDAPResultInvalidCredentials: // 49
			return fmt.Errorf("%s", decodeCode49(ldapErr.Err.Error()))

		case goldap.LDAPResultOperationsError: // 1
			msg := ldapErr.Err.Error()
			if strings.Contains(msg, "successful bind must be completed") ||
				strings.Contains(msg, "000004DC") {
				return fmt.Errorf("null sessions are disabled on this DC — provide credentials (-u/-p, -H, or --ccache)")
			}
			return fmt.Errorf("LDAP operations error: %s", msg)

		case 8: // LDAPResultStrongAuthRequired — ADP-139
			return fmt.Errorf("DC requires LDAP signing — connect via LDAPS (port 636) or use Kerberos (--ccache)")

		case 13: // LDAPResultConfidentialityRequired — ADP-139
			return fmt.Errorf("DC requires channel binding / confidentiality — connect via LDAPS (port 636)")

		case goldap.LDAPResultInsufficientAccessRights: // 50
			return fmt.Errorf("insufficient LDAP read permissions — bind with a valid domain account (-u/-p)")

		case goldap.LDAPResultUnavailable: // 52
			return fmt.Errorf("DC is temporarily unavailable — try again or check DC health")

		case goldap.LDAPResultUnwillingToPerform: // 53
			return fmt.Errorf("DC refused the operation — check DC configuration or try LDAPS (port 636)")

		case goldap.LDAPResultBusy: // 51
			return fmt.Errorf("DC is busy — retry in a few seconds")

		case 4: // LDAPResultSizeLimitExceeded — ADP-147
			return fmt.Errorf("LDAP result size limit exceeded — DC page size may be restricted; try --scope to narrow the search")

		case 12: // LDAPResultUnavailableCriticalExtension — ADP-147
			return fmt.Errorf("DC rejected a required LDAP control (code 12) — this DC may be Samba/non-Windows; ACL checks may be limited")

		case 32: // LDAPResultNoSuchObject — ADP-147
			return fmt.Errorf("base DN not found — check domain spelling or use --scope with the correct OU path")
		}
	}

	// Network-level errors — use lower-cased raw for case-insensitive matching (ADP-143, ADP-144).
	raw := err.Error()
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "actively refused") || // Windows: "connectex: No connection could be made..."
		strings.Contains(lower, "connectex:"):
		return fmt.Errorf("DC unreachable — connection refused (check DC IP and firewall on port 389/636)")

	case strings.Contains(lower, "i/o timeout") ||
		strings.Contains(lower, "timed out") ||
		strings.Contains(lower, "deadline exceeded"):
		return fmt.Errorf("DC unreachable — connection timed out (check network path, firewall, or proxy)")

	case strings.Contains(lower, "no such host") ||
		strings.Contains(lower, "no such host is known"): // Windows DNS phrasing
		return fmt.Errorf("DC hostname not resolved — check --dc value or DNS")

	case strings.Contains(lower, "connection reset"):
		return fmt.Errorf("DC reset the connection — try LDAPS (port 636) or check proxy")

	case strings.Contains(lower, "tls:") || strings.Contains(lower, "tls handshake"): // ADP-143
		return fmt.Errorf("LDAPS TLS handshake failed — check that port 636 is reachable and the DC has a valid certificate")
	}

	return err
}

// decodeCode49 parses the Windows sub-error from a ResultCode 49 error string.
// The "data XXXX" field is a hex Windows error code.
func decodeCode49(msg string) string {
	m := reData.FindStringSubmatch(msg)
	if m != nil {
		code, err := strconv.ParseInt(m[1], 16, 64)
		if err == nil {
			if reason := windowsLogonError(code); reason != "" {
				return reason
			}
			// Unknown sub-code — report it instead of lying "wrong password" (ADP-142)
			return fmt.Sprintf("authentication failed — Windows sub-error 0x%x (credentials may be correct but account/policy blocks logon)", code)
		}
	}
	// No data field at all — generic message
	return "authentication failed — wrong username or password"
}

// friendlyKerberosError converts raw gokrb5 error strings into readable messages.
// gokrb5 errors are plain fmt.Errorf — not *goldap.Error — so friendlyLDAPError
// cannot handle them. Applied in BindKerberos and kerberos_auth.go.
func friendlyKerberosError(err error) error {
	if err == nil {
		return nil
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "skew") || strings.Contains(lower, "clock"):
		return fmt.Errorf("Kerberos clock skew too large — sync system clock with DC (max ±5 min): %w", err)
	case strings.Contains(lower, "s_principal_unknown") || strings.Contains(lower, "principal unknown") ||
		strings.Contains(lower, "server not found"):
		return fmt.Errorf("Kerberos SPN not found — try using DC hostname instead of IP (--dc dc01.corp.local): %w", err)
	case strings.Contains(lower, "tkt_expired") || strings.Contains(lower, "ticket") && strings.Contains(lower, "expir"):
		return fmt.Errorf("Kerberos ticket has expired — renew ccache (kinit or get a fresh ticket): %w", err)
	case strings.Contains(lower, "etype_nosupp") || strings.Contains(lower, "etype") && strings.Contains(lower, "supp"):
		return fmt.Errorf("Kerberos encryption type not supported — RC4 ccache against AES-only DC or vice versa: %w", err)
	case strings.Contains(lower, "no such file") || strings.Contains(lower, "load ccache"):
		return fmt.Errorf("ccache file not found or unreadable — check --ccache path: %w", err)
	case strings.Contains(lower, "credentials"):
		return fmt.Errorf("Kerberos credentials invalid or not found in ccache: %w", err)
	}
	return err
}

// windowsLogonError maps Windows logon error codes to user-friendly strings.
// These appear in the "data" hex field of LDAP Result Code 49 responses from AD.
func windowsLogonError(code int64) string {
	switch code {
	case 0x0:
		return "authentication failed — wrong username or password"
	case 0x52d: // 1325 — PASSWORD_RESTRICTION (ADP-142)
		return "authentication failed — password does not meet complexity/history requirements"
	case 0x52e: // 1326 — LOGON_FAILURE
		return "authentication failed — wrong password"
	case 0x52f: // 1327 — ACCOUNT_RESTRICTION
		return "authentication failed — account restriction (check logon hours or workstation restrictions)"
	case 0x530: // 1328 — INVALID_LOGON_HOURS
		return "authentication failed — account not permitted to log on at this time"
	case 0x531: // 1329 — INVALID_WORKSTATION
		return "authentication failed — account not permitted to log on from this workstation"
	case 0x532: // 1330 — PASSWORD_EXPIRED
		return "authentication failed — password has expired (change it before enumerating)"
	case 0x533: // 1331 — ACCOUNT_DISABLED
		return "authentication failed — account is disabled"
	case 0x568: // 1384 — SMARTCARD_LOGON_REQUIRED
		return "authentication failed — account requires smartcard logon"
	case 0x569: // 1385 — LOGON_TYPE_NOT_GRANTED (ADP-142)
		return "authentication failed — account not allowed to log on via network (check 'Access this computer from the network' GPO)"
	case 0x701: // 1793 — ACCOUNT_EXPIRED
		return "authentication failed — account has expired"
	case 0x773: // 1907 — PASSWORD_MUST_CHANGE
		return "authentication failed — user must change password before first logon"
	case 0x775: // 1909 — ACCOUNT_LOCKED_OUT
		return "authentication failed — account is locked out (too many failed attempts)"
	case 0x6fa: // 1786 — NO_TRUST_LSA_SECRET (ADP-142)
		return "authentication failed — no trust LSA secret found (cross-domain trust issue)"
	case 0x6fb: // 1787 — TRUSTED_DOMAIN_FAILURE (ADP-142)
		return "authentication failed — trusted domain operation failed (check forest trust configuration)"
	case 0x6fd: // 1789 — TRUSTED_RELATIONSHIP_FAILURE
		return "authentication failed — secure channel to trusted domain failed"
	}
	return ""
}
