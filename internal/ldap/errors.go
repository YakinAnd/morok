package ldap

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

var reData = regexp.MustCompile(`\bdata\s+([0-9a-fA-F]+)\b`)

// friendlyLDAPError converts a raw go-ldap error into a human-readable message.
// It recognises the most common Windows Active Directory LDAP error patterns:
//   - ResultCode 49 (invalid credentials) — decodes the Windows sub-error from the "data" hex field
//   - ResultCode 1  (operations error)    — detects null-session restriction
//   - ResultCode 50 (insufficient rights) — access denied message
//   - ResultCode 52 (unavailable)         — DC not ready
//   - Network errors                      — connection refused / timeout
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

		case goldap.LDAPResultInsufficientAccessRights: // 50
			return fmt.Errorf("insufficient LDAP read permissions — bind with a valid domain account (-u/-p)")

		case goldap.LDAPResultUnavailable: // 52
			return fmt.Errorf("DC is temporarily unavailable — try again or check DC health")

		case goldap.LDAPResultUnwillingToPerform: // 53
			return fmt.Errorf("DC refused the operation — check DC configuration or try LDAPS (port 636)")

		case goldap.LDAPResultBusy: // 51
			return fmt.Errorf("DC is busy — retry in a few seconds")
		}
	}

	// Network-level errors (connection refused, timeout, etc.)
	raw := err.Error()
	switch {
	case strings.Contains(raw, "connection refused"):
		return fmt.Errorf("DC unreachable — connection refused (check DC IP and firewall on port 389/636)")
	case strings.Contains(raw, "i/o timeout") || strings.Contains(raw, "timeout"):
		return fmt.Errorf("DC unreachable — connection timed out (check network path, firewall, or proxy)")
	case strings.Contains(raw, "no such host"):
		return fmt.Errorf("DC hostname not resolved — check --dc value or DNS")
	case strings.Contains(raw, "connection reset"):
		return fmt.Errorf("DC reset the connection — try LDAPS (--dc with port 636) or check proxy")
	case strings.Contains(raw, "TLS handshake"):
		return fmt.Errorf("LDAPS TLS handshake failed — DC certificate issue (self-signed is accepted by morok)")
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
		}
	}
	// no data field or unknown sub-code — generic message
	return "authentication failed — wrong username or password"
}

// windowsLogonError maps Windows logon error codes to user-friendly strings.
// These appear in the "data" hex field of LDAP Result Code 49 responses from AD.
func windowsLogonError(code int64) string {
	switch code {
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
	case 0x701: // 1793 — ACCOUNT_EXPIRED
		return "authentication failed — account has expired"
	case 0x773: // 1907 — PASSWORD_MUST_CHANGE
		return "authentication failed — user must change password before first logon"
	case 0x775: // 1909 — ACCOUNT_LOCKED_OUT
		return "authentication failed — account is locked out (too many failed attempts)"
	case 0x568: // 1384 — SMARTCARD_LOGON_REQUIRED
		return "authentication failed — account requires smartcard logon"
	case 0x0:
		return "authentication failed — wrong username or password"
	}
	return ""
}
