package analysis

import (
	"math"
	"strings"
)

// CVSS 3.1 metric weights per specification
var (
	cvssAV = map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	cvssAC = map[string]float64{"L": 0.77, "H": 0.44}
	cvssPR = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27} // Scope=Unchanged
	cvssPRC = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50} // Scope=Changed
	cvssUI = map[string]float64{"N": 0.85, "R": 0.62}
	cvssCIA = map[string]float64{"N": 0.00, "L": 0.22, "H": 0.56}
)

// CVSSScore computes a CVSS 3.1 base score from a vector string.
// Example: "AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
func CVSSScore(vector string) float64 {
	m := make(map[string]string, 8)
	for _, seg := range strings.Split(vector, "/") {
		if k, v, ok := strings.Cut(seg, ":"); ok {
			m[k] = v
		}
	}

	av := cvssAV[m["AV"]]
	ac := cvssAC[m["AC"]]
	scope := m["S"]
	var pr float64
	if scope == "C" {
		pr = cvssPRC[m["PR"]]
	} else {
		pr = cvssPR[m["PR"]]
	}
	ui := cvssUI[m["UI"]]
	c := cvssCIA[m["C"]]
	i := cvssCIA[m["I"]]
	a := cvssCIA[m["A"]]

	iscBase := 1.0 - (1.0-c)*(1.0-i)*(1.0-a)

	var isc float64
	if scope == "U" {
		isc = 6.42 * iscBase
	} else {
		isc = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	}

	if isc <= 0 {
		return 0
	}

	exploitability := 8.22 * av * ac * pr * ui

	var base float64
	if scope == "U" {
		base = math.Min(isc+exploitability, 10)
	} else {
		base = math.Min(1.08*(isc+exploitability), 10)
	}

	return cvssRoundUp(base)
}

// cvssRoundUp rounds to 1 decimal place upward (CVSS 3.1 spec requirement)
func cvssRoundUp(val float64) float64 {
	return math.Ceil(val*10) / 10
}

// CVSSSeverity returns the severity label for a CVSS 3.1 base score
func CVSSSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score > 0:
		return "Low"
	default:
		return "Informational"
	}
}

// CVSSForKerberostable returns the CVSS 3.1 base score for a Kerberoastable account.
// adminCount=true means the account has elevated privileges (DA/service admin),
// which changes Scope to Changed and raises the score significantly.
func CVSSForKerberostable(adminCount bool) float64 {
	if adminCount {
		// Privileged SPN: offline crack → domain admin: AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H
		return CVSSScore("AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H")
	}
	// Regular SPN: offline crack → single account compromise: AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N
	return CVSSScore("AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N")
}

// CVSSForASREP returns the CVSS 3.1 base score for an AS-REP Roastable account.
// No pre-authentication required — any unauthenticated attacker can request the hash.
func CVSSForASREP() float64 {
	// No pre-auth = no credentials needed: AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N
	return CVSSScore("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N")
}
