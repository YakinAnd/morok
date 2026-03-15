package analysis

import (
	"fmt"
	"strings"
 	"strconv"
	"github.com/fatih/color"

	adldap "github.com/YakinAnd/adpath/internal/ldap"
)

// ============================================================
// Моделі даних
// ============================================================

// GPOFinding — один знайдений GPO з інформацією безпеки
type GPOFinding struct {
	Name            string
	DN              string
	GUID            string
	LinkedTo        []string // OU/Domain до яких прив'язаний
	EditableBy      []string // хто може редагувати (крім адмінів)
	HasCPassword    bool     // містить зашифровані паролі в Preferences
	IsHighRisk      bool
	RiskReasons     []string
}

// PasswordPolicy — налаштування парольної політики
type PasswordPolicy struct {
	MinLength       int
	MaxAge          int    // днів
	MinAge          int    // днів
	Complexity      bool
	LockoutThreshold int
	ReversibleEncryption bool
}

// GPOResult — результат аналізу GPO
type GPOResult struct {
	Domain          string
	GPOFindings     []GPOFinding
	PasswordPolicy  *PasswordPolicy
	DefaultPolicy   *PasswordPolicy
}

// ============================================================
// LDAP фільтри
// ============================================================

const (
	// Всі GPO об'єкти
	FilterAllGPO = "(objectClass=groupPolicyContainer)"

	// GPO Links на OU
	FilterOUWithGPO = "(&(objectClass=organizationalUnit)(gPLink=*))"

	// Domain object для password policy і GPO links
	FilterDomainObject = "(objectClass=domain)"
)

var gpoAttributes = []string{
	"distinguishedName",
	"displayName",
	"name",            // GUID у форматі {GUID}
	"gPCFileSysPath",  // шлях до SYSVOL
	"nTSecurityDescriptor",
	"objectClass",
}

var ouAttributes = []string{
	"distinguishedName",
	"gPLink",
	"name",
}

var domainAttributes = []string{
	"distinguishedName",
	"gPLink",
	"minPwdLength",
	"maxPwdAge",
	"minPwdAge",
	"pwdProperties",
	"lockoutThreshold",
}

// ============================================================
// Основна функція аналізу
// ============================================================

// AnalyzeGPO знаходить небезпечні GPO конфігурації
func AnalyzeGPO(client *adldap.Client) (*GPOResult, error) {
	result := &GPOResult{
		Domain: client.GetDomain(),
	}

	color.Blue("\n[*] Analyzing Group Policy Objects...")

	// збираємо всі GPO
	gpos, err := collectGPOs(client)
	if err != nil {
		return nil, err
	}

	color.Blue("[*] Found %d GPOs, analyzing...", len(gpos))

	// збираємо GPO links (OU → GPO)
	links, err := collectGPOLinks(client)
	if err != nil {
		return nil, err
	}

	// зіставляємо GPO з їх links
	for i := range gpos {
		guid := extractGUID(gpos[i].GUID)
		for ou, ouLinks := range links {
			for _, link := range ouLinks {
				if strings.EqualFold(extractGUID(link), guid) {
					gpos[i].LinkedTo = append(gpos[i].LinkedTo, ou)
				}
			}
		}
	}

	// аналізуємо права на редагування GPO
	for i := range gpos {
		analyzeGPOPermissions(client, &gpos[i])
	}

	// збираємо тільки знахідки з ризиками
	for _, gpo := range gpos {
		if gpo.IsHighRisk || len(gpo.EditableBy) > 0 {
			result.GPOFindings = append(result.GPOFindings, gpo)
		}
	}

	// аналізуємо password policy
	pp, err := collectPasswordPolicy(client)
	if err != nil {
		color.Yellow("[!] Could not collect password policy: %v", err)
	} else {
		result.DefaultPolicy = pp
		assessPasswordPolicy(pp, result)
	}

	color.Green("[+] Found %d GPO findings", len(result.GPOFindings))

	return result, nil
}

// ============================================================
// Збір GPO об'єктів
// ============================================================

func collectGPOs(client *adldap.Client) ([]GPOFinding, error) {
	entries, err := client.Search(FilterAllGPO, gpoAttributes)
	if err != nil {
		return nil, fmt.Errorf("GPO search failed: %w", err)
	}

	var gpos []GPOFinding
	for _, entry := range entries {
		gpo := GPOFinding{
			Name: entry.GetAttributeValue("displayName"),
			DN:   entry.DN,
			GUID: entry.GetAttributeValue("name"),
		}

		// перевіряємо чи є в SYSVOL path ознаки cpassword
		sysvolPath := entry.GetAttributeValue("gPCFileSysPath")
		if sysvolPath != "" {
			gpo.HasCPassword = checkForCPassword(sysvolPath)
		}

		if gpo.HasCPassword {
			gpo.IsHighRisk = true
			gpo.RiskReasons = append(gpo.RiskReasons,
				"GPO Preferences may contain cpassword (encrypted credentials decryptable with public AES key)")
		}

		gpos = append(gpos, gpo)
	}

	return gpos, nil
}

// ============================================================
// Збір GPO Links
// ============================================================

func collectGPOLinks(client *adldap.Client) (map[string][]string, error) {
	links := make(map[string][]string)

	// links на OU
	ouEntries, err := client.Search(FilterOUWithGPO, ouAttributes)
	if err != nil {
		return nil, fmt.Errorf("OU GPO link search failed: %w", err)
	}

	for _, entry := range ouEntries {
		gPLink := entry.GetAttributeValue("gPLink")
		if gPLink == "" {
			continue
		}
		parsedLinks := parseGPLink(gPLink)
		if len(parsedLinks) > 0 {
			ouName := entry.GetAttributeValue("name")
			if ouName == "" {
				ouName = entry.DN
			}
			links[ouName] = parsedLinks
		}
	}

	// links на domain object
	domainEntries, err := client.Search(FilterDomainObject, domainAttributes)
	if err == nil {
		for _, entry := range domainEntries {
			gPLink := entry.GetAttributeValue("gPLink")
			if gPLink != "" {
				parsedLinks := parseGPLink(gPLink)
				if len(parsedLinks) > 0 {
					links["Domain"] = parsedLinks
				}
			}
		}
	}

	return links, nil
}

// parseGPLink парсить атрибут gPLink формату:
// [LDAP://cn={GUID},cn=policies,...;0][LDAP://cn={GUID},...;2]
func parseGPLink(gPLink string) []string {
	var guids []string
	parts := strings.Split(gPLink, "[")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// знаходимо GUID у форматі {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
		start := strings.Index(part, "{")
		end := strings.Index(part, "}")
		if start != -1 && end != -1 && end > start {
			guid := part[start : end+1]
			guids = append(guids, guid)
		}
	}
	return guids
}

// extractGUID нормалізує GUID до формату {GUID}
func extractGUID(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") {
		s = "{" + s
	}
	if !strings.HasSuffix(s, "}") {
		s = s + "}"
	}
	return strings.ToLower(s)
}

// ============================================================
// Аналіз прав на GPO
// ============================================================

// analyzeGPOPermissions перевіряє хто може редагувати GPO
func analyzeGPOPermissions(client *adldap.Client, gpo *GPOFinding) {
	// Шукаємо через ACL хто має права на цей GPO
	// Використовуємо спрощений підхід через LDAP search
	filter := fmt.Sprintf("(&(objectClass=groupPolicyContainer)(name=%s))", gpo.GUID)
	attrs := []string{"distinguishedName", "nTSecurityDescriptor"}

	entries, err := client.Search(filter, attrs)
	if err != nil || len(entries) == 0 {
		return
	}

	// Перевіряємо через відомі небезпечні права
	// В повній реалізації тут був би парсинг nTSecurityDescriptor
	// Для MVP перевіряємо через gPCFileSysPath права доступу
}

// ============================================================
// Password Policy
// ============================================================

func collectPasswordPolicy(client *adldap.Client) (*PasswordPolicy, error) {
	entries, err := client.Search(FilterDomainObject, domainAttributes)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("domain object not found")
	}

	entry := entries[0]
	pp := &PasswordPolicy{}

	// minPwdLength
	if v := entry.GetAttributeValue("minPwdLength"); v != "" {
		fmt.Sscanf(v, "%d", &pp.MinLength)
	}

	// pwdProperties біт 0x1 = DOMAIN_PASSWORD_COMPLEX
	if v := entry.GetAttributeValue("pwdProperties"); v != "" {
		var props int
		fmt.Sscanf(v, "%d", &props)
		pp.Complexity = (props & 0x1) != 0
		pp.ReversibleEncryption = (props & 0x10) != 0
	}

	// lockoutThreshold
	if v := entry.GetAttributeValue("lockoutThreshold"); v != "" {
		fmt.Sscanf(v, "%d", &pp.LockoutThreshold)
	}

	// maxPwdAge — Windows зберігає в 100-наносекундних інтервалах (від'ємне)
	if v := entry.GetAttributeValue("maxPwdAge"); v != "" {
    age, err := strconv.ParseInt(v, 10, 64)
    if err == nil {
        if age < 0 {
            age = -age
        }
        if age == 0 {
            pp.MaxAge = 0
        } else {
            pp.MaxAge = int(age / 864000000000)
        }
    }
	}

	return pp, nil
}

func assessPasswordPolicy(pp *PasswordPolicy, result *GPOResult) {
	// перевіряємо слабкі налаштування
	_ = pp   // буде використано в PrintGPOResult
	_ = result
}

// ============================================================
// Перевірка cpassword
// ============================================================

// checkForCPassword перевіряє чи може GPO містити cpassword
// В реальності треба читати XML файли з SYSVOL
// Для MVP відмічаємо як потенційно вразливий
func checkForCPassword(sysvolPath string) bool {
	// GPO Preferences файли які можуть містити cpassword:
	// Groups.xml, Services.xml, Scheduledtasks.xml,
	// Datasources.xml, Printers.xml, Drives.xml
	// Без доступу до SYSVOL не можемо перевірити напряму
	// Повертаємо false — відмічатимемо тільки якщо є доступ
	return false
}

// ============================================================
// Вивід результатів
// ============================================================

// PrintGPOResult виводить результати GPO аналізу
func PrintGPOResult(gr *GPOResult) {
	printPasswordPolicyResult(gr)
	printGPOFindings(gr)
}

func printPasswordPolicyResult(gr *GPOResult) {
	if gr.DefaultPolicy == nil {
		color.Yellow("[!] Could not retrieve password policy")
		return
	}

	pp := gr.DefaultPolicy
	color.Cyan("\n[*] Default Domain Password Policy:\n")

	// мінімальна довжина
	if pp.MinLength < 8 {
		color.Red("  🔴 Minimum password length: %d (recommended: 12+)", pp.MinLength)
	} else if pp.MinLength < 12 {
		color.Yellow("  🟠 Minimum password length: %d (recommended: 12+)", pp.MinLength)
	} else {
		color.Green("  ✓  Minimum password length: %d", pp.MinLength)
	}

	// складність
	if !pp.Complexity {
		color.Red("  🔴 Password complexity: DISABLED")
	} else {
		color.Green("  ✓  Password complexity: enabled")
	}

	// reversible encryption
	if pp.ReversibleEncryption {
		color.Red("  🔴 Reversible encryption: ENABLED (passwords stored in plaintext-equivalent)")
	} else {
		color.Green("  ✓  Reversible encryption: disabled")
	}

	// lockout
	if pp.LockoutThreshold == 0 {
		color.Red("  🔴 Account lockout: DISABLED (brute force possible)")
	} else if pp.LockoutThreshold > 10 {
		color.Yellow("  🟠 Account lockout threshold: %d (recommended: 5 or less)", pp.LockoutThreshold)
	} else {
		color.Green("  ✓  Account lockout threshold: %d", pp.LockoutThreshold)
	}

	// max password age
	if pp.MaxAge == 0 || pp.MaxAge > 3650 {
    color.Red("  🔴 Maximum password age: NEVER EXPIRES (passwords valid indefinitely)")
	} else if pp.MaxAge > 90 {
    color.Yellow("  🟠 Maximum password age: %d days (recommended: 90 or less)", pp.MaxAge)
	} else {
    color.Green("  ✓  Maximum password age: %d days", pp.MaxAge)
	}
}

func printGPOFindings(gr *GPOResult) {
	if len(gr.GPOFindings) == 0 {
		color.Green("\n[+] No dangerous GPO configurations found")
		return
	}

	color.Red("\n[!] Dangerous GPO Findings (%d):\n", len(gr.GPOFindings))

	for _, gpo := range gr.GPOFindings {
		icon := "🟠"
		if gpo.IsHighRisk {
			icon = "🔴"
		}

		color.White("\n  %s %s", icon, gpo.Name)
		color.White("      GUID: %s", gpo.GUID)
		color.White("      DN:   %s", gpo.DN)

		if len(gpo.LinkedTo) > 0 {
			color.White("      Linked to:")
			for _, link := range gpo.LinkedTo {
				color.Cyan("        - %s", link)
			}
		}

		if len(gpo.EditableBy) > 0 {
			color.Red("      Editable by (non-admins):")
			for _, editor := range gpo.EditableBy {
				color.Red("        - %s", editor)
			}
		}

		for _, reason := range gpo.RiskReasons {
			color.Red("      Risk: %s", reason)
		}
	}

	color.Cyan("\n[*] GPO Abuse hints:")
	color.White("  If you can edit a GPO linked to Domain or high-value OU:")
	color.White("    pyGPOAbuse.py -f AddLocalAdmin -u <user> -p <pass> -d %s --dc-ip <DC>", gr.Domain)
	color.White("  Check for cpassword in SYSVOL:")
	color.White("    Get-GPPPassword (PowerSploit)")
	color.White("    findstr /S /I cpassword \\\\%s\\SYSVOL\\%s\\Policies\\*.xml", gr.Domain, gr.Domain)
}