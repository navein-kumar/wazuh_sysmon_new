# Sysmon + Wazuh DLP Monitoring

Data Loss Prevention (DLP) solution using Sysmon for endpoint telemetry and Wazuh for detection and alerting.

## Architecture

```
Endpoint (Windows)              Wazuh Manager
┌──────────────┐               ┌──────────────────┐
│  Sysmon      │──── logs ────>│  dlp_rule.xml    │
│  config.xml  │   (Wazuh      │  (detection +     │
│              │    agent)      │   correlation)    │
└──────────────┘               └──────────────────┘
```

## Files

| File | Location | Purpose |
|------|----------|---------|
| `config.xml` | Endpoint: `C:\Windows\Sysmon\` | Sysmon configuration - what to monitor |
| `dlp_rule.xml` | Wazuh Manager: `/var/ossec/etc/rules/` | Wazuh detection rules - what to alert on |

---

## Sysmon Config (`config.xml`)

**Schema:** 4.50 | **Hashing:** MD5, SHA256, IMPHASH

### Sysmon Events Monitored

| Event ID | Event Name | DLP Purpose |
|----------|-----------|-------------|
| 1 | ProcessCreate | Detect exfiltration tools (MEGAsync, curl, bitsadmin) |
| 3 | NetworkConnect | Track outbound connections |
| 11 | FileCreate | Detect uploads/downloads via `.lnk` files in Recent folder |
| 15 | FileCreateStreamHash | Detect Chrome/Brave downloads via `Zone.Identifier` ADS |
| 22 | DNSQuery | Detect connections to AI platforms, paste sites, cloud storage |
| 24 | ClipboardChange | Monitor clipboard copy operations (file names only) |

### Event ID 15 - Why It's Needed for Chrome

Edge and Firefox create files directly in `\Downloads\` (caught by Event 11). Chrome writes a `.tmp` file, renames it, then adds a `Zone.Identifier` Alternate Data Stream - Event 11 only sees the `.tmp` name. Event 15 (FileCreateStreamHash) catches the final filename via the ADS.

```
Chrome download flow:
  .tmp file created --> renamed to final name --> Zone.Identifier ADS written
                                                  └── Event 15 catches this
```

### Clipboard Monitoring Note

`CaptureClipboard` and `ArchiveDirectory` have been **removed** to prevent disk bloat (was generating 60GB+ of archived clipboard content). Event ID 24 still logs clipboard change events including process name and file names - the raw content is just no longer saved to disk.

### Key Exclusions (config.xml)

- Windows system processes (svchost, csrss, dwm, etc.)
- Security software (Sophos, CrowdStrike, SentinelOne, ESET, etc.)
- OCSP/certificate validation DNS queries
- Image file Zone.Identifier streams (.jpg, .png, .gif - noise reduction)

---

## Wazuh Rules (`dlp_rule.xml`)

### Rule ID Reference

#### Base Sysmon Rules (Level 0-3)

| Rule ID | Parent | Event | Description |
|---------|--------|-------|-------------|
| 100600 | 60004 | - | Base parent rule for all Sysmon events |
| 100601 | 100600 | 1 | Process Create |
| 100603 | 100600 | 3 | Network Connect |
| 100611 | 100600 | 11 | File Create |
| 100615 | 100600 | 15 | FileCreateStreamHash |
| 100622 | 100600 | 22 | DNS Query |
| 100624 | 100600 | 24 | Clipboard Change |

#### DNS-Based DLP Detection (Level 6-12)

| Rule ID | Level | Detects | MITRE |
|---------|-------|---------|-------|
| 100710 | 8 | AI platforms (ChatGPT, Claude, Gemini, Copilot, DeepSeek, etc.) | T1567 |
| 100711 | 12 | Paste sites (Pastebin, paste.ee, justpaste.it, etc.) | T1567, T1048 |
| 100712 | 8 | Code repos (GitHub, GitLab, Bitbucket) | T1567.002 |
| 100713 | 10 | Cloud storage (Dropbox, Google Drive, OneDrive, MEGA, WeTransfer, etc.) | T1567.002 |
| 100714 | 6 | Collaboration tools (Teams, Slack, Discord, Telegram) | - |
| 100715 | 8 | Personal email (Gmail, Yahoo, ProtonMail, Outlook, Zoho) | T1048.003 |

#### Clipboard + DNS Correlation Rules (Level 12, 180s timeframe)

These fire when clipboard activity is detected within 3 minutes of visiting a risky site on the same machine.

| Rule ID | Correlates Clipboard With |
|---------|---------------------------|
| 100720 | AI platform access |
| 100721 | Paste site access |
| 100722 | Code repository access |
| 100723 | Cloud storage access |
| 100724 | Collaboration tool access |
| 100725 | Personal email access |

#### File Upload/Download Detection (Level 8)

| Rule ID | Level | Detects |
|---------|-------|---------|
| 100902 | 2 | File access in Windows shared folder (Event 4663) |
| 100903 | 10 | Browser reading file from shared folder (possible upload) |
| 100905 | 3 | `.lnk` created in Recent folder (base rule) |
| 100906 | 8 | File download detected via Recent folder |
| 100907 | 8 | File upload/access detected via Recent folder |
| 100908 | 8 | File created directly in Downloads folder |

#### Chrome/Brave Download Detection - Event 15 (Level 8-12)

| Rule ID | Level | Detects |
|---------|-------|---------|
| 100910 | 8 | Chrome download via Zone.Identifier |
| 100911 | 8 | Brave download via Zone.Identifier |
| 100912 | 8 | Any download to Downloads folder via Event 15 |
| 100913 | 12 | High-risk file type downloaded (.exe, .ps1, .zip, .iso, etc.) |
| 100914 | 8 | Download to Desktop via Event 15 |

#### Exfiltration Tools Detection (Level 10-12)

| Rule ID | Level | Tool | MITRE |
|---------|-------|------|-------|
| 100732 | 12 | MEGAsync | T1567.002 |
| 100735 | 10 | Git push / remote add | T1567.002 |
| 100740 | 10 | Bitsadmin file transfer | T1197, T1567.002 |
| 100741 | 10 | Curl upload | T1567.002 |
| 100742 | 10 | Certreq exfiltration | T1567.002 |

#### Noise Suppression (Level 0)

| Rule ID | Excludes |
|---------|----------|
| 100002 | Sophos AMSI provider events |
| 100800 | Security tools by image path |
| 100801 | Security tools by sourceImage |
| 100802 | Security tools by targetImage |

#### Other Rules

| Rule ID | Level | Description |
|---------|-------|-------------|
| 100001 | 5 | SSH auth failed from specific IP |
| 81603 | 3 | FortiGate firewall logs |
| 81633 | 4 | FortiGate app-ctrl pass |
| 100901 | 3 | Office 365 login failed |

---

## Deployment

### Install Sysmon (Endpoint - Run as Admin)

```powershell
# First time install
sysmon64.exe -accepteula -i config.xml

# Update existing config
sysmon64.exe -c config.xml

# Verify running
Get-Service Sysmon64
```

### Deploy Wazuh Rules (Manager)

```bash
# Copy rules
cp dlp_rule.xml /var/ossec/etc/rules/

# Test rules
/var/ossec/bin/wazuh-logtest

# Restart manager
systemctl restart wazuh-manager
```

---

## Alert Levels

| Level | Meaning | Action |
|-------|---------|--------|
| 0 | Suppressed / excluded | No alert |
| 3 | Informational | Logged only |
| 6 | Low | Monitor |
| 8 | Medium | Review |
| 10 | High | Investigate |
| 12 | Critical | Immediate response |
