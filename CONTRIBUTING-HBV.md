# THC Scalpel — HoneyBadger Vanguard Fork

**Fork:** `thc-scalpel-hbv.ps1`  
**Original:** KL3FT3Z / hackteam.red — [thc-scalpel](https://github.com/Hackteam-Red/thc-scalpel)  
**Fork Author:** HoneyBadger — [HoneyBadger Vanguard, LLC](https://ihbv.io)  
**Version:** 1.1.0-HBV  
**Requires:** PowerShell 7.0+ (original: 5.1+)

---

## What This Fork Adds

The original `thc-scalpel.ps1` is an excellent stealth recon toolkit. This fork extends it with purple team / SIEM integration capabilities from the HBV toolkit stack, while preserving 100% backward-compatible parameters and the original `ip.thc.org` API endpoints (`sb/`, `cn/`).

### New Features

| Feature | Description |
|---------|-------------|
| **OPSEC Footprint Telemetry** | Rolling 0–100 score based on request velocity, volume, and failure rate. Displayed per-query and summarized at session end. |
| **MITRE ATT&CK Tagging** | Every result object and log event carries the correct technique: T1590.002 (rDNS), T1596.001 (subdomain), T1590.004 (CNAME/subnet). |
| **Wazuh SIEM Integration** | NDJSON log output + decoder + 5 detection rules (baseline, high-noise, takeover risk, subdomain enum, API failure). |
| **Dangling CNAME Detection** | Screens CNAME results against 15 cloud provider patterns for subdomain takeover candidates. Red console warning + JSON flag + HTML badge. |
| **HTML Threat Report** | Self-contained report with OPSEC bar, MITRE strip, VT badges, and per-result finding cards. |
| **VirusTotal Enrichment** | Optional `-VTApiKey`. First 5 subdomains per domain checked against VT v3 API. Rate-limit-conscious. |
| **Pipeline Input** | `ValueFromPipeline` support — pipe domain lists from PhishRonin or any upstream tool. |
| **Structured Output** | All functions return `[PSCustomObject]` for native PowerShell pipeline filtering/sorting. |

---

## New Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-ReportFile` | String | Path for HTML threat report output |
| `-WazuhLogFile` | String | NDJSON log path (default: `.\thc-scalpel-wazuh.json`) |
| `-VTApiKey` | String | VirusTotal v3 API key (optional) |
| `-NoWazuh` | Switch | Suppress Wazuh log output |

All original parameters (`-Target`, `-Type`, `-InputFile`, `-OutputFile`, `-Delay`, `-Threads`, `-Keywords`, `-Timeout`, `-Stealth`) are preserved unchanged.

---

## Usage Examples

```powershell
# Subdomain enum with HTML report
.\thc-scalpel-hbv.ps1 -Target "example.com" -Type subdomain -ReportFile report.html

# Full stealth recon with all outputs
.\thc-scalpel-hbv.ps1 -Target "corp.com" -Type subdomain `
    -Keywords "admin,dev,vpn,api,internal" -Stealth `
    -VTApiKey $env:VT_API_KEY `
    -OutputFile results.json -ReportFile report.html

# Pipeline: file → scalpel → filter → export
Get-Content phish-domains.txt |
    .\thc-scalpel-hbv.ps1 -Type cname -ReportFile takeover-check.html |
    Where-Object { $_.TakeoverRisk } |
    ConvertTo-Json | Out-File takeover-risks.json

# CNAME takeover sweep, suppress Wazuh log
.\thc-scalpel-hbv.ps1 -InputFile domains.txt -Type cname -NoWazuh
```

---

## Wazuh Integration

Deploy the included files to your Wazuh manager:

```bash
cp wazuh/thc-scalpel-decoder.xml /var/ossec/etc/decoders/
cp wazuh/thc-scalpel-rules.xml   /var/ossec/etc/rules/
systemctl restart wazuh-manager
```

Configure your agent's `ossec.conf` to watch the log file:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/path/to/thc-scalpel-wazuh.json</location>
</localfile>
```

**Included Rules:**

| Rule ID | Level | Trigger |
|---------|-------|---------|
| 100600 | 3 | Any scalpel recon event |
| 100601 | 10 | OPSEC footprint score ≥ 70 |
| 100602 | 12 | Dangling CNAME / takeover risk |
| 100603 | 5 | Subdomain enumeration complete |
| 100604 | 7 | API request failure |

---

## MITRE ATT&CK Coverage

| Operation | Technique |
|-----------|-----------|
| `rdns` | T1590.002 — Gather Victim Network Info: DNS |
| `subdomain` | T1596.001 — Search Open Technical Databases: DNS/Passive DNS |
| `cname` | T1590.004 — Gather Victim Network Info: Network Topology |
| `subnet` | T1590.004 — Gather Victim Network Info: Network Topology |

---

## File Structure

```
thc-scalpel/
├── thc-scalpel.ps1          # Original (unchanged)
├── thc-scalpel.py           # Original (unchanged)
├── thc-scalpel-hbv.ps1      # This fork
├── wazuh/
│   ├── thc-scalpel-decoder.xml
│   └── thc-scalpel-rules.xml
└── CONTRIBUTING-HBV.md      # This file
```

---

## Acknowledgments

- **KL3FT3Z / hackteam.red** — original tool and ip.thc.org integration
- **The Hacker's Choice (THC)** — ip.thc.org API and 30 years of community contributions
- HBV additions draw from the PhishRonin and HoneyBadger Sentinel toolkit patterns

MIT License — same as original.
