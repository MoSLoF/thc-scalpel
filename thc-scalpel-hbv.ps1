#Requires -Version 7.0
<#
.SYNOPSIS
    THC Scalpel - Stealth Reconnaissance Toolkit (HoneyBadger Vanguard Edition)

.DESCRIPTION
    Surgical precision reconnaissance toolkit powered by the ip.thc.org API.

    This fork extends the original thc-scalpel.ps1 by KL3FT3Z / hackteam.red with:
      - MITRE ATT&CK technique tagging (T1590.002, T1590.004, T1596.001)
      - OPSEC footprint telemetry: rolling request-rate scoring (0-100)
      - Wazuh-compatible SIEM JSON logging (see wazuh/ for decoder + rules)
      - HTML threat report generation with cyberpunk aesthetic
      - Dangling CNAME / subdomain takeover detection
      - VirusTotal domain enrichment (optional, -VTApiKey)
      - Pipeline input support: pipe domain lists from PhishRonin / RoninHunt
      - Structured [PSCustomObject] output throughout — no raw string returns

.PARAMETER Target
    Target IP address, domain name, or CIDR subnet.
    Accepts pipeline input.

.PARAMETER Type
    Operation type: rdns | subdomain | cname | subnet
    Default: rdns

.PARAMETER InputFile
    Path to file containing targets (one per line). Lines beginning with # are skipped.

.PARAMETER OutputFile
    Output path. Extension determines format: .json (default), .csv, .xml

.PARAMETER ReportFile
    Path for self-contained HTML threat report. Omit to skip report generation.

.PARAMETER WazuhLogFile
    Append-mode NDJSON log for Wazuh logcollector. Default: .\thc-scalpel-wazuh.json

.PARAMETER Delay
    Seconds between API requests. Default: 0.5

.PARAMETER Threads
    Parallel thread count for bulk operations. Default: 5

.PARAMETER Keywords
    Comma-separated filter keywords, e.g. "admin,dev,vpn,staging,api"

.PARAMETER Timeout
    HTTP timeout in seconds. Default: 30

.PARAMETER Stealth
    Enable stealth mode: forces Threads=1, randomized 2-5s jitter delays.

.PARAMETER VTApiKey
    VirusTotal v3 API key for domain reputation enrichment (optional).
    First 5 unique domains per query are checked to respect free-tier limits.

.PARAMETER NoWazuh
    Suppress Wazuh log output entirely.

.EXAMPLE
    # Standard subdomain enum with HTML report
    .\thc-scalpel-hbv.ps1 -Target "example.com" -Type subdomain -ReportFile report.html

.EXAMPLE
    # Stealth recon with VT enrichment, keyword filter, all outputs
    .\thc-scalpel-hbv.ps1 -Target "corp.com" -Type subdomain `
        -Keywords "admin,dev,vpn,api" -Stealth `
        -VTApiKey $env:VT_API_KEY `
        -OutputFile results.json -ReportFile report.html

.EXAMPLE
    # Pipeline from file — PhishRonin RoninHunt → scalpel → filter
    Get-Content suspicious_domains.txt |
        .\thc-scalpel-hbv.ps1 -Type subdomain -Keywords "login,auth,sso" |
        Where-Object { $_.Count -gt 0 } |
        ConvertTo-Json | Out-File infra.json

.EXAMPLE
    # CNAME takeover sweep
    .\thc-scalpel-hbv.ps1 -InputFile domains.txt -Type cname -ReportFile cname-report.html

.NOTES
    Original Tool  : KL3FT3Z / hackteam.red  (MIT License)
    HBV Fork Author: HoneyBadger — HoneyBadger Vanguard, LLC (ihbv.io)
    Fork Version   : 1.1.0-HBV
    Requires       : PowerShell 7.0+ (tested on 7.5.4)
    Original Req   : PowerShell 5.1+

    MITRE ATT&CK Techniques:
      T1590.002 — Gather Victim Network Information: DNS
      T1590.004 — Gather Victim Network Information: Network Topology
      T1596.001 — Search Open Technical Databases: DNS/Passive DNS

    API Endpoints (ip.thc.org):
      rDNS     : https://ip.thc.org/<ip>
      Subdomain: https://ip.thc.org/sb/<domain>
      CNAME    : https://ip.thc.org/cn/<domain>
      Subnet   : https://ip.thc.org/<cidr>

    LEGAL: Authorized engagements only.
           Unauthorized use is illegal and unethical.
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [string]$Target,

    [Parameter(Mandatory = $false)]
    [ValidateSet('rdns','subdomain','cname','subnet')]
    [string]$Type = 'rdns',

    [Parameter(Mandatory = $false)]
    [string]$InputFile,

    [Parameter(Mandatory = $false)]
    [string]$OutputFile,

    [Parameter(Mandatory = $false)]
    [string]$ReportFile,

    [Parameter(Mandatory = $false)]
    [string]$WazuhLogFile = '.\thc-scalpel-wazuh.json',

    [Parameter(Mandatory = $false)]
    [double]$Delay = 0.5,

    [Parameter(Mandatory = $false)]
    [int]$Threads = 5,

    [Parameter(Mandatory = $false)]
    [string]$Keywords,

    [Parameter(Mandatory = $false)]
    [int]$Timeout = 30,

    [Parameter(Mandatory = $false)]
    [switch]$Stealth,

    [Parameter(Mandatory = $false)]
    [switch]$NoWazuh,

    [Parameter(Mandatory = $false)]
    [string]$VTApiKey
)

begin {
    #region ── Constants & State ────────────────────────────────────────────────
    $HBV_VERSION  = '1.1.0-HBV'
    $BASE_URL     = 'https://ip.thc.org'
    $USER_AGENT   = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'

    # Known cloud providers vulnerable to subdomain takeover
    $TAKEOVER_PATTERNS = @(
        '\.s3\.amazonaws\.com$', '\.s3-website', '\.github\.io$',
        '\.heroku\.com$', '\.herokuapp\.com$', '\.azurewebsites\.net$',
        '\.cloudfront\.net$', '\.fastly\.net$', '\.zendesk\.com$',
        '\.shopify\.com$', '\.squarespace\.com$', '\.ghost\.io$',
        '\.surge\.sh$', '\.netlify\.app$', '\.vercel\.app$'
    )

    $script:OpsecState = [ordered]@{
        SessionStart      = Get-Date
        TotalRequests     = 0
        FailedRequests    = 0
        RequestTimestamps = [System.Collections.Generic.List[datetime]]::new()
        FootprintScore    = 0
        StealthMode       = $Stealth.IsPresent
        TargetCount       = 0
        ResultCount       = 0
    }

    $script:AllResults     = [System.Collections.Generic.List[PSCustomObject]]::new()
    $script:WazuhEvents    = [System.Collections.Generic.List[hashtable]]::new()
    $script:PipelineInputs = [System.Collections.Generic.List[string]]::new()

    $script:KeywordList = @()
    if ($Keywords) {
        $script:KeywordList = $Keywords -split ',' | ForEach-Object { $_.Trim().ToLower() }
    }

    if ($Stealth) {
        $script:Threads = 1
        Write-Host "  [STEALTH] Single-thread mode, randomized 2-5s jitter active." -ForegroundColor Yellow
    }
    #endregion

    #region ── Banner ───────────────────────────────────────────────────────────
    Write-Host @"

██████ ██  ██ ▄█████     ▄█████ ▄█████ ▄████▄ ██     █████▄ ██████ ██
  ██   ██████ ██     ▄▄▄ ▀▀▀▄▄▄ ██     ██▄▄██ ██     ██▄▄█▀ ██▄▄   ██
  ██   ██  ██ ▀█████     █████▀ ▀█████ ██  ██ ██████ ██     ██▄▄▄▄ ██████

  Original: KL3FT3Z / hackteam.red  |  HBV Fork v$HBV_VERSION: ihbv.io
  MITRE: T1590.002 / T1590.004 / T1596.001
"@ -ForegroundColor Cyan
    #endregion

    #region ── Helper: OPSEC Footprint Scorer ──────────────────────────────────
    function Measure-OpsecFootprint {
        $now         = Get-Date
        $windowStart = $now.AddMinutes(-1)
        $recentCount = ($script:OpsecState.RequestTimestamps |
            Where-Object { $_ -gt $windowStart } | Measure-Object).Count

        $velScore  = [math]::Min(50, $recentCount * 5)
        $volScore  = [math]::Min(30, [int]($script:OpsecState.TotalRequests / 10))
        $failScore = [math]::Min(20, $script:OpsecState.FailedRequests * 4)
        $total     = $velScore + $volScore + $failScore

        $script:OpsecState.FootprintScore = [math]::Min(100, $total)

        $risk = switch ($total) {
            { $_ -le 20 } { 'LOW';      break }
            { $_ -le 50 } { 'MEDIUM';   break }
            { $_ -le 75 } { 'HIGH';     break }
            default         { 'CRITICAL' }
        }

        return [PSCustomObject]@{
            Score      = $script:OpsecState.FootprintScore
            RiskLevel  = $risk
            ReqPerMin  = $recentCount
            TotalReqs  = $script:OpsecState.TotalRequests
            FailedReqs = $script:OpsecState.FailedRequests
        }
    }
    #endregion

    #region ── Helper: API Request ──────────────────────────────────────────────
    function Invoke-THCRequest {
        param(
            [string]$Endpoint,
            [int]$RetryCount = 3
        )

        # Timing — stealth jitter or standard delay
        if ($Stealth) {
            Start-Sleep -Milliseconds (Get-Random -Minimum 2000 -Maximum 5000)
        }
        elseif ($Delay -gt 0) {
            Start-Sleep -Milliseconds ([int]($Delay * 1000))
        }

        $script:OpsecState.TotalRequests++
        $script:OpsecState.RequestTimestamps.Add((Get-Date))

        $url     = "$BASE_URL/$Endpoint"
        $attempt = 0

        while ($attempt -lt $RetryCount) {
            try {
                $response = Invoke-WebRequest -Uri $url `
                    -UserAgent $USER_AGENT `
                    -TimeoutSec $Timeout `
                    -UseBasicParsing `
                    -ErrorAction Stop

                if ($response.StatusCode -eq 200) {
                    $data = $response.Content -split "`n" | Where-Object { $_ -match '\S' }
                    return @{ Success = $true; Data = $data; Count = $data.Count }
                }
            }
            catch {
                $attempt++
                $script:OpsecState.FailedRequests++
                if ($attempt -ge $RetryCount) {
                    return @{ Success = $false; Error = $_.Exception.Message; Data = @(); Count = 0 }
                }
                Start-Sleep -Seconds 2
            }
        }
        return @{ Success = $false; Error = 'Max retries exceeded'; Data = @(); Count = 0 }
    }
    #endregion

    #region ── Helper: VirusTotal Enrichment ────────────────────────────────────
    function Get-VTReputation {
        param([string]$Domain)
        if (-not $VTApiKey) { return $null }
        try {
            $headers = @{ 'x-apikey' = $VTApiKey }
            $resp    = Invoke-RestMethod -Uri "https://www.virustotal.com/api/v3/domains/$Domain" `
                -Headers $headers -TimeoutSec 15 -ErrorAction Stop
            $s = $resp.data.attributes.last_analysis_stats
            return [PSCustomObject]@{
                Malicious  = $s.malicious
                Suspicious = $s.suspicious
                Harmless   = $s.harmless
                Undetected = $s.undetected
                VTScore    = "$($s.malicious)/$($s.malicious + $s.suspicious + $s.harmless + $s.undetected)"
            }
        }
        catch { return $null }
    }
    #endregion

    #region ── Helper: Wazuh Event Logger ───────────────────────────────────────
    function Write-WazuhEvent {
        param(
            [string]$EventType,
            [string]$TargetValue,
            [hashtable]$Data,
            [string]$MitreId = 'T1590.002'
        )
        if ($NoWazuh) { return }
        $script:WazuhEvents.Add(@{
            timestamp       = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ')
            program_name    = 'thc-scalpel-hbv'
            event_type      = $EventType
            target          = $TargetValue
            mitre_technique = $MitreId
            mitre_tactic    = 'Reconnaissance'
            opsec_footprint = $script:OpsecState.FootprintScore
            stealth_mode    = $script:OpsecState.StealthMode
            data            = $Data
            hbv_version     = $HBV_VERSION
        })
    }
    #endregion

    #region ── Core Recon Functions ─────────────────────────────────────────────
    function Invoke-ReverseDNS {
        param([string]$IP)
        Write-Host "  [rDNS    ] $IP" -ForegroundColor Cyan
        $raw = Invoke-THCRequest -Endpoint $IP
        $result = [PSCustomObject]@{
            Type      = 'RDNS'
            Target    = $IP
            Hostnames = if ($raw.Success) { $raw.Data } else { @() }
            Count     = $raw.Count
            Success   = $raw.Success
            Error     = $raw.Error
            Timestamp = Get-Date -Format 'o'
            MitreTTP  = 'T1590.002'
        }
        Write-WazuhEvent -EventType 'RDNS_RESULT' -TargetValue $IP -MitreId 'T1590.002' `
            -Data @{ hostnames = $result.Hostnames; count = $result.Count }
        return $result
    }

    function Invoke-SubdomainEnum {
        param([string]$Domain)
        Write-Host "  [SUBDOMAIN] $Domain" -ForegroundColor Cyan
        $raw = Invoke-THCRequest -Endpoint "sb/$Domain"

        $subs = if ($raw.Success) { $raw.Data } else { @() }

        # Keyword filter
        if ($script:KeywordList.Count -gt 0) {
            $subs = $subs | Where-Object {
                $s = $_.ToLower()
                $script:KeywordList | Where-Object { $s -like "*$_*" } | Select-Object -First 1
            }
        }

        # VT enrichment on first 5 unique domains
        $enriched = [System.Collections.Generic.List[PSCustomObject]]::new()
        $vtCount  = 0
        foreach ($s in $subs) {
            $vt = if ($vtCount -lt 5) { $vtCount++; Get-VTReputation -Domain $s } else { $null }
            $enriched.Add([PSCustomObject]@{ Subdomain = $s; VT = $vt })
        }

        $result = [PSCustomObject]@{
            Type       = 'SUBDOMAIN'
            Target     = $Domain
            Subdomains = $enriched
            Count      = $enriched.Count
            Success    = $raw.Success
            Error      = $raw.Error
            Keywords   = $script:KeywordList -join ','
            Timestamp  = Get-Date -Format 'o'
            MitreTTP   = 'T1596.001'
        }
        Write-WazuhEvent -EventType 'SUBDOMAIN_RESULT' -TargetValue $Domain -MitreId 'T1596.001' `
            -Data @{ count = $enriched.Count; keywords = $result.Keywords
                     subdomains = @($enriched | Select-Object -Expand Subdomain) }
        return $result
    }

    function Invoke-CnameLookup {
        param([string]$Domain)
        Write-Host "  [CNAME   ] $Domain" -ForegroundColor Cyan
        $raw = Invoke-THCRequest -Endpoint "cn/$Domain"

        $cnames   = if ($raw.Success) { $raw.Data } else { @() }
        $dangling = $cnames | Where-Object {
            $c = $_
            $TAKEOVER_PATTERNS | Where-Object { $c -match $_ } | Select-Object -First 1
        }

        if ($dangling) {
            Write-Host "  [!] TAKEOVER RISK detected: $($dangling -join ', ')" -ForegroundColor Red
        }

        $result = [PSCustomObject]@{
            Type           = 'CNAME'
            Target         = $Domain
            CNAMEs         = $cnames
            DanglingCNAMEs = @($dangling)
            TakeoverRisk   = ($null -ne $dangling -and @($dangling).Count -gt 0)
            Count          = $cnames.Count
            Success        = $raw.Success
            Error          = $raw.Error
            Timestamp      = Get-Date -Format 'o'
            MitreTTP       = 'T1590.004'
        }
        Write-WazuhEvent -EventType 'CNAME_RESULT' -TargetValue $Domain -MitreId 'T1590.004' `
            -Data @{ count = $cnames.Count; takeover_risk = $result.TakeoverRisk
                     dangling_cnames = @($dangling) }
        return $result
    }

    function Invoke-SubnetScan {
        param([string]$Subnet)
        Write-Host "  [SUBNET  ] $Subnet" -ForegroundColor Cyan
        $raw = Invoke-THCRequest -Endpoint $Subnet
        $result = [PSCustomObject]@{
            Type      = 'SUBNET'
            Target    = $Subnet
            Hosts     = if ($raw.Success) { $raw.Data } else { @() }
            Count     = $raw.Count
            Success   = $raw.Success
            Error     = $raw.Error
            Timestamp = Get-Date -Format 'o'
            MitreTTP  = 'T1590.004'
        }
        Write-WazuhEvent -EventType 'SUBNET_RESULT' -TargetValue $Subnet -MitreId 'T1590.004' `
            -Data @{ count = $raw.Count }
        return $result
    }

    function Invoke-ScalpelTarget {
        param([string]$TargetValue, [string]$OpType)
        $script:OpsecState.TargetCount++
        $opsec = Measure-OpsecFootprint

        $riskColor = switch ($opsec.RiskLevel) {
            'LOW'      { 'Green' }
            'MEDIUM'   { 'Yellow' }
            'HIGH'     { 'DarkYellow' }
            'CRITICAL' { 'Red' }
        }
        Write-Host "  [OPSEC:$($opsec.RiskLevel.PadRight(8))] Score=$($opsec.Score) | Req/min=$($opsec.ReqPerMin)" `
            -ForegroundColor $riskColor

        $r = switch ($OpType.ToLower()) {
            'rdns'      { Invoke-ReverseDNS    -IP     $TargetValue }
            'subdomain' { Invoke-SubdomainEnum -Domain $TargetValue }
            'cname'     { Invoke-CnameLookup   -Domain $TargetValue }
            'subnet'    { Invoke-SubnetScan    -Subnet $TargetValue }
        }

        if ($r) {
            $script:AllResults.Add($r)
            $script:OpsecState.ResultCount += $r.Count
        }
    }
    #endregion

    #region ── HTML Report Generator ────────────────────────────────────────────
    function New-HBVHtmlReport {
        param(
            [PSCustomObject[]]$Results,
            [PSCustomObject]$Opsec,
            [string]$OutPath
        )

        $ts            = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        $totalFindings = ($Results | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
        $takeoverCount = ($Results | Where-Object { $_.TakeoverRisk }).Count
        $duration      = [int](Get-Date).Subtract($script:OpsecState.SessionStart).TotalSeconds
        $riskColor     = switch ($Opsec.RiskLevel) {
            'LOW'      { '#00ff88' }
            'MEDIUM'   { '#ffd700' }
            'HIGH'     { '#ff8800' }
            'CRITICAL' { '#ff0055' }
        }

        $rowsHtml = foreach ($r in $Results) {
            $icon = switch ($r.Type) {
                'RDNS'      { '🔍' }
                'SUBDOMAIN' { '🌐' }
                'CNAME'     { '🔗' }
                'SUBNET'    { '📡' }
                default     { '•' }
            }
            $itemsHtml = ''
            switch ($r.Type) {
                'SUBDOMAIN' {
                    foreach ($item in $r.Subdomains) {
                        $vtBadge = ''
                        if ($item.VT) {
                            $c = if ($item.VT.Malicious -gt 0) { '#ff0055' } `
                                 elseif ($item.VT.Suspicious -gt 0) { '#ffd700' } `
                                 else { '#00ff88' }
                            $vtBadge = "<span class='badge' style='background:$c;color:#000'>VT:$($item.VT.VTScore)</span>"
                        }
                        $itemsHtml += "<li>$($item.Subdomain) $vtBadge</li>"
                    }
                }
                'CNAME' {
                    foreach ($c in $r.CNAMEs) {
                        $db = if ($r.DanglingCNAMEs -contains $c) {
                            "<span class='badge' style='background:#ff0055;color:#fff'>⚠ TAKEOVER</span>"
                        } else { '' }
                        $itemsHtml += "<li>$c $db</li>"
                    }
                }
                'RDNS'   { foreach ($h in $r.Hostnames) { $itemsHtml += "<li>$h</li>" } }
                'SUBNET' { foreach ($h in $r.Hosts)     { $itemsHtml += "<li>$h</li>" } }
            }
            $kwLabel = if ($r.Keywords) { "<small class='kw'>Filter: $($r.Keywords)</small>" } else { '' }
@"
<div class="card">
  <div class="card-head">
    <span class="type-badge">$icon $($r.Type)</span>
    <span class="target">$($r.Target)</span>
    <span class="count-badge">$($r.Count) findings</span>
    <span class="mitre-badge">$($r.MitreTTP)</span>
    <span class="ts-sm">$($r.Timestamp)</span>
  </div>
  $kwLabel
  <ul class="findings">$itemsHtml</ul>
</div>
"@
        }

        $html = @"
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>THC Scalpel | HBV Recon Report</title>
<style>
:root{--bg:#0a0a0f;--panel:#111118;--border:#1e1e2e;--cyan:#00d4ff;--green:#00ff88;
--red:#ff0055;--gold:#ffd700;--text:#c0c0d0;--dim:#666680;--font:'Courier New',monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:13px}
header{background:linear-gradient(135deg,#0d0d1a,#1a0d2e);border-bottom:1px solid var(--cyan);
  padding:20px 30px;display:flex;align-items:center;gap:20px}
.logo{font-size:22px;color:var(--cyan);font-weight:bold;letter-spacing:3px}
.sub{color:var(--dim);font-size:11px;margin-top:4px}
.hdr-right{margin-left:auto;text-align:right;font-size:11px;color:var(--dim)}
.hdr-right a{color:var(--cyan);text-decoration:none}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;padding:20px 30px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:14px;text-align:center}
.sv{font-size:26px;font-weight:bold;color:var(--cyan)}
.sl{color:var(--dim);font-size:11px;margin-top:4px;text-transform:uppercase}
.opsec{margin:0 30px 20px;background:var(--panel);border:1px solid var(--border);
  border-radius:6px;padding:14px}
.opsec-title{color:var(--dim);font-size:11px;text-transform:uppercase;margin-bottom:8px}
.bar-track{background:#1a1a2e;border-radius:4px;height:14px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;background:$riskColor;width:$($Opsec.Score)%}
.opsec-meta{display:flex;justify-content:space-between;margin-top:6px;color:var(--dim);font-size:11px}
.rl{color:$riskColor;font-weight:bold}
.mitre{margin:0 30px 20px;padding:10px 14px;background:#0f0f1f;border:1px solid #2a1a4e;
  border-radius:6px;font-size:11px;color:var(--dim)}
.mitre span{color:#9d7aff;margin-right:16px}
.results{padding:0 30px 30px}
.sec-title{color:var(--cyan);font-size:13px;text-transform:uppercase;letter-spacing:2px;
  border-bottom:1px solid var(--border);padding-bottom:8px;margin-bottom:14px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:6px;margin-bottom:12px}
.card-head{background:#0f0f1f;padding:10px 14px;display:flex;flex-wrap:wrap;align-items:center;
  gap:10px;border-bottom:1px solid var(--border)}
.type-badge{background:#1a2a3a;color:var(--cyan);padding:2px 8px;border-radius:3px;
  font-size:11px;border:1px solid var(--cyan)}
.target{color:#fff;font-weight:bold;font-size:14px;flex:1}
.count-badge{background:#1a3a1a;color:var(--green);padding:2px 8px;border-radius:3px;font-size:11px}
.mitre-badge{background:#2a1a4e;color:#9d7aff;padding:2px 8px;border-radius:3px;font-size:10px}
.ts-sm{color:var(--dim);font-size:10px;margin-left:auto}
.kw{display:block;padding:4px 14px;color:var(--dim);font-size:11px}
.findings{list-style:none;padding:10px 14px;columns:2;column-gap:20px}
.findings li{padding:3px 0;border-bottom:1px solid #1a1a2a;font-size:12px;break-inside:avoid}
.findings li:last-child{border-bottom:none}
.badge{display:inline-block;padding:1px 6px;border-radius:3px;font-size:10px;
  margin-left:6px;font-weight:bold}
footer{text-align:center;padding:20px;color:var(--dim);font-size:11px;
  border-top:1px solid var(--border)}
footer a{color:var(--cyan);text-decoration:none}
</style></head><body>
<header>
  <div>
    <div class="logo">🔪 THC SCALPEL</div>
    <div class="sub">HoneyBadger Vanguard Edition | Stealth Reconnaissance Toolkit</div>
  </div>
  <div class="hdr-right">
    Powered by <a href="https://ip.thc.org">ip.thc.org</a><br>
    Generated: $ts
  </div>
</header>
<div class="grid">
  <div class="stat"><div class="sv">$($Results.Count)</div><div class="sl">Queries Run</div></div>
  <div class="stat"><div class="sv">$totalFindings</div><div class="sl">Total Findings</div></div>
  <div class="stat"><div class="sv" style="color:$(if($takeoverCount -gt 0){'#ff0055'}else{'#00ff88'})">$takeoverCount</div><div class="sl">Takeover Risks</div></div>
  <div class="stat"><div class="sv">$($Opsec.TotalReqs)</div><div class="sl">API Requests</div></div>
  <div class="stat"><div class="sv">$($Opsec.ReqPerMin)</div><div class="sl">Req/min</div></div>
  <div class="stat"><div class="sv">${duration}s</div><div class="sl">Duration</div></div>
</div>
<div class="opsec">
  <div class="opsec-title">⚡ OPSEC Footprint Score</div>
  <div class="bar-track"><div class="bar-fill"></div></div>
  <div class="opsec-meta">
    <span>Score: <span class="rl">$($Opsec.Score)/100</span></span>
    <span>Risk: <span class="rl">$($Opsec.RiskLevel)</span></span>
    <span>Stealth: $(if($script:OpsecState.StealthMode){'✅ ON'}else{'❌ OFF'})</span>
    <span>Failed Reqs: $($Opsec.FailedReqs)</span>
  </div>
</div>
<div class="mitre">
  <strong style="color:#9d7aff">MITRE ATT&amp;CK</strong> &nbsp;|&nbsp;
  <span>T1590.002 — DNS Recon</span>
  <span>T1590.004 — Network Topology</span>
  <span>T1596.001 — Passive DNS</span>
</div>
<div class="results">
  <div class="sec-title">Reconnaissance Results</div>
  $($rowsHtml -join "`n")
</div>
<footer>
  THC Scalpel HBV Fork v$HBV_VERSION &nbsp;|&nbsp;
  Original: <a href="https://github.com/Hackteam-Red/thc-scalpel">hackteam.red / KL3FT3Z</a> &nbsp;|&nbsp;
  HBV Fork: <a href="https://ihbv.io">ihbv.io</a> &nbsp;|&nbsp;
  Authorized use only.
</footer></body></html>
"@
        $html | Out-File -FilePath $OutPath -Encoding UTF8
        Write-Host "  [REPORT] HTML report saved: $OutPath" -ForegroundColor Green
    }
    #endregion
}

process {
    if ($Target) { $script:PipelineInputs.Add($Target) }
}

end {
    #region ── Build Target List ─────────────────────────────────────────────
    $targets = [System.Collections.Generic.List[string]]::new()
    foreach ($t in $script:PipelineInputs) { $targets.Add($t) }
    if ($InputFile -and (Test-Path $InputFile)) {
        Get-Content $InputFile |
            Where-Object { $_ -match '\S' -and -not $_.TrimStart().StartsWith('#') } |
            ForEach-Object { $targets.Add($_.Trim()) }
    }

    if ($targets.Count -eq 0) {
        Write-Error "No targets provided. Use -Target, -InputFile, or pipeline input."
        return
    }

    Write-Host "`n  [*] Targets: $($targets.Count)  |  Type: $Type  |  Threads: $(if($Stealth){1}else{$Threads})  |  Keywords: $(if($script:KeywordList){"'$($script:KeywordList -join ',')'"}else{'none'})" -ForegroundColor Cyan
    Write-Host "  ──────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    #endregion

    #region ── Execute ───────────────────────────────────────────────────────
    $effectiveThreads = if ($Stealth) { 1 } else { $Threads }
    if ($effectiveThreads -gt 1 -and $targets.Count -gt 1) {
        $targets | ForEach-Object -Parallel {
            # Pull needed items into parallel scope
            $fn      = ${function:Invoke-ScalpelTarget}
            $opType  = $using:Type
            & $fn -TargetValue $_ -OpType $opType
        } -ThrottleLimit $effectiveThreads
    }
    else {
        foreach ($t in $targets) { Invoke-ScalpelTarget -TargetValue $t -OpType $Type }
    }
    #endregion

    #region ── OPSEC Summary ─────────────────────────────────────────────────
    $finalOpsec = Measure-OpsecFootprint
    $duration   = [int](Get-Date).Subtract($script:OpsecState.SessionStart).TotalSeconds
    $riskColor  = switch ($finalOpsec.RiskLevel) {
        'LOW'      { 'Green' }; 'MEDIUM' { 'Yellow' }; 'HIGH' { 'DarkYellow' }; default { 'Red' }
    }

    Write-Host "`n  ──────────────────────────────────────────────────────────" -ForegroundColor DarkGray
    Write-Host "  [OPSEC SUMMARY]" -ForegroundColor Cyan
    Write-Host "    Footprint  : $($finalOpsec.Score)/100  [$($finalOpsec.RiskLevel)]" -ForegroundColor $riskColor
    Write-Host "    Requests   : $($finalOpsec.TotalReqs) total, $($finalOpsec.FailedReqs) failed" -ForegroundColor Gray
    Write-Host "    Findings   : $($script:OpsecState.ResultCount) total" -ForegroundColor Gray
    Write-Host "    Duration   : ${duration}s" -ForegroundColor Gray
    #endregion

    #region ── Export: JSON / CSV / XML ──────────────────────────────────────
    $resultsArray = @($script:AllResults)
    if ($OutputFile) {
        $ext = [System.IO.Path]::GetExtension($OutputFile).ToLower()
        switch ($ext) {
            '.csv'  { $resultsArray | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8 }
            '.xml'  { $resultsArray | Export-Clixml -Path $OutputFile }
            default { $resultsArray | ConvertTo-Json -Depth 8 | Out-File $OutputFile -Encoding UTF8 }
        }
        Write-Host "  [OUTPUT] Saved: $OutputFile" -ForegroundColor Green
    }
    #endregion

    #region ── Export: Wazuh NDJSON ──────────────────────────────────────────
    if (-not $NoWazuh -and $script:WazuhEvents.Count -gt 0) {
        $script:WazuhEvents |
            ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 5 } |
            Out-File -FilePath $WazuhLogFile -Encoding UTF8 -Append
        Write-Host "  [WAZUH]  $($script:WazuhEvents.Count) events appended → $WazuhLogFile" -ForegroundColor DarkCyan
    }
    #endregion

    #region ── Export: HTML Report ───────────────────────────────────────────
    if ($ReportFile) {
        New-HBVHtmlReport -Results $resultsArray -Opsec $finalOpsec -OutPath $ReportFile
    }
    #endregion

    Write-Host "`n  [+] Reconnaissance complete.`n" -ForegroundColor Green

    # Return structured objects for pipeline chaining
    return $resultsArray
}
