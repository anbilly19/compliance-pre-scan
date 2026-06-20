<#
.SYNOPSIS
    Smoke-tests the compliance-pre-scan API against the running local server.
.DESCRIPTION
    Creates synthetic test files in a temp directory, POSTs each to /scan,
    checks the expected HTTP status code and decision field, then fetches
    the audit trail and exports a Betriebsrat CSV.
    Requires PowerShell 7+ and a running server on $BaseUrl.
.PARAMETER BaseUrl
    Base URL of the server. Default: http://localhost:8000
.PARAMETER UserId
    user_id sent with each request. Default: smoke-test
.EXAMPLE
    .\scripts\smoke_test.ps1
    .\scripts\smoke_test.ps1 -BaseUrl http://localhost:8080
#>
param(
    [string]$BaseUrl = "http://localhost:8000",
    [string]$UserId  = "smoke-test"
)

$ErrorActionPreference = "Stop"

# ----------------------------------------------------------------
# colour helpers
# ----------------------------------------------------------------
function Pass($msg) { Write-Host "  [PASS] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function Info($msg) { Write-Host "  [INFO] $msg" -ForegroundColor Cyan }
function Head($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Yellow }

# ----------------------------------------------------------------
# check server is up
# ----------------------------------------------------------------
Head "Checking server at $BaseUrl"
try {
    $null = Invoke-WebRequest "$BaseUrl/docs" -Method Get -ErrorAction Stop
    Info "Server is reachable"
} catch {
    $code = $_.Exception.Response.StatusCode.value__
    if ($null -ne $code -and [int]$code -lt 500) {
        Info "Server reachable (got $code)"
    } else {
        Fail "Cannot reach $BaseUrl -- is the server running?"
        exit 1
    }
}

# ----------------------------------------------------------------
# temp directory
# ----------------------------------------------------------------
$TmpDir = Join-Path $env:TEMP ("compliance_smoke_" + (Get-Random))
New-Item -ItemType Directory -Path $TmpDir | Out-Null
Info "Temp files: $TmpDir"

$PassCount = 0
$FailCount = 0

# ----------------------------------------------------------------
# Invoke-Scan: POST a file to /scan using -Form (PS7 native multipart)
# Returns hashtable: { Status = int; Body = PSObject }
# ----------------------------------------------------------------
function Invoke-Scan {
    param(
        [string]$FilePath,
        [string]$FileName = ""
    )
    if (-not $FileName) { $FileName = Split-Path $FilePath -Leaf }

    $form = @{
        user_id    = $UserId
        session_id = "smoke-session"
        file       = Get-Item $FilePath
    }

    # Rename the FileInfo name seen by the server if FileName differs from actual name
    # by copying to a temp path with the desired name.
    if ($FileName -ne (Split-Path $FilePath -Leaf)) {
        $renamed = Join-Path (Split-Path $FilePath) $FileName
        Copy-Item $FilePath $renamed -Force
        $form.file = Get-Item $renamed
    }

    try {
        $resp = Invoke-RestMethod `
            -Uri "$BaseUrl/scan" `
            -Method Post `
            -Form $form `
            -StatusCodeVariable sc `
            -ErrorAction Stop
        return @{ Status = [int]$sc; Body = $resp }
    } catch {
        $status = [int]$_.Exception.Response.StatusCode.value__
        $raw    = $_.ErrorDetails.Message
        try   { $parsed = $raw | ConvertFrom-Json }
        catch { $parsed = [PSCustomObject]@{ detail = $raw } }
        return @{ Status = $status; Body = $parsed }
    }
}

# ----------------------------------------------------------------
# Assert-Scan: run one scenario, print PASS/FAIL + hit summary
# ----------------------------------------------------------------
function Assert-Scan {
    param(
        [string]$Label,
        [string]$FilePath,
        [int]   $ExpectedStatus,
        [string]$ExpectedDecision,
        [string]$FileName = ""
    )

    $r  = Invoke-Scan -FilePath $FilePath -FileName $FileName
    $ok = ($r.Status -eq $ExpectedStatus) -and ($r.Body.decision -eq $ExpectedDecision)

    $got = "HTTP " + $r.Status + "  decision=" + $r.Body.decision
    if ($ok) {
        Pass ($Label + "  ->  " + $got)
        $script:PassCount++
    } else {
        Fail ($Label + "  ->  got " + $got + "  (expected " + $ExpectedStatus + " / " + $ExpectedDecision + ")")
        if ($r.Body.detail) { Info ("    detail: " + $r.Body.detail) }
        $script:FailCount++
    }

    $hits = @()
    if ($r.Body.pii_matches     -and $r.Body.pii_matches.Count)     { $hits += "pii=" + $r.Body.pii_matches.Count }
    if ($r.Body.secret_matches  -and $r.Body.secret_matches.Count)  { $hits += "secrets=" + $r.Body.secret_matches.Count }
    if ($r.Body.keyword_matches -and $r.Body.keyword_matches.Count) { $hits += "keywords=" + $r.Body.keyword_matches.Count }
    if ($r.Body.anomaly_matches -and $r.Body.anomaly_matches.Count) { $hits += "anomalies=" + $r.Body.anomaly_matches.Count }
    if ($hits.Count -gt 0) { Info ("    hits: " + ($hits -join "  ")) }
}

# ================================================================
# Scenario 1 -- clean text file
# ================================================================
Head "Scenario 1 -- Clean text file (expect 200 ALLOW or ALLOW_WITH_WARNING)"
$f = Join-Path $TmpDir "clean.txt"
Set-Content $f "Meeting notes from 2024-06-01. Nothing sensitive here. Agenda: sprint review."
$r = Invoke-Scan -FilePath $f
if ($r.Status -eq 200 -and $r.Body.decision -in @("ALLOW", "ALLOW_WITH_WARNING")) {
    Pass ("Clean file  ->  HTTP " + $r.Status + "  decision=" + $r.Body.decision)
    $PassCount++
} else {
    Fail ("Clean file  ->  got HTTP " + $r.Status + "  decision=" + $r.Body.decision)
    $FailCount++
}

# ================================================================
# Scenario 2 -- AWS key -> BLOCK
# ================================================================
Head "Scenario 2 -- File with AWS key (expect 451 BLOCK)"
$f = Join-Path $TmpDir "secrets.txt"
Set-Content $f "Config dump:`nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
Assert-Scan -Label "AWS key file" -FilePath $f -ExpectedStatus 451 -ExpectedDecision "BLOCK"

# ================================================================
# Scenario 3 -- PII: CV-style text
# ================================================================
Head "Scenario 3 -- PII: CV-style text (expect 200 ALLOW_WITH_WARNING)"
$f = Join-Path $TmpDir "cv.txt"
@"
Max Mustermann
Musterstrasse 1, 12345 Berlin
Tel: +49 30 12345678
E-Mail: max.mustermann@example.de
Geburtsdatum: 01.01.1985
IBAN: DE89 3704 0044 0532 0130 00
"@ | Set-Content $f
Assert-Scan -Label "CV PII file" -FilePath $f -ExpectedStatus 200 -ExpectedDecision "ALLOW_WITH_WARNING"

# ================================================================
# Scenario 4 -- Betriebsrat keywords
# ================================================================
Head "Scenario 4 -- Betriebsrat keywords (expect 200 ALLOW_WITH_WARNING)"
$f = Join-Path $TmpDir "betriebsrat.txt"
Set-Content $f "Betreff: Betriebsrat-Sitzung - Personalakte Mitarbeiter XY - Abmahnung und Kuendigung."
Assert-Scan -Label "Betriebsrat memo" -FilePath $f -ExpectedStatus 200 -ExpectedDecision "ALLOW_WITH_WARNING"

# ================================================================
# Scenario 5 -- JWT token -> BLOCK
# ================================================================
Head "Scenario 5 -- JWT token (expect 451 BLOCK)"
$f = Join-Path $TmpDir "jwt.txt"
Set-Content $f "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
Assert-Scan -Label "JWT token" -FilePath $f -ExpectedStatus 451 -ExpectedDecision "BLOCK"

# ================================================================
# Scenario 6 -- extension mismatch: EXE renamed to PDF
# ================================================================
Head "Scenario 6 -- Extension mismatch: EXE renamed to PDF (expect 451 BLOCK)"
$src = "$env:SystemRoot\System32\find.exe"
$f   = Join-Path $TmpDir "invoice_real.exe"
Copy-Item $src $f
Assert-Scan -Label "Fake PDF (EXE)" -FilePath $f -ExpectedStatus 451 -ExpectedDecision "BLOCK" -FileName "invoice.pdf"

# ================================================================
# Scenario 7 -- unsupported file type (.mp4)
# ================================================================
Head "Scenario 7 -- Unsupported file type .mp4 (expect 415)"
$f = Join-Path $TmpDir "video.mp4"
Set-Content $f "not a real video"
$r = Invoke-Scan -FilePath $f -FileName "video.mp4"
if ($r.Status -eq 415) {
    Pass "Unsupported type  ->  HTTP 415"
    $PassCount++
} else {
    Fail ("Unsupported type  ->  got HTTP " + $r.Status + "  (expected 415)")
    $FailCount++
}

# ================================================================
# Scenario 8 -- archive bomb: nested ZIPs 4 levels deep
# ================================================================
Head "Scenario 8 -- Archive bomb: nested ZIP 4 levels deep (expect 451 BLOCK)"
Add-Type -AssemblyName System.IO.Compression.FileSystem

function New-ZipWith {
    param([string]$ZipPath, [string]$EntryPath)
    if (Test-Path $ZipPath) { Remove-Item $ZipPath }
    $zip = [System.IO.Compression.ZipFile]::Open($ZipPath, 'Create')
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
        $zip, $EntryPath, (Split-Path $EntryPath -Leaf)) | Out-Null
    $zip.Dispose()
}

$inner = Join-Path $TmpDir "inner.txt" ; Set-Content $inner "payload"
$z4    = Join-Path $TmpDir "level4.zip" ; New-ZipWith $z4 $inner
$z3    = Join-Path $TmpDir "level3.zip" ; New-ZipWith $z3 $z4
$z2    = Join-Path $TmpDir "level2.zip" ; New-ZipWith $z2 $z3
$z1    = Join-Path $TmpDir "bomb.zip"   ; New-ZipWith $z1 $z2

Assert-Scan -Label "ZIP bomb 4 levels" -FilePath $z1 -ExpectedStatus 451 -ExpectedDecision "BLOCK" -FileName "bomb.zip"

# ================================================================
# Audit trail
# ================================================================
Head "Audit trail (last 20 events)"
try {
    $events = Invoke-RestMethod "$BaseUrl/events?limit=20" -Method Get
    Info ("Total events: " + $events.Count)
    foreach ($e in $events) {
        Write-Host ("  " + $e.timestamp + "  " + $e.filename.PadRight(25) + "  " + $e.decision.PadRight(20) + "  risk=" + $e.risk_level)
    }
} catch {
    Fail ("Could not fetch audit trail: " + $_)
}

# ================================================================
# Betriebsrat CSV export
# ================================================================
Head "Betriebsrat CSV export"
$csvPath = Join-Path $TmpDir "audit_export.csv"
try {
    Invoke-WebRequest "$BaseUrl/events/export" -OutFile $csvPath -ErrorAction Stop
    $lineCount = (Get-Content $csvPath).Count
    Pass ("CSV saved to " + $csvPath + "  (" + $lineCount + " lines)")
} catch {
    Fail ("CSV export failed: " + $_)
}

# ================================================================
# Summary
# ================================================================
Head "Results"
Write-Host ("  Passed: " + $PassCount) -ForegroundColor Green
$failColor = if ($FailCount -gt 0) { "Red" } else { "Green" }
Write-Host ("  Failed: " + $FailCount) -ForegroundColor $failColor
Write-Host ("  Temp   : " + $TmpDir)
Write-Host ("  CSV    : " + $csvPath)
Write-Host ""

if ($FailCount -gt 0) { exit 1 } else { exit 0 }
