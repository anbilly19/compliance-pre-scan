<#
.SYNOPSIS
    Smoke-tests the compliance-pre-scan API against the running local server.

.DESCRIPTION
    Creates synthetic test files in a temp directory, POSTs each to /scan,
    checks the expected HTTP status code and decision field, then fetches
    the audit trail and exports a Betriebsrat CSV.

    Assumes the server is already running on $BaseUrl (default: http://localhost:8000).

.PARAMETER BaseUrl
    Base URL of the compliance-pre-scan server. Default: http://localhost:8000

.PARAMETER UserId
    user_id sent with each scan request. Default: smoke-test

.EXAMPLE
    .\scripts\smoke_test.ps1
    .\scripts\smoke_test.ps1 -BaseUrl http://localhost:8080
#>

param(
    [string]$BaseUrl = "http://localhost:8000",
    [string]$UserId  = "smoke-test"
)

$ErrorActionPreference = "Stop"

# ── colour helpers ────────────────────────────────────────────────────────────
function Pass($msg) { Write-Host "  [PASS] $msg" -ForegroundColor Green }
function Fail($msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function Info($msg) { Write-Host "  [INFO] $msg" -ForegroundColor Cyan }
function Head($msg) { Write-Host "`n=== $msg ===" -ForegroundColor Yellow }

# ── check server is up ────────────────────────────────────────────────────────
Head "Checking server at $BaseUrl"
try {
    $ping = Invoke-RestMethod "$BaseUrl/docs" -Method Get -ErrorAction Stop
    Info "Server is reachable"
} catch {
    # /docs may redirect; a 404 still means the server is up
    if ($_.Exception.Response.StatusCode.value__ -lt 500) {
        Info "Server is reachable (got $($_.Exception.Response.StatusCode))"
    } else {
        Fail "Cannot reach $BaseUrl — is the server running?"
        exit 1
    }
}

# ── temp directory for synthetic files ───────────────────────────────────────
$TmpDir = Join-Path $env:TEMP "compliance_smoke_$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir | Out-Null
Info "Temp files in $TmpDir"

$PassCount = 0
$FailCount = 0

# ── helper: POST /scan and return parsed body + status code ──────────────────
function Invoke-Scan {
    param([string]$FilePath, [string]$FileName = "")
    if (-not $FileName) { $FileName = Split-Path $FilePath -Leaf }

    $fileBytes    = [System.IO.File]::ReadAllBytes($FilePath)
    $boundary     = [System.Guid]::NewGuid().ToString("N")
    $CRLF         = "`r`n"

    $bodyParts  = "--$boundary$CRLF"
    $bodyParts += "Content-Disposition: form-data; name=`"user_id`"$CRLF$CRLF$UserId$CRLF"
    $bodyParts += "--$boundary$CRLF"
    $bodyParts += "Content-Disposition: form-data; name=`"session_id`"$CRLF$CRLFsmoke-session$CRLF"
    $bodyParts += "--$boundary$CRLF"
    $bodyParts += "Content-Disposition: form-data; name=`"file`"; filename=`"$FileName`"$CRLF"
    $bodyParts += "Content-Type: application/octet-stream$CRLF$CRLF"

    $encoding   = [System.Text.Encoding]::Latin1
    $headerBytes = $encoding.GetBytes($bodyParts)
    $footerBytes = $encoding.GetBytes("$CRLF--$boundary--$CRLF")
    $body        = $headerBytes + $fileBytes + $footerBytes

    try {
        $resp = Invoke-WebRequest `
            -Uri "$BaseUrl/scan" `
            -Method Post `
            -ContentType "multipart/form-data; boundary=$boundary" `
            -Body $body `
            -ErrorAction Stop
        return @{ Status = $resp.StatusCode; Body = ($resp.Content | ConvertFrom-Json) }
    } catch {
        $status = $_.Exception.Response.StatusCode.value__
        $raw    = $_.ErrorDetails.Message
        try   { $parsed = $raw | ConvertFrom-Json } catch { $parsed = @{ detail = $raw } }
        return @{ Status = $status; Body = $parsed }
    }
}

function Assert-Scan {
    param(
        [string]$Label,
        [string]$FilePath,
        [int]   $ExpectedStatus,
        [string]$ExpectedDecision,
        [string]$FileName = ""
    )

    $r = Invoke-Scan -FilePath $FilePath -FileName $FileName
    $ok = ($r.Status -eq $ExpectedStatus) -and ($r.Body.decision -eq $ExpectedDecision)

    if ($ok) {
        Pass "$Label  →  HTTP $($r.Status)  decision=$($r.Body.decision)"
        $script:PassCount++
    } else {
        Fail "$Label  →  got HTTP $($r.Status) decision=$($r.Body.decision)  (expected $ExpectedStatus / $ExpectedDecision)"
        if ($r.Body.detail) { Info "    detail: $($r.Body.detail)" }
        $script:FailCount++
    }

    # Print hit summary when available
    $hits = @()
    if ($r.Body.pii_matches)     { $hits += "pii=$($r.Body.pii_matches.Count)" }
    if ($r.Body.secret_matches)  { $hits += "secrets=$($r.Body.secret_matches.Count)" }
    if ($r.Body.keyword_matches) { $hits += "keywords=$($r.Body.keyword_matches.Count)" }
    if ($r.Body.anomaly_matches) { $hits += "anomalies=$($r.Body.anomaly_matches.Count)" }
    if ($hits) { Info "    hits: $($hits -join '  ')" }
}

# ── scenario 1: clean text file ───────────────────────────────────────────────
Head "Scenario 1 — Clean text file (expect 200 ALLOW or ALLOW_WITH_WARNING)"
$f = Join-Path $TmpDir "clean.txt"
Set-Content $f "Meeting notes from 2024-06-01. Nothing sensitive here. Agenda: sprint review."

$r = Invoke-Scan -FilePath $f
if ($r.Status -eq 200 -and $r.Body.decision -in @("ALLOW","ALLOW_WITH_WARNING")) {
    Pass "Clean file  →  HTTP $($r.Status)  decision=$($r.Body.decision)"
    $PassCount++
} else {
    Fail "Clean file  →  got HTTP $($r.Status) decision=$($r.Body.decision)"
    $FailCount++
}

# ── scenario 2: AWS key → BLOCK ───────────────────────────────────────────────
Head "Scenario 2 — File with AWS key (expect 451 BLOCK)"
$f = Join-Path $TmpDir "secrets.txt"
Set-Content $f "Config dump:`nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
Assert-Scan "AWS key file" $f 451 "BLOCK"

# ── scenario 3: PII — CV-style text ──────────────────────────────────────────
Head "Scenario 3 — PII: CV-style text (expect 200 ALLOW_WITH_WARNING)"
$f = Join-Path $TmpDir "cv.txt"
Set-Content $f @"
Max Mustermann
Musterstraße 1, 12345 Berlin
Tel: +49 30 12345678
E-Mail: max.mustermann@example.de
Geburtsdatum: 01.01.1985
IBAN: DE89 3704 0044 0532 0130 00
"@
Assert-Scan "CV / PII file" $f 200 "ALLOW_WITH_WARNING"

# ── scenario 4: Betriebsrat keywords ─────────────────────────────────────────
Head "Scenario 4 — Betriebsrat keywords (expect 200 ALLOW_WITH_WARNING)"
$f = Join-Path $TmpDir "betriebsrat.txt"
Set-Content $f "Betreff: Betriebsrat-Sitzung - Personalakte Mitarbeiter XY - Abmahnung und Kuendigung gemaess Betriebsverfassungsgesetz."
Assert-Scan "Betriebsrat memo" $f 200 "ALLOW_WITH_WARNING"

# ── scenario 5: JWT token ─────────────────────────────────────────────────────
Head "Scenario 5 — JWT token in config (expect 451 BLOCK)"
$f = Join-Path $TmpDir "jwt.txt"
Set-Content $f "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
Assert-Scan "JWT token" $f 451 "BLOCK"

# ── scenario 6: extension mismatch (rename exe → pdf) ────────────────────────
Head "Scenario 6 — Extension mismatch: EXE renamed to PDF (expect 451 BLOCK)"
$exe = "$env:SystemRoot\System32\find.exe"
$f   = Join-Path $TmpDir "invoice.pdf"
Copy-Item $exe $f
Assert-Scan "Fake PDF (EXE)" $f 451 "BLOCK" -FileName "invoice.pdf"

# ── scenario 7: unsupported file type ────────────────────────────────────────
Head "Scenario 7 — Unsupported file type .mp4 (expect 415)"
$f = Join-Path $TmpDir "video.mp4"
Set-Content $f "not a real video"
$r = Invoke-Scan -FilePath $f -FileName "video.mp4"
if ($r.Status -eq 415) {
    Pass "Unsupported type  →  HTTP 415"
    $PassCount++
} else {
    Fail "Unsupported type  →  got HTTP $($r.Status)  (expected 415)"
    $FailCount++
}

# ── scenario 8: zip bomb (nested zips) ───────────────────────────────────────
Head "Scenario 8 — Archive bomb: deeply nested ZIP (expect 451 BLOCK)"
Add-Type -AssemblyName System.IO.Compression.FileSystem
# Build 4 levels deep: level4.zip inside level3.zip inside level2.zip inside level1.zip
$z4 = Join-Path $TmpDir "level4.zip"
$z3 = Join-Path $TmpDir "level3.zip"
$z2 = Join-Path $TmpDir "level2.zip"
$z1 = Join-Path $TmpDir "bomb.zip"
$inner = Join-Path $TmpDir "inner.txt"
Set-Content $inner "payload"

function New-ZipWithFile($zipPath, $filePath) {
    if (Test-Path $zipPath) { Remove-Item $zipPath }
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, 'Create')
    [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $filePath, (Split-Path $filePath -Leaf)) | Out-Null
    $zip.Dispose()
}
New-ZipWithFile $z4 $inner
New-ZipWithFile $z3 $z4
New-ZipWithFile $z2 $z3
New-ZipWithFile $z1 $z2

Assert-Scan "ZIP bomb (4 levels)" $z1 451 "BLOCK" -FileName "bomb.zip"

# ── audit trail ──────────────────────────────────────────────────────────────
Head "Audit trail (last 20 events)"
try {
    $events = Invoke-RestMethod "$BaseUrl/events?limit=20" -Method Get
    Info "Total events returned: $($events.Count)"
    $events | ForEach-Object {
        $line = "  $($_.timestamp)  $($_.filename.PadRight(25))  $($_.decision.PadRight(20))  risk=$($_.risk_level)"
        Write-Host $line
    }
} catch {
    Fail "Could not fetch audit trail: $_"
}

# ── Betriebsrat CSV export ────────────────────────────────────────────────────
Head "Betriebsrat CSV export"
$csvPath = Join-Path $TmpDir "audit_export.csv"
try {
    Invoke-WebRequest "$BaseUrl/events/export" -OutFile $csvPath -ErrorAction Stop
    $lines = (Get-Content $csvPath).Count
    Pass "CSV exported to $csvPath  ($lines lines)"
} catch {
    Fail "CSV export failed: $_"
}

# ── summary ───────────────────────────────────────────────────────────────────
Head "Results"
Write-Host "  Passed: $PassCount" -ForegroundColor Green
Write-Host "  Failed: $FailCount" -ForegroundColor $(if ($FailCount -gt 0) { "Red" } else { "Green" })
Write-Host "  Temp files: $TmpDir"
Write-Host "  CSV export: $csvPath"
Write-Host ""

if ($FailCount -gt 0) { exit 1 } else { exit 0 }
