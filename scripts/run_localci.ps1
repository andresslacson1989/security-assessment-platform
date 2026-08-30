# ==============================================================================
# LocalCI Job Trigger & Log Streaming Script
# Usage: .\scripts\run_localci.ps1 [-Branch main] [-Pipeline python313]
# ==============================================================================
param(
    [string]$Branch = "main",
    [string]$Pipeline = "python313",
    [string]$Repo = "andresslacson1989/security-assessment-platform"
)

# 1. Load Cloudflare Access Credentials
$cfPath = "F:\cf.txt"
if (!(Test-Path $cfPath)) {
    Write-Error "Credentials file $cfPath not found."
    exit 1
}

$cfLines = Get-Content $cfPath
$clientId = ""
$clientSecret = ""
foreach ($line in $cfLines) {
    if ($line -match "CF-Access-Client-Id:\s*(.+)") { $clientId = $matches[1].Trim().Trim('`') }
    if ($line -match "CF-Access-Client-Secret:\s*(.+)") { $clientSecret = $matches[1].Trim().Trim('`') }
    if ($line -match "^([a-f0-9]{32,})\s*$") { if (-not $clientId) { $clientId = $matches[1] } else { $clientSecret = $matches[1] } }
}

$headers = @{
    "CF-Access-Client-Id" = $clientId
    "CF-Access-Client-Secret" = $clientSecret
    "Content-Type" = "application/json"
    "Accept" = "application/json"
}

# 2. Submit Job
$idempotencyKey = "sec-platform-$(Get-Date -Format 'yyyyMMddHHmmss')"
$payload = @{
    repository = $Repo
    head_ref = "refs/heads/$Branch"
    pipeline_id = $Pipeline
    idempotency_key = $idempotencyKey
} | ConvertTo-Json

Write-Host "Submitting LocalCI Job for $Repo ($Branch) with pipeline $Pipeline..." -ForegroundColor Cyan
try {
    $job = Invoke-RestMethod -Uri "https://localci.pixelretrobooth.com/api/v1/jobs" -Method Post -Headers $headers -Body $payload
    $jobId = $job.id
    Write-Host "Job Submitted Successfully! Job ID: $jobId" -ForegroundColor Green
} catch {
    Write-Host "Failed to submit job: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.ErrorDetails) {
        Write-Host "Response: $($_.ErrorDetails.Message)" -ForegroundColor Yellow
    }
    Write-Host "`nNote: Ensure the repository '$Repo' is added in the LocalCI Admin Dashboard (https://localci.pixelretrobooth.com/dashboard)." -ForegroundColor Yellow
    exit 1
}

# 3. Poll Status & Stream Logs
Write-Host "Polling job status..." -ForegroundColor Cyan
$completed = $false
while (-not $completed) {
    Start-Sleep -Seconds 3
    $statusObj = Invoke-RestMethod -Uri "https://localci.pixelretrobooth.com/api/v1/jobs/$jobId" -Headers $headers
    $currentStatus = $statusObj.status
    $conclusion = $statusObj.conclusion
    Write-Host "Status: $currentStatus $(if ($conclusion) { "($conclusion)" })"

    if ($currentStatus -in @("completed", "failed")) {
        $completed = $true
        Write-Host "`n=== Final Container Logs ===" -ForegroundColor Cyan
        $logs = Invoke-RestMethod -Uri "https://localci.pixelretrobooth.com/api/v1/jobs/$jobId/logs" -Headers $headers
        Write-Host $logs.untrusted_log_text

        if ($conclusion -eq "success") {
            Write-Host "`nLocalCI Run PASSED (100% Verified)!" -ForegroundColor Green
            exit 0
        } else {
            Write-Host "`nLocalCI Run FAILED!" -ForegroundColor Red
            exit 1
        }
    }
}
