# ==============================================================================
# Local Docker Build & GHCR Push Script
# Usage:
#   .\scripts\build_and_push.ps1                          # Dev: AMD64 only
#   .\scripts\build_and_push.ps1 -Production              # Prod: AMD64 + ARM64
#   .\scripts\build_and_push.ps1 -Production -Tag v8.0.0  # Prod: tagged release
# Authoritative Contract: contracts/08 Section 10.4
# ==============================================================================
param(
    [switch]$Production,
    [string]$Tag = ""
)

$Registry = "ghcr.io"
$ImageName = "andresslacson1989/security-assessment-platform"
$FullImage = "$Registry/$ImageName"

# 1. Load GitHub PAT from F:\gh.txt
$ghPath = "F:\gh.txt"
if (!(Test-Path $ghPath)) {
    Write-Error "GitHub credentials not found at $ghPath"
    exit 1
}
$ghLines = Get-Content $ghPath
$ghToken = ""
foreach ($line in $ghLines) {
    if ($line -match "^(ghp_|github_pat_)[A-Za-z0-9_]+") {
        $ghToken = $matches[0]
        break
    }
    if ($line -match "Access token:\s*(.+)") {
        $ghToken = $matches[1].Trim()
        break
    }
}
if (-not $ghToken) {
    $ghToken = ($ghLines | Where-Object { $_ -match "^(ghp_|github_pat_)" } | Select-Object -First 1).Trim()
}
if (-not $ghToken) {
    Write-Error "Could not parse GitHub token from $ghPath"
    exit 1
}

# 2. Login to GHCR
Write-Host "Logging in to $Registry..." -ForegroundColor Cyan
$ghToken | docker login $Registry -u andresslacson1989 --password-stdin
if ($LASTEXITCODE -ne 0) { Write-Error "Docker login failed"; exit 1 }

# 3. Resolve commit SHA for tagging
$commitSha = (git rev-parse --short HEAD).Trim()
$platforms = if ($Production) { "linux/amd64,linux/arm64" } else { "linux/amd64" }

# 4. Build tags
$tags = @(
    "--tag", "$FullImage`:latest",
    "--tag", "$FullImage`:sha-$commitSha"
)
if ($Tag) {
    # Parse semver e.g. v8.0.0 -> also tag v8.0 and v8
    $tags += "--tag", "$FullImage`:$Tag"
    if ($Tag -match "^v?(\d+)\.(\d+)\.(\d+)$") {
        $tags += "--tag", "$FullImage`:v$($matches[1]).$($matches[2])"
        $tags += "--tag", "$FullImage`:v$($matches[1])"
    }
}

# 5. Ensure buildx builder is set up
docker buildx inspect cyberassess-builder --bootstrap 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Creating buildx builder 'cyberassess-builder'..." -ForegroundColor Yellow
    docker buildx create --name cyberassess-builder --driver docker-container --bootstrap --use
}
docker buildx use cyberassess-builder

# 6. Build & Push
$buildMode = if ($Production) { "PRODUCTION (AMD64 + ARM64)" } else { "DEVELOPMENT (AMD64)" }
Write-Host ""
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "  Building: $buildMode" -ForegroundColor Cyan
Write-Host "  Image:    $FullImage" -ForegroundColor Cyan
Write-Host "  Tags:     latest, sha-$commitSha$(if ($Tag) { ", $Tag" })" -ForegroundColor Cyan
Write-Host "  Platform: $platforms" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan
Write-Host ""

$buildArgs = @(
    "buildx", "build",
    "--platform", $platforms,
    "--push"
) + $tags + @(".")

docker @buildArgs
if ($LASTEXITCODE -ne 0) { Write-Error "Docker build failed!"; exit 1 }

Write-Host ""
Write-Host "Build & Push Complete!" -ForegroundColor Green
Write-Host "Image available at: $FullImage`:latest" -ForegroundColor Green
Write-Host "Pull command: docker pull $FullImage`:latest" -ForegroundColor Cyan
