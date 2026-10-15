# Build the self-hosted recon tool images (tools/*/Dockerfile).
# These tools have no reliable public image, so we build them locally and the
# worker (which shares the host Docker socket) runs them by tag.
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$tools = @(
    @{ name = "assetfinder"; tag = "recon/assetfinder:latest" },
    @{ name = "waybackurls"; tag = "recon/waybackurls:latest" },
    @{ name = "ct";          tag = "recon/ct:latest" },
    @{ name = "sublist3r";   tag = "recon/sublist3r:latest" },
    @{ name = "findomain";   tag = "recon/findomain:latest" },
    @{ name = "domainaudit"; tag = "recon/domainaudit:latest" },
    @{ name = "takeover";    tag = "recon/takeover:latest" },
    @{ name = "nuclei";      tag = "recon/nuclei:latest" },
    @{ name = "sqlmap";      tag = "recon/sqlmap:latest" },
    @{ name = "jsrecon";     tag = "recon/jsrecon:latest" },
    @{ name = "openredirect";tag = "recon/openredirect:latest" }
)

Write-Host "==> Building $($tools.Count) tool image(s)"
foreach ($tool in $tools) {
    Write-Host "==> Building $($tool.name) -> $($tool.tag) ..."
    docker build -t $tool.tag "tools/$($tool.name)"
    if ($LASTEXITCODE -ne 0) { throw "build failed for $($tool.name)" }
}

Write-Host "==> All tool images built."
