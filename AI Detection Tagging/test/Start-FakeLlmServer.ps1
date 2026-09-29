<#
.SYNOPSIS
    Test helper: a fake OpenAI-compatible LLM server used to trigger the "Shadow-AI signals" section
    of the AI Detection Dashboard. It is a test aid only, not a real model server.

.DESCRIPTION
    Starts a local HTTP listener on 127.0.0.1:<Port> that answers every request with a static
    OpenAI-style model list. While it runs, Set-AiDetectionTag.ps1 detects it through the 'apiprobe'
    vector as "Local LLM server (OpenAI-compatible API, port <Port>)" - which appears under
    "Shadow-AI signals" in the dashboard, because the port is not tied to any catalog tool.

    Usage on a Windows test VM:
      1. Run this script and leave the window open.
      2. While it runs, run Set-AiDetectionTag.ps1 on the same device.
      3. Run Set-AiDashboard.ps1 - "Shadow-AI signals" now lists this device.
      4. Stop with Ctrl+C, then run the agent again to clear the signal.

    Default port 8000 is on the dashboard's probe list. Other free probe ports: 5000, 8080, 8081.
    The source is ASCII-only so Windows PowerShell 5.1 reads it correctly.

.EXAMPLE
    .\Start-FakeLlmServer.ps1

.EXAMPLE
    .\Start-FakeLlmServer.ps1 -Port 8081
#>
param([int]$Port = 8000)

$ErrorActionPreference = 'Stop'
$prefix = "http://127.0.0.1:$Port/"

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($prefix)

try {
    $listener.Start()
}
catch {
    Write-Host "ERROR: could not start the listener on $prefix"
    Write-Host "  $($_.Exception.Message)"
    Write-Host "  Fixes:"
    Write-Host "    - run PowerShell as Administrator, or"
    Write-Host "    - reserve the URL once:  netsh http add urlacl url=$prefix user=Everyone"
    Write-Host "    - or pick another probe port:  -Port 8081   (also 5000 / 8080)"
    exit 1
}

Write-Host "Fake OpenAI-compatible LLM server listening on $prefix"
Write-Host "Purpose: trigger the dashboard's 'Shadow-AI signals' (apiprobe vector)."
Write-Host "Next: run Set-AiDetectionTag.ps1 on this device, then Set-AiDashboard.ps1."
Write-Host "Press Ctrl+C to stop."
Write-Host ""

# OpenAI /v1/models shape. The dashboard's apiprobe checks /api/tags first (looks for a 'models'
# property - absent here), then /v1/models (object == 'list' or a 'data' property - present here).
$body = '{"object":"list","data":[{"id":"shadow-ai-test-model","object":"model","owned_by":"fake-llm-server"}]}'
$bytes = [Text.Encoding]::UTF8.GetBytes($body)

try {
    while ($listener.IsListening) {
        # Poll asynchronously so Ctrl+C stays responsive instead of blocking on GetContext()
        $task = $listener.GetContextAsync()
        while (-not $task.Wait(200)) { }
        $context = $task.Result

        $method = $context.Request.HttpMethod
        $url = $context.Request.RawUrl
        try {
            $context.Response.StatusCode = 200
            $context.Response.ContentType = 'application/json'
            $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        }
        catch { }
        finally { $context.Response.Close() }

        Write-Host ("  {0}  {1} {2}" -f (Get-Date -Format 'HH:mm:ss'), $method, $url)
    }
}
finally {
    $listener.Stop()
    $listener.Close()
    Write-Host ""
    Write-Host "Server stopped."
}
