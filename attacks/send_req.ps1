# send_req
# 使用统一配置的版本

param(
    [string]$InputFile = "requests.jsonl",
    [string]$OutputFile = "responses.jsonl",
    [string]$reportFile="responses_report.jsonl",
    [int]$DelaySeconds = 1
)

Set-Location -Path $PSScriptRoot

# 加载配置文件
function Load-EnvFile {
    param([string]$EnvPath = "../.env")  # 从项目根目录读取
    
    if (-not (Test-Path $EnvPath)) {
        Write-Host "警告: .env 文件不存在，使用默认配置" -ForegroundColor Yellow
        return @{
            AUTH_SERVER_HOST = "127.0.0.1"
            AUTH_SERVER_PORT = "18001"
            GUARD_PROXY_HOST = "127.0.0.1"
            GUARD_PROXY_PORT = "18003"
        }
    }
    
    $config = @{}
    Get-Content $EnvPath | ForEach-Object {
        if ($_ -match '^([^#][^=]+)=(.*)$') {
            $key = $matches[1].Trim()
            $value = $matches[2].Trim()
            $config[$key] = $value
        }
    }
    return $config
}

$config = Load-EnvFile

$AUTH_URL = "http://$($config.AUTH_SERVER_HOST):$($config.AUTH_SERVER_PORT)/token"
$GUARD_URL = "http://$($config.GUARD_PROXY_HOST):$($config.GUARD_PROXY_PORT)/mcp"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Guard Proxy 批量请求工具" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Auth Server: $AUTH_URL" -ForegroundColor Gray
Write-Host "Guard Proxy: $GUARD_URL" -ForegroundColor Gray

# 检查输入文件
if (-not (Test-Path $InputFile)) {
    Write-Host "错误: 输入文件不存在: $InputFile" -ForegroundColor Red
    exit 1
}

# 读取请求
$requests = @()
$lines = Get-Content -Path $InputFile -Encoding UTF8

foreach ($line in $lines) {
    $trimmed = $line.Trim()
    if ($trimmed -ne "") {
        try {
            $req = $trimmed | ConvertFrom-Json
            $requests += $req
        }
        catch {
            Write-Host "解析失败: $trimmed" -ForegroundColor Red
        }
    }
}

$totalRequests = $requests.Count
Write-Host "加载了 $totalRequests 个请求" -ForegroundColor Green

if ($totalRequests -eq 0) {
    Write-Host "没有有效的请求，退出" -ForegroundColor Red
    exit 1
}

$results = @()
$successCount = 0
$index = 0

foreach ($req in $requests) {
    $index++
    Write-Host "`n[$index] $($req.name)" -ForegroundColor Yellow
    
    # 获取 Token（使用配置的 URL）
    $tokenBody = @{
        user_id = $req.auth.user_id
        session_id = "session-$($req.id)"
        scopes = $req.auth.scopes
    } | ConvertTo-Json -Compress
    
    try {
        $tokenResponse = Invoke-RestMethod -Uri $AUTH_URL `
            -Method Post -ContentType "application/json" -Body $tokenBody -ErrorAction Stop
        $token = $tokenResponse.access_token
        Write-Host "  Token 获取成功" -ForegroundColor Gray
    }
    catch {
        Write-Host "  Token 获取失败" -ForegroundColor Red
        $results += @{
            id = $req.id
            name = $req.name
            success = $false
            decision = "token_error"
            expected = $req.expected
            timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        continue
    }
    
    # 确定 source_label
    $sourceLabel = if ($req.request.source_label) { $req.request.source_label } else { "user" }
    
    # 构造请求
    $requestBody = @{
        jsonrpc = "2.0"
        id = 1
        method = "tools/call"
        params = @{
            intent = @{
                intent_id = "batch-$($req.id)-$(Get-Date -Format 'HHmmssfff')"
                session_id = "session-$($req.id)"
                tool_name = $req.request.tool_name
                tool_args = $req.request.tool_args
                purpose = $req.request.purpose
                source_trace = @(
                    @{
                        source_id = "batch-script"
                        label = $sourceLabel
                    }
                )
                risk_ack = $true
            }
        }
    } | ConvertTo-Json -Depth 10
    
    # 发送请求（使用配置的 URL）
    try {
        $response = Invoke-RestMethod -Uri $GUARD_URL `
            -Method Post `
            -Headers @{
                Authorization = "Bearer $token"
                "Content-Type" = "application/json"
            } `
            -Body $requestBody `
            -ErrorAction Stop
        
        $decision = $response.result.decision
        $isSuccess = ($decision -eq "allow")
        $isFail = ($decision -eq "deny")
        
        if ($isSuccess) { $successCount++ }
        
        $color = if ($isSuccess) { "Green" } 
                elseif ($isFail){"Red"} 
                else{"Magenta"}
        Write-Host "  决策: $decision" -ForegroundColor $color
        
        $results += @{
            id = $req.id
            name = $req.name
            success = $isSuccess
            decision = $decision
            expected = $req.expected
            response = $response
            timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
    catch {
        Write-Host "  请求失败: $_" -ForegroundColor Red
        $results += @{
            id = $req.id
            name = $req.name
            success = $false
            decision = "error"
            expected = $req.expected
            error = $_.Exception.Message
            timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
    }
    
    Start-Sleep -Seconds $DelaySeconds
}

# 统计
$totalCount = $results.Count
$failCount = $totalCount - $successCount

Write-Host "`n" -ForegroundColor White
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "执行统计" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "总请求数: $totalCount" -ForegroundColor White
Write-Host "成功: $successCount" -ForegroundColor Green
Write-Host "失败: $failCount" -ForegroundColor Red

# 保存结果
$summary = @{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    total = $totalCount
    success = $successCount
    failed = $failCount
    results = $results
}

# 保存结果到 JSONL（每行一个结果）
$outputDir = Split-Path $OutputFile -Parent
if ($outputDir -and -not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
}

# 清空或创建输出文件
"" | Out-File -FilePath $OutputFile -Encoding UTF8 -NoNewline

# 逐行写入每个结果（简化的格式）
foreach ($result in $results) {
    # 创建简化的结果对象
    $simplifiedResult = @{
        id = $result.id
        name = $result.name
        decision = $result.decision
        success = $result.success
        expected = $result.expected
        timestamp = $result.timestamp
        # 只保留关键响应信息，不保存整个 response
        response_summary = if ($result.response.result) {
            @{
                decision = $result.response.result.decision
                content = if ($result.response.result.content) {
                    $result.response.result.content[0].text
                } else { $null }
                isError = $result.response.result.isError
            }
        } else { $null }
    }
    
    # 每行写入一个 JSON 对象
    $simplifiedResult | ConvertTo-Json -Compress | Out-File -FilePath $OutputFile -Append -Encoding UTF8
}

# 可选：同时保存完整报告
$reportFile = $OutputFile.Replace(".jsonl", "_full_report.json")
$summary = @{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    total = $totalCount
    success = $successCount
    failed = $failCount
    results = $results  # 完整结果
}
$summary | ConvertTo-Json -Depth 10 | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "`n完整报告已保存到: $reportFile" -ForegroundColor Green
Write-Host "`n结果已保存到: $OutputFile" -ForegroundColor Green
Write-Host "完成!" -ForegroundColor Green