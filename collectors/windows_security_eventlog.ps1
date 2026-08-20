param(
    [string]$Endpoint = "http://localhost:8000/api/v1/ingest/events",
    [int]$LookbackMinutes = 15,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$ApiKey = $env:SENTINELSCOPE_INGESTION_KEY
if (-not $DryRun -and [string]::IsNullOrWhiteSpace($ApiKey)) {
    throw "Set SENTINELSCOPE_INGESTION_KEY before running the collector."
}
$startTime = (Get-Date).AddMinutes(-$LookbackMinutes)
$records = Get-WinEvent -FilterHashtable @{ LogName = "Security"; Id = 4624, 4625; StartTime = $startTime }
$events = foreach ($record in $records) {
    $xml = [xml]$record.ToXml()
    $fields = @{}
    foreach ($item in $xml.Event.EventData.Data) { $fields[$item.Name] = [string]$item.'#text' }
    $ip = $fields["IpAddress"]
    if ([string]::IsNullOrWhiteSpace($ip) -or $ip -eq "-") { $ip = "127.0.0.1" }
    $username = $fields["TargetUserName"]
    if ([string]::IsNullOrWhiteSpace($username) -or $username -eq "-") { $username = "unknown" }

    @{
        timestamp  = $record.TimeCreated.ToUniversalTime().ToString("o")
        user_id    = $username
        event_type = "login"
        outcome    = if ($record.Id -eq 4624) { "success" } else { "failure" }
        ip_address = $ip
        country    = "ZZ"
        endpoint   = "/windows-logon"
        role       = "user"
        source     = "windows-security-eventlog"
        details    = @{
            event_id         = $record.Id
            workstation_name = $fields["WorkstationName"]
            logon_type       = $fields["LogonType"]
            process_name     = $fields["ProcessName"]
            status           = $fields["Status"]
        }
    }
}

if ($DryRun) {
    $events | ConvertTo-Json -Depth 5
    exit 0
}

for ($offset = 0; $offset -lt $events.Count; $offset += 100) {
    $last = [Math]::Min($offset + 99, $events.Count - 1)
    $batch = @($events[$offset..$last])
    $body = @{ events = $batch } | ConvertTo-Json -Depth 6
    Invoke-RestMethod -Method Post -Uri $Endpoint -Headers @{ "X-Ingestion-Key" = $ApiKey } -ContentType "application/json" -Body $body
}
