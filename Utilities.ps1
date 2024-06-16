$global:EventLogger = $null

class HttpKnockException : Exception {
    HttpKnockException([string]$Message) : base($Message) {}
}

class IllegalArgumentException : HttpKnockException {
    IllegalArgumentException([string]$Message) : base($Message) {}
}

class InternalErrorException : HttpKnockException {
    InternalErrorException([string]$Message) : base($Message) {}
}

class Configuration {
    [string]$WebServiceName
    [string]$WatchServiceName
    [string]$MutexNameToRewriteKnockedJson
    [string]$EventLogLogName
    [string]$EventLogSource
    [string]$FirewallRuleName
    [int]$FirewallRuleTcpPortNumber
    [int]$KnockServicePortNumber
    [int]$WatchTimeInterval
    [int]$TimeToDisableRule
}

class ConfigurationFactory {
    [Configuration]Create([psobject]$Data) {
        $c = [Configuration]::new()
        $c.WebServiceName = $Data.WebServiceName
        $c.WatchServiceName = $Data.WatchServiceName
        $c.MutexNameToRewriteKnockedJson = $Data.MutexNameToRewriteKnockedJson
        $c.EventLogLogName = $Data.EventLogLogName
        $c.EventLogSource = $Data.EventLogSource
        $c.FirewallRuleName = $Data.FirewallRuleName
        $c.FirewallRuleTcpPortNumber = $Data.FirewallRuleTcpPortNumber
        $c.KnockServicePortNumber = $Data.KnockServicePortNumber
        $c.WatchTimeInterval = $Data.WatchTimeInterval
        $c.TimeToDisableRule = $Data.TimeToDisableRule
        return $c
    }
}

class ConfigurationReader {
    [string]$Path

    ConfigurationReader([string]$Path) {
        $this.Path = $Path
    }
    [Configuration]Read() {
        $Factory = [ConfigurationFactory]::new()

        $Json = Get-Content -LiteralPath $this.Path -Encoding UTF8
        $Data = $Json | ConvertFrom-Json
        return $Factory.Create($Data)
    }
}

class Knock {
    Knock([System.DateTime]$LastAccessTime) {
        $this.LastAccessTime = $LastAccessTime
    }
    [System.DateTime]$LastAccessTime
}

class KnockWriter {
    [System.Threading.Mutex]$Mutex
    [string]$Path

    KnockWriter([System.Threading.Mutex]$Mutex, [string]$Path) {
        $this.Mutex = $Mutex
        $this.Path = $Path
    }
    Write([Knock]$Knock) {
        try {
            $this.Mutex.WaitOne()

            $LocalDate = $Knock.LastAccessTime
            $UtcDate = $LocalDate.ToUniversalTime()
            $Data = @{"LastAccessTime"=$UtcDate}
            $Json = $Data | ConvertTo-Json
            $Json | Set-Content -LiteralPath $this.Path -Encoding UTF8
        } finally {
            $this.Mutex.ReleaseMutex()
        }
    }
}

class KnockReader {
    [System.Threading.Mutex]$Mutex
    [string]$Path

    KnockReader([System.Threading.Mutex]$Mutex, [string]$Path) {
        $this.Mutex = $Mutex
        $this.Path = $Path
    }
    [knock] Read() {
        try {
            $this.Mutex.WaitOne()

            $Json = Get-Content -LiteralPath $this.Path -Encoding UTF8
            $DataUtc = $Json | ConvertFrom-Json
            $LastAccessTimeUtc = $DataUtc.LastAccessTime
            $LastAccessTime = $LastAccessTimeUtc.ToLocalTime()
            return [Knock]::new($LastAccessTime)
        } finally {
            $this.Mutex.ReleaseMutex()
        }
    }
}

class EventLogger {
    [string]$LogName
    [string]$Source

    EventLogger([string]$LogName, [string]$Source) {
        $this.LogName = $LogName
        $this.Source = $Source
    }
    WriteEntry([System.Diagnostics.EventLogEntryType]$Type, [int]$EventId, [string]$Message) {
        # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventlogentrytype?view=net-8.0
        # https://learn.microsoft.com/ja-jp/dotnet/api/system.diagnostics.eventlog.writeentry?view=net-8.0
        Write-EventLog -LogName $this.LogName -Source $this.Source -EventId $EventId -Message $Message

        $DateString = Get-Date -UFormat "%Y-%m-%d %H:%M:%S"
        Write-Host ("{0} {1}" -f $DateString, $Message)
    }
    WriteEventError([int]$EventId, [string]$Message) {
        $Type = [System.Diagnostics.EventLogEntryType]::Error
        $this.WriteEntry($Type, $EventId, $Message)
    }
    WriteEventWarning([int]$EventId, [string]$Message) {
        $Type = [System.Diagnostics.EventLogEntryType]::Warning
        $this.WriteEntry($Type, $EventId, $Message)
    }
    WriteEventInformation([int]$EventId, [string]$Message) {
        $Type = [System.Diagnostics.EventLogEntryType]::Information
        $this.WriteEntry($Type, $EventId, $Message)
    }
    WriteEventSuccessAudit([int]$EventId, [string]$Message) {
        $Type = [System.Diagnostics.EventLogEntryType]::SuccessAudit
        $this.WriteEntry($Type, $EventId, $Message)
    }
    WriteEventFailureAudit([int]$EventId, [string]$Message) {
        $Type = [System.Diagnostics.EventLogEntryType]::FailureAudit
        $this.WriteEntry($Type, $EventId, $Message)
    }
}

function Read-Configuration {
    param()

    $Path = Join-Path $PSScriptRoot "configurations.json"
    $Reader = [ConfigurationReader]::new($Path)
    return $Reader.Read()
}

function Test-CurrentPrincipalIsInAdministratorRole {
    param()

    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = [Security.Principal.WindowsPrincipal]$Identity
    $AdministratorRole = [Security.Principal.WindowsBuiltInRole]::Administrator
    return $Principal.IsInRole($AdministratorRole)
}

function Exit-IfUserDoesNotHaveAdministrativePrivileges() {
    param()

    if (-not (Test-CurrentPrincipalIsInAdministratorRole)) {
        throw [IllegalArgumentException]::new("Administrative privileges are required.")
    }
}

function Test-CommandExists {
    param($Name)

    $Command = Get-Command -Name $Name -ErrorAction SilentlyContinue
    return $null -eq $Command
}

function Exit-IfCommandIsNotFound {
    param($Name)

    if (-not(Test-CommandExists -Name $Name)) {
        $Message = "Command {0} is not found." -f $Name
        throw [IllegalArgumentException]::new($Message)
    }
}

function Register-Service {
    param(
        [Parameter(Mandatory)][string]$ServiceName,
        [Parameter(Mandatory)][string]$ScriptName
    )

    Exit-IfCommandIsNotFound -Name "nssm.exe"

    $PowershellCommand = Get-Command powershell.exe
    if ($null -eq $PowershellCommand) {
        throw [InternalErrorException]::new("Internal Error")
    }

    $PowershellCommandPath = $PowershellCommand.Path
    $FullName = Join-Path $PSScriptRoot $ScriptName
    $AppParameters = '-NoLogo -ExecutionPolicy ByPass -NoProfile -File "{0}"' -f $FullName

    nssm.exe install $ServiceName $PowershellCommandPath
    nssm.exe set $ServiceName AppDirectory $PSScriptRoot
    nssm.exe set $ServiceName AppParameters $AppParameters
}

function Register-WebService {
    param([Parameter(Mandatory)][string]$WebServiceName)
    Register-Service -ServiceName $WebServiceName -ScriptName "Invoke-WebService.ps1"
}

function Register-WatchService {
    param([Parameter(Mandatory)][string]$WatchServiceName)
    Register-Service -ServiceName $WatchServiceName -ScriptName "Invoke-WatchAndEnableRuleMain.ps1"
}

function Unregister-Service {
    param([Parameter(Mandatory)][string]$ServiceName)

    Exit-IfCommandIsNotFound -Name "nssm.exe"
    nssm.exe remove $ServiceName
}

function Get-KnockedJsonPath {
    param()

    $DataDirectory = Join-Path $PSScriptRoot "data"
    return Join-Path $DataDirectory "knocked.json"
}

function Get-FirewallRuleArray {
    param([Parameter(Mandatory)][string]$FirewallRuleDisplayName)

    $AllRules = Get-NetFirewallRule
    $Rules = @(
        $AllRules |
        Where-Object { $_.Action -eq 'Allow' } |
        Where-Object { $_.Direction -eq 'Inbound' } |
        Where-Object { $_.DisplayName -ceq $FirewallRuleDisplayName } |
        Where-Object { $true }
    )
    return $Rules
}

function Invoke-EnsureThatFirewallRuleExist {
    param(
        [Parameter(Mandatory)][string]$FirewallRuleDisplayName,
        [Parameter(Mandatory)][int]$TcpPortNumber
    )

    $FirewallRules = Get-FirewallRuleArray -FirewallRuleDisplayName $FirewallRuleDisplayName
    if ($FirewallRules.Count -eq 0) {
        $global:EventLogger.WriteEventInformation(1, "Create firewall rule {0}." -f $FirewallRuleDisplayName)
        New-NetFirewallRule -DisplayName $FirewallRuleDisplayName -Direction Inbound -Protocol TCP -LocalPort $TcpPortNumber -Action Allow |
        Out-Null
    }
}

function Test-FirewallRuleShouldBeEnabled {
    param(
        [Parameter(Mandatory)][System.DateTime]$LastAccessTime,
        [Parameter(Mandatory)][int]$TimeToDisableRule,
        [System.DateTime]$Now
    )

    if ($null -eq $Now) {
        $Now = Get-Date
    }

    $TimeSpan = New-TimeSpan -Start $LastAccessTime -End $Now
    return $TimeSpan.TotalSeconds -lt $TimeToDisableRule
}

function Invoke-EnsureThatFirewallRuleStatus {
    [CmdletBinding(DefaultParameterSetName = 'Disabled')]
    param(
        [Parameter(Mandatory)][string]$FirewallRuleDisplayName,
        [Parameter(ParameterSetName = 'Enabled', Mandatory)][Switch]$Enabled,
        [Parameter(ParameterSetName = 'Disabled', Mandatory)][Switch]$Disabled
    )

    $EnabledType = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]

    $FirewallRules = Get-FirewallRuleArray -FirewallRuleDisplayName $FirewallRuleDisplayName
    foreach ($Rule in $FirewallRules) {
        if ($Enabled -and ($Rule.Enabled -eq $EnabledType::False)) {
            $global:EventLogger.WriteEventInformation(1, 'Enable firewall rule "{0}".' -f $FirewallRuleDisplayName)
            $Rule | Enable-NetFirewallRule
        } elseif ($Disabled -and ($Rule.Enabled -eq $EnabledType::True)) {
            $global:EventLogger.WriteEventInformation(1, 'Disable firewall rule "{0}".' -f $FirewallRuleDisplayName)
            $Rule | Disable-NetFirewallRule
        }
    }
}

$script:LastEnabledOrDisabled = $null

function Invoke-EnsureThatFirewallRuleIsDesiredState {
    param(
        [Parameter(Mandatory)][int]$TimeToDisableRule,
        [Parameter(Mandatory)][string]$FirewallRuleName
    )

    $ShouldBeEnabled = Test-FirewallRuleShouldBeEnabled -LastAccessTime $LastAccessTime -TimeToDisableRule $TimeToDisableRule

    $EnabledOrDisabled = if ($ShouldBeEnabled) { "enabled" } else { "disabled" }

    if ($script:LastEnabledOrDisabled -ne $EnabledOrDisabled) {
        $Message = 'Ensure that firewall rule "{0}" is {1}.' -f $FirewallRuleName, $EnabledOrDisabled
        $global:EventLogger.WriteEventInformation(1, $Message)
    }

    if ($ShouldBeEnabled) {
        Invoke-EnsureThatFirewallRuleStatus -FirewallRuleDisplayName $FirewallRuleName -Enabled
    } else {
        Invoke-EnsureThatFirewallRuleStatus -FirewallRuleDisplayName $FirewallRuleName -Disabled
    }

    $script:LastEnabledOrDisabled = $EnabledOrDisabled
}

function Invoke-InstallMain {
    param()

    # 管理者権限であるか確認します。
    # イベント ログを構成するために管理者権限が必要です。
    Exit-IfUserDoesNotHaveAdministrativePrivileges

    # 設定を読みます。
    [Configuration]$Configuration = Read-Configuration

    # イベント ログを構成します。
    $Message = "Add LogName: {0}, Source: {1} ..." -f $Configuration.EventLogLogName, $Configuration.EventLogSource
    Write-Host $Message
    New-EventLog -LogName $Configuration.EventLogLogName -Source $Configuration.EventLogSource -ErrorAction SilentlyContinue

    # サービスを構成します。
    Register-WebService -WebServiceName $Configuration.WebServiceName -ErrorAction SilentlyContinue
    Register-WatchService -WatchServiceName $Configuration.WatchServiceName -ErrorAction SilentlyContinue

    # Mutex を構成します。
    New-Object System.Threading.Mutex($false, $Configuration.MutexNameToRewriteKnockedJson) | Out-Null

    Write-Host "Installed successfully."
}

function Invoke-UninstallMain {
    param()

    # 管理者権限であるか確認します。
    # イベント ログを構成するために管理者権限が必要です。
    Exit-IfUserDoesNotHaveAdministrativePrivileges

    # 設定を読みます。
    [Configuration]$Configuration = Read-Configuration

    # イベント ログを構成します。
    $Message = "Remove Source: {1} ..." -f $Configuration.EventLogSource
    Write-Host $Message
    Remove-EventLog -Source $Configuration.EventLogSource -ErrorAction SilentlyContinue

    # サービスを構成します。
    Unregister-Service -ServiceName $Configuration.WebServiceName -ErrorAction SilentlyContinue
    Unregister-Service -ServiceName $Configuration.WatchServiceName -ErrorAction SilentlyContinue

    # Mutex を構成します。
    $Mutex = New-Object System.Threading.Mutex($false, $Configuration.MutexNameToRewriteKnockedJson)
    $Mutex.Dispose()

    Write-Host "Uninstalled successfully."
}

function Invoke-WebServiceMain {
    param()

    # TODO: 管理者権限なしで起動できるか、確認する。
    # netsh を構成することで、管理者権限なしに Web サービスを起動できるかもしれません。
    # https://learn.microsoft.com/en-us/dotnet/framework/wcf/feature-details/configuring-http-and-https?redirectedfrom=MSDN

    # 設定を読む。
    [Configuration]$Configuration = Read-Configuration
    $global:EventLogger = [EventLogger]::new($Configuration.EventLogLogName, $Configuration.EventLogSource)

    $Mutex = [System.Threading.Mutex]::new($false, $Configuration.MutexNameToRewriteKnockedJson)
    $KnockedJsonPath = Get-KnockedJsonPath
    $KnockWriter = [KnockWriter]::new($Mutex, $KnockedJsonPath)

    # Web サービスを起動する。
    $HttpListener = New-Object System.Net.HttpListener
    $Prefixes = $HttpListener.Prefixes
    $Prefix = "http://+:{0}/" -f $Configuration.KnockServicePortNumber
    $Prefixes.Add($Prefix)
    $global:EventLogger.WriteEventInformation(0, "Listening port http://127.0.0.1:{0}/ ..." -f $Configuration.KnockServicePortNumber)
    $HttpListener.Start()

    # 要求があれば、ファイルに日時を記録する。
    try {
        while ($true) {
            $Context = $HttpListener.GetContext()
            $global:EventLogger.WriteEventInformation(0, "Accepted.")

            # 要求を得る。
            $Request = $Context.Request
            $QueryStringHash = & {
                # 同じ Name に複数の値がある場合を無視することを許容する。
                $Hash = @{}
                $NameValueCollection = $Request.QueryString
                foreach ($Name in $NameValueCollection) {
                    $Value = $NameValueCollection[$Name]
                    $Hash[$Name] = $Value
                }
                $Hash
            }
            $RequestHash = @{
                "Method"=$Request.HttpMethod
                "Url"=$Request.Url.OriginalString
                "RawUrl"=$Request.RawUrl
                "QueryStringHash"=$QueryStringHash
                "UserHostName"=$Request.UserHostName
                "UserHostAddress"=$Request.UserHostAddress
                "UserAgent"=$Request.UserAgent
                "UrlReferrer"=$Request.UrlReferrer
            }
            $RequestJson = $RequestHash | ConvertTo-Json
            $global:EventLogger.WriteEventInformation(0, $RequestJson)

            # クライアントに応答する。
            $Response = @{"status"="ok"}
            $ResponseJson = $Response | ConvertTo-Json
            $Content = [System.Text.Encoding]::UTF8.GetBytes($ResponseJson)
            $Response = $Context.Response
            $Response.ContentType = 'application/json'
            $Response.ContentLength64 = $Content.Length
            $Response.OutputStream.Write($content, 0, $content.Length)
            $Response.StatusCode = 200
            $Response.Close()

            # 要求が指定条件であれば、ファイルに時刻を記録する。
            if ($QueryStringHash["knock"] -eq "y") {
                # "http://.../path/to?knock=y" にアクセスがあったら、ファイルに時刻を記録する。
                $Now = Get-Date
                $Knock = [Knock]::new($Now)
                $KnockWriter.Write($Knock)
            }
        }
    } finally {
        $HttpListener.Stop()
    }
}

function Invoke-WatchAndEnableRuleMain {
    param()

    # 管理者権限であるか確認します。
    # ファイアウォールのルールを有効・無効にするために管理者権限が必要であるため。
    Exit-IfUserDoesNotHaveAdministrativePrivileges

    # 設定を読む。
    [Configuration]$Configuration = Read-Configuration

    $global:EventLogger = [EventLogger]::new($Configuration.EventLogLogName, $Configuration.EventLogSource)
    $global:EventLogger.WriteEventInformation(0, "Starting to watch the file...")

    # ファイアウォールのルールを定義済みにします。
    Invoke-EnsureThatFirewallRuleExist `
            -FirewallRuleDisplayName $Configuration.FirewallRuleName `
            -TcpPortNumber $Configuration.FirewallRuleTcpPortNumber

    #
    # 最終アクセス時刻から一定期間の間、ファイアウォールのルールを有効にします。
    #

    $Mutex = [System.Threading.Mutex]::new($false, $Configuration.MutexNameToRewriteKnockedJson)
    $KnockedJsonPath = Get-KnockedJsonPath
    $KnockReader = [KnockReader]::new($Mutex, $KnockedJsonPath)

    $PreviousLastAccessTime = $null
    while ($true) {
        $Knock = $KnockReader.Read()
        $LastAccessTime = $Knock.LastAccessTime

        if ($PreviousLastAccessTime -ne $LastAccessTime) {
            Invoke-EnsureThatFirewallRuleIsDesiredState `
                    -TimeToDisableRule $Configuration.TimeToDisableRule `
                    -FirewallRuleName $Configuration.FirewallRuleName
        }
        $PreviousLastAccessTime = $LastAccessTime

        Start-Sleep $Configuration.WatchTimeInterval
    }
}
