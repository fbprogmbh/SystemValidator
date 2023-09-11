#SystemValidator Version
$version = "1.0.1"
function isAdmin {
    return ([Security.Principal.WindowsIdentity]::GetCurrent().Groups -contains 'S-1-5-32-544')
}


function Get-Event{
    param(
        [System.Diagnostics.Eventing.Reader.EventLogRecord] $event
    )
    if ($event.Id -eq 1002 -or $event.Id -eq 300 -or $event.Id -eq 2001 -or $event.Id -eq 4252) {
        return;
    }
    htmlElement 'tr' @{} {
        htmlElement 'td' @{} { $event.TimeCreated }
        htmlElement 'td' @{} { $event.Id }
        htmlElement 'td' @{} { $event.LevelDisplayName }
        if($event.LevelDisplayName -eq "Warning"){
            htmlElement 'td' @{style = "background-color: yellow;" } { $event.Message }
        }
        if($event.LevelDisplayName -eq "Error"){
            htmlElement 'td' @{style = "background-color: orange;" } { $event.Message }
        }
        if($event.LevelDisplayName -eq "Critical"){
            htmlElement 'td' @{style = "background-color: red;" } { $event.Message }
        }
    }
}


function Get-LogsByLogName {
    param (
        [string] $logName
    )
    $args = @{}
    $args.Add("StartTime", ((Get-Date).AddDays((-30))))
    $args.Add("EndTime", (Get-Date))
    $args.Add("LogName", $logName)
    
    $eventPS = Get-WinEvent -FilterHashtable $args
    $warningEvents = $eventPS | Where-Object { $_.LevelDisplayName -eq "Warning" }
    $errorEvents = $eventPS | Where-Object { $_.LevelDisplayName -eq "Error" }
    $criticalEvents = $eventPS | Where-Object { $_.LevelDisplayName -eq "Critical" }
    if ($warningEvents.Length + $errorEvents.Length + $criticalEvents.Length -eq 0 ) {
        return;
    }
    foreach ($event in $warningEvents) {
        Get-Event $event
    }
    foreach ($event in $errorEvents) {
        Get-Event $event
    }
    foreach ($event in $criticalEvents) {
        Get-Event $event
    }
}



function Get-LogCountByName {
    param (
        [string] $logName
    )
    $args = @{}
    $args.Add("StartTime", ((Get-Date).AddDays((-30))))
    $args.Add("EndTime", (Get-Date))
    $args.Add("LogName", $logName)
    
    $eventPS = Get-WinEvent -FilterHashtable $args
    $warningEvents = $eventPS | Where-Object { $_.LevelDisplayName -eq "Warning" }
    $errorEvents = $eventPS | Where-Object { $_.LevelDisplayName -eq "Error" }
    $criticalEvents = $eventPS | Where-Object { $_.LevelDisplayName -eq "Critical" }
    $sum = 0
    foreach ($event in $warningEvents) {
        if ($event.Id -eq 1002 -or $event.Id -eq 300 -or $event.Id -eq 2001 -or $event.Id -eq 4252) {
            continue;
        }
        $sum += 1
    }
    foreach ($event in $errorEvents) {
        if ($event.Id -eq 1002 -or $event.Id -eq 300 -or $event.Id -eq 2001 -or $event.Id -eq 4252) {
            continue;
        }
        $sum += 1
    }
    foreach ($event in $criticalEvents) {
        if ($event.Id -eq 1002 -or $event.Id -eq 300 -or $event.Id -eq 2001 -or $event.Id -eq 4252) {
            continue;
        }
        $sum += 1
    }
    if ($warningEvents.Length + $errorEvents.Length + $criticalEvents.Length -eq 0) {
        return "No Logs found.";
    }
    return $sum
}


function Get-AuditResource {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Name
    )
    #Windows OS
    if ($null -eq $script:loadedResources) {
        return & WindowsSecurityPolicy
    }
    if (-not $script:loadedResources.ContainsKey($Name)) {
        $script:loadedResources[$Name] = (& "$RootPath\Resources\$($Name).ps1")
    }
    return $script:loadedResources[$Name]
}

function ConvertTo-NTAccountUser {
    [CmdletBinding()]
    [OutputType([hashtable])]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string] $Name
    )

    process {
        try {
            # Convert Domaingroups to german
            $language = Get-UICulture
            if ($language.Name -match "de-DE") {
                if ($name -eq "Enterprise Admins") {
                    $name = "Organisations-Admins"
                }
                elseif ($name -eq "Domain Admins") {
                    $name = "Domänen-Admins"
                }
            }

            # Convert friendlynames to SID
            $map = @{
                "Administrators"                      = "S-1-5-32-544"
                "Guests"                              = "S-1-5-32-546"
                "Local account"                       = "S-1-5-113"
                "Local Service"                       = "S-1-5-19"
                "Network Service"                     = "S-1-5-20"
                "NT AUTHORITY\Authenticated Users"    = "S-1-5-11"
                "Remote Desktop Users"                = "S-1-5-32-555"
                "Service"                             = "S-1-5-6"
                "Users"                               = "S-1-5-32-545"
                "NT VIRTUAL MACHINE\Virtual Machines" = "S-1-5-83-0"
            }

            if ($map.ContainsKey($name)) {
                $name = $map[$name]
            }

            # Identity doesn't exist on when Hyper-V isn't installed
            if ($Name -eq "S-1-5-83-0" -and $hyperVStatus -ne "Enabled") {
                return $null
            }

            Write-Verbose "[ConvertTo-NTAccountUser] Converting identity '$Name' to NTAccount"
            if ($Name -match "^(S-[0-9-]{3,})") {
                $sidAccount = [System.Security.Principal.SecurityIdentifier]$Name
            }
            else {
                $sidAccount = ([System.Security.Principal.NTAccount]$Name).Translate([System.Security.Principal.SecurityIdentifier])
            }
            if ($sidAccount.Translate([System.Security.Principal.NTAccount]) -eq "NULL SID") {
                return @{
                    Account = $null
                    Sid     = $sidAccount.Value
                }
            }
            else {
                return @{
                    Account = $sidAccount.Translate([System.Security.Principal.NTAccount])
                    Sid     = $sidAccount.Value
                }
            }
        }
        catch {
            return @{
                Account = "Orphaned Account"
                Sid     = $Name
            }
        }
    }
}


function WindowsSecurityPolicy {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdministrator = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if (-not $isAdministrator) {
        throw "Administrator privileges are required!"
    }

    # get a temporary file to save and process the secedit settings
    $securityPolicyPath = Join-Path -Path $env:TEMP -ChildPath 'SecurityPolicy.inf'

    # export the secedit settings to this temporary file
    Write-Verbose "[WindowsSecurityPolicy] Exporting local security policies from secedit into tempory file: $securityPolicyPath"
    secedit.exe /export /cfg $securityPolicyPath | Out-Null

    $config = @{}
    switch -regex -file $securityPolicyPath {
        "^\[(.+)\]" {
            # Section
            $section = $matches[1]
            $config[$section] = @{}
        }
        "(.+?)\s*=(.*)" {
            # Key
            $name = $matches[1]
            $value = $matches[2] -replace "\*"
            $config[$section][$name] = $value
        }
    }

    Write-Verbose "[WindowsSecurityPolicy] Converting identities in 'Privilege Rights' section"
    $privilegeRights = @{}
    foreach ($key in $config["Privilege Rights"].Keys) {
        # Make all accounts SIDs
        $accounts = $($config["Privilege Rights"][$key] -split ",").Trim() `
		    | ConvertTo-NTAccountUser -Verbose:$VerbosePreference `
		    | Where-Object { $null -ne $_ }
        $privilegeRights[$key] = $accounts
    }
    $config["Privilege Rights"] = $privilegeRights

    # sanitize input
    $systemAccess = @{}
    foreach ($key in $config["System Access"].Keys) {
        $systemAccess[$key] = $config["System Access"][$key].Trim()
    }
    $config["System Access"] = $systemAccess

    return $config

}



#Helper function for 'Test-ASRRules'
Function Test-RegistryValue ($regkey, $name) {
    if (Get-ItemProperty -Path $regkey -Name $name -ErrorAction Ignore) {
        $true
    }
    else {
        $false
    }
}

function Get-ASRRuleNameByID {
    param (
        [string] $ruleID
    )
    $asrTable = @{
        "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
        "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
        "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
        "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
        "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
        "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
        "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
        "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
        "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
        "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes"
        "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
        "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
        "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
        "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
        "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
        "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
    }
    return $asrTable[$ruleID]
}



function Get-ASRStatus {
    $regValue = 0;
    $regValueTwo = 0;
    $Path = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
    $Value = "ExploitGuard_ASR_Rules"
    
    $asrTest1 = Test-ASRRules -Path $Path -Value $Value 
    if ($asrTest1) {
        $regValue = Get-ItemProperty -ErrorAction Stop `
            -Path $Path `
            -Name $Value `
        | Select-Object -ExpandProperty $Value
    }

    $Path2 = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
    $Value2 = "ExploitGuard_ASR_Rules"

    $asrTest2 = Test-ASRRules -Path $Path2 -Value $Value2 
    if ($asrTest2) {
        $regValueTwo = Get-ItemProperty -ErrorAction Stop `
            -Path $Path2 `
            -Name $Value2 `
        | Select-Object -ExpandProperty $Value2
    }

    if ($regValue -ne 1 -and $regValueTwo -ne 1) {
        return "False"
    }
    return "True"
}



#This function is needed in AuditGroups, which check both paths of ASR-Rules.
function Test-ASRRules {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String] $Path,
        [Parameter(Mandatory = $true)]
        [String] $Value
    )

    process {
        try {
            if (Test-Path -Path $Path) {
                return Test-RegistryValue $Path $Value
            }
            else {
                return $false
            }
        }
        catch {

        }
    }

}

##### Tests #####
function ConfigurationCheck {
    param(
        [string] $check,
        [string] $currentConfig,
        [string] $logicCheck,
        [string] $targetConfig
    )

    switch -regex($logicCheck) {
        'eq' {
            if ($currentConfig -eq $targetConfig) {
                $result = "Compliant"
            }
            else {
                $result = "Non-compliant"
            }
        }
        'ge' {
            if ($currentConfig -ge $targetConfig) {
                $result = "Compliant"
            }
            else {
                $result = "Non-compliant"
            }
        }
        'ne' {
            if ($currentConfig -ne $targetConfig) {
                $result = "Compliant"
            }
            else {
                $result = "Non-compliant"
            }
        }
        'match' {
            if ($currentConfig -match $targetConfig) {
                $result = "Compliant"
            }
            else {
                $result = "Non-compliant"
            }
        }
        'info' {
            $result = "Information"
        }
    }
    htmlElement 'tr' @{} {
        htmlElement 'td' @{} { $check }
        htmlElement 'td' @{} { $targetConfig }
        htmlElement 'td' @{} { $currentConfig }
        if ($result -eq "Compliant") {
            htmlElement 'td' @{class = "Compliant" } { $result }
        }
        if ($result -eq "Non-compliant") {
            htmlElement 'td' @{class = "False" } { $result }
        }
        if ($result -eq "Information") {
            htmlElement 'td' @{class = "Information" } { $result }
        }
    }
}

###### HTML Functions ######
function htmlElement {
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $ElementName,

        [Parameter(Mandatory = $true, Position = 1)]
        [hashtable]
        $Attributes,

        [Parameter(Mandatory = $true, Position = 2)]
        [scriptblock]
        $Children
    )

    $htmlAttributes = @()
    foreach ($attribute in $Attributes.GetEnumerator()) {
        $htmlAttributes += '{0}="{1}"' -f $attribute.Name, $attribute.Value
    }

    [string[]]$htmlChildren = & $Children

    return '<{0} {1}>{2}</{0}>' -f $ElementName, ($htmlAttributes -join ' '), ($htmlChildren -join '')
}

function Create-HTMLDocument {
    $head = Create-HTMLHead
    $body = Create-HTMLBody
    $html = "<!DOCTYPE html><html lang=`"en`">$($head)$($body)</body></html> "
    return $html
}

function Create-HTMLHead {
    $head = htmlElement 'head' @{} {
        htmlElement 'meta' @{ charset = 'UTF-8' } { }
        htmlElement 'meta' @{ name = 'viewport'; content = 'width=device-width, initial-scale=1.0' } { }
        htmlElement 'meta' @{ 'http-equiv' = 'X-UA-Compatible'; content = 'ie=edge' } { }
        htmlElement 'title' @{} { "System_Validator [$(Get-Date)]" }
        htmlElement 'style' @{} {
            ".informationRow{
                padding-right: 200px;
            }
            .Compliant{
                background-color:limegreen;
            }
            .False{
                background-color:red;
            }
            .Information{
                background-color:lightgrey;
            }
            table{
                margin-bottom:50px
            }
            h2{
                margin-bottom: 5px
            }

            #EventLogs_PowerShell, #EventLogs_WindowsDefender, #EventLogs_WinRM, #EventLogs_DSC{
                display: none;
            }
            #togglePowerShell:checked + #EventLogs_PowerShell{
                display: block;
            }
            #toggleWindowsDefender:checked + #EventLogs_WindowsDefender{
                display: block;
            }
            #toggleWinRM:checked + #EventLogs_WinRM{
                display: block;
            }
            #toggleDSC:checked + #EventLogs_DSC{
                display: block;
            }
            " 
        }
    }
    return $head
}

function Create-TableRow {
    param(
        [string[]] $content
    )
    htmlElement 'tr' @{} {
        for ($i = 0; $i -lt $content.Count; $i++) {
            htmlElement 'td' @{style = "padding-right: 100px" } { $content[$i] }
        }
    }
}

function Create-Table {
    param(
        [string] $title
    )
    htmlElement 'h2' @{} { $title }
    htmlElement 'table' @{} {
        htmlElement 'thead' @{} {
            htmlElement 'tr' @{} {
                htmlElement 'th' @{class = "informationRow" } { "Configuration Check" }
                htmlElement 'th' @{class = "informationRow" } { "Target Configuration" }
                htmlElement 'th' @{class = "informationRow" } { "Current Configuration" }
                htmlElement 'th' @{class = "informationRow" } { "Result" }
            }
        }
        htmlElement 'tbody' @{} {
            $lcmConfigs = Get-DscLocalConfigurationManager
            ConfigurationCheck "ActionAfterReboot" $lcmConfigs.ActionAfterReboot "eq" "ContinueConfiguration"
        }
    }
}


function Create-HTMLBody {
    $body = htmlElement 'body'@{} {
        #System information
        htmlElement 'h1' @{} { "SystemValidator $($version)" }
        htmlElement 'h2' @{} { "System information" }
        $v = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $infos = Get-CimInstance Win32_OperatingSystem
        $uptime = (get-date) - (gcim Win32_OperatingSystem).LastBootUpTime
        $licenseStatus = (Get-CimInstance SoftwareLicensingProduct -Filter "Name like 'Windows%'" | where { $_.PartialProductKey } | select Description, LicenseStatus -ExpandProperty LicenseStatus)
        switch ($licenseStatus) {
            "0" { $lcStatus = "Unlicensed" }
            "1" { $lcStatus = "Licensed" }
            "2" { $lcStatus = "OOBGrace" }
            "3" { $lcStatus = "OOTGrace" }
            "4" { $lcStatus = "NonGenuineGrace" }
            "5" { $lcStatus = "Notification" }
            "6" { $lcStatus = "ExtendedGrace" }
        }
        $role = Switch ((Get-CimInstance -Class Win32_ComputerSystem).DomainRole) {
            "0"	{ "Standalone Workstation" }
            "1"	{ "Member Workstation" }
            "2"	{ "Standalone Server" }
            "3"	{ "Member Server" }
            "4"	{ "Backup Domain Controller" }
            "5"	{ "Primary Domain Controller" }
        }
        Write-Host "Fetching system information"
        $disk = Get-CimInstance Win32_LogicalDisk | Where-Object -Property DeviceID -eq "C:"
        htmlElement 'table' @{} {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Configuration Check" }
                }
            }
            htmlElement 'tbody' @{} {
                ConfigurationCheck "Hostname" $(hostname) "" ""
                ConfigurationCheck "Date" $(Get-Date) "" ""
                ConfigurationCheck "System Uptime" $('{0:d1}:{1:d2}:{2:d2}:{3:d2}' -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds) "" ""
                ConfigurationCheck "Operating System" $($infos.Caption) "" ""
                ConfigurationCheck "System Type" $((Get-WmiObject win32_operatingsystem | select osarchitecture).osarchitecture) "" ""
                ConfigurationCheck "Build Number" ('Version {0} (Build {1}.{2})' -f $v.DisplayVersion, $v.CurrentBuildNumber, $v.UBR) "" ""
                ConfigurationCheck "Installation Language" $((Get-UICulture).DisplayName) "" ""
                ConfigurationCheck "Domain role" $($role) "" ""
                ConfigurationCheck "Free disk space" $("{0:N1} GB" -f ($disk.FreeSpace / 1GB)) "" ""
                ConfigurationCheck "License Status" $($lcStatus) "" ""
            }
        }
        #PSVersionTable
        Write-Host "Fetching PowerShell information"
        htmlElement 'h2' @{} { "PowerShell" }
        htmlElement 'table' @{} {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Configuration Check" }
                    htmlElement 'th' @{class = "informationRow" } { "Target Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Current Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Result" }
                }
            }
            htmlElement 'tbody' @{} {
                $psVTable = $psversiontable
                $policies = (Get-ExecutionPolicy -List)
                ConfigurationCheck "PSVersion" $psVTable.PSVersion "ge" "5.1"
                ConfigurationCheck "PSEdition" $psVTable.PSEdition "info" ""
                ConfigurationCheck "BuildVersion" $psVTable.BuildVersion "info" ""
                ConfigurationCheck "CLRVersion" $psVTable.CLRVersion "info" ""
                ConfigurationCheck "WSManStackVersion" $psVTable.WSManStackVersion "info" ""
                ConfigurationCheck "PSRemotingProtocolVersion" $psVTable.PSRemotingProtocolVersion "info" ""
                ConfigurationCheck "SerializationVersion" $psVTable.SerializationVersion "info" ""
                ConfigurationCheck "(Effective ExecutionPolicy) ExecutionPolicy" $(Get-ExecutionPolicy) "eq" "RemoteSigned"
                ConfigurationCheck "(ExecutionPolicy) MachinePolicy" $($policies[0].ExecutionPolicy) "info" ""
                ConfigurationCheck "(ExecutionPolicy) UserPolicy" $($policies[1].ExecutionPolicy) "info" ""
                ConfigurationCheck "(ExecutionPolicy) Process" $($policies[2].ExecutionPolicy) "info" ""
                ConfigurationCheck "(ExecutionPolicy) CurrentUser" $($policies[3].ExecutionPolicy) "info" ""
                ConfigurationCheck "(ExecutionPolicy) LocalMachine" $($policies[4].ExecutionPolicy) "info" ""
            }
        }

        #DSCLocalConfigurationManager
        Write-Host "Fetching DSC LCM information"
        htmlElement 'h2' @{} { "DSCLocalConfigurationManager" }
        htmlElement 'table' @{} {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Configuration Check" }
                    htmlElement 'th' @{class = "informationRow" } { "Target Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Current Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Result" }
                }
            }
            htmlElement 'tbody' @{} {
                $lcmConfigs = Get-DscLocalConfigurationManager
                ConfigurationCheck "RefreshMode" $lcmConfigs.RefreshMode "eq" "Push"
                ConfigurationCheck "ActionAfterReboot" $lcmConfigs.ActionAfterReboot "info" ""
                ConfigurationCheck "ConfigurationMode" $lcmConfigs.ConfigurationMode "info" ""
                ConfigurationCheck "LCMState" $lcmConfigs.LCMState "info" ""
                ConfigurationCheck "ConfigurationModeFrequencyMins" $lcmConfigs.ConfigurationModeFrequencyMins "info" ""
                ConfigurationCheck "StatusRetentionTimeInDays" $lcmConfigs.StatusRetentionTimeInDays "info" ""
                ConfigurationCheck "RebootNodeIfNeeded" $lcmConfigs.RebootNodeIfNeeded "info" ""
                ConfigurationCheck "RefreshFrequencyMins" $lcmConfigs.RefreshFrequencyMins "info" ""
                ConfigurationCheck "AllowModuleOverWrite" $lcmConfigs.AllowModuleOverWrite "info" ""
            }
        }

        Write-Host "Fetching DSC Configuration Status information"
        htmlElement 'h3' @{} { "DSC Status" }
        htmlElement 'table' @{} {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Configuration Check" }
                    htmlElement 'th' @{class = "informationRow" } { "Target Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Current Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Result" }
                }
            }
            $ConfigurationStatusSize = ((Get-ChildItem  -Path "C:\Windows\System32\Configuration\ConfigurationStatus" | measure Length -s).sum / 1Mb).ToString(".##")
            #Skip if DSC-ConfigurationManager Refresh Mode is "Disabled"
            $dscStatus = $null
            $lcmConfigs = Get-DscLocalConfigurationManager
            if($lcmConfigs.RefreshMode -ne "Disabled"){
                while($lcmConfigs.LCMStateDetail -ne ""){
                    Start-Sleep -Seconds 20
                    Write-Host "LCM is in status '$($lcmConfigs.LCMStateDetail)', waiting..."
                    $lcmConfigs = Get-DscLocalConfigurationManager
                }
                Test-DscConfiguration
                $dscStatus = Get-DscConfigurationStatus
            }
            htmlElement 'tbody' @{} {
                ConfigurationCheck "ConfigurationStatus-Folder Size (MB)" $ConfigurationStatusSize "info" ""
                if ($null -eq $dscStatus) {
                    ConfigurationCheck "DSC Status" "null" "eq" "null"
                }
                else {
                    ConfigurationCheck "DSC Status" "DSC configuration already exists" "eq" "null"
                }
            }
        }

        
        Write-Host "Fetching User Right Assignements"
        htmlElement 'h2' @{} { "User Right Assignements" }
        htmlElement 'table' @{} {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Configuration Check" }
                    htmlElement 'th' @{class = "informationRow" } { "Target Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Current Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Result" }
                }
            }

            $securityPolicy = Get-AuditResource "WindowsSecurityPolicy"
            $currentUserRightsSeNetworkLogonRight = $securityPolicy["Privilege Rights"]["SeNetworkLogonRight"]
            htmlElement 'tbody' @{} {
                foreach ($user in $currentUserRightsSeNetworkLogonRight) {
                    ConfigurationCheck "SeNetworkLogonRight" $($user.Account) "info" ""
                }
            }
        }


        #WinRM
        Write-Host "Fetching WinRM Configuration"
        htmlElement 'h2' @{} { "WinRM" }
        #WSMan Check
        htmlElement 'table' @{} {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow"; style = "padding-right: 161px;" } { "WSMan Check" }
                    htmlElement 'th' @{class = "informationRow" } { "Target Configuration" }
                    htmlElement 'th' @{class = "informationRow"; style = "padding-left: 77px;" } { "Current Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Result" }
                }
            }
            htmlElement 'tbody' @{} {
                $hostname = $(hostname)
                $testWSMan = Test-WSMan -computername $hostname -ErrorVariable "wmitest" -Authentication Negotiate
                ConfigurationCheck "wmid" $($testWSMan.wsmid) "info" ""
                ConfigurationCheck "ProtocolVersion" $($testWSMan.ProtocolVersion) "info" ""
                ConfigurationCheck "ProductVendor" $($testWSMan.ProductVendor) "info" ""
                ConfigurationCheck "ProductVersion" $($testWSMan.ProductVersion) "info" ""
            }
        }

        #Service Check
        htmlElement 'table' @{} {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Service Check" }
                    htmlElement 'th' @{class = "informationRow" } { "Target Configuration" }
                    htmlElement 'th' @{class = "informationRow"; style = "padding-left: 48px;" } { "Current Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Result" }
                }
            }
            htmlElement 'tbody' @{} {
                $winRMService = Get-Service -Name "WinRM"
                $winRMStatus = $winRMService | Select-Object Status
                $winRMStartType = $winRMService | Select-Object StartType
                $WinRM_LogOnAs = Get-WmiObject -Class Win32_Service -Filter "Name='WinRM'" | Select-Object -ExpandProperty StartName
                ConfigurationCheck "Status" $winRMStatus.Status "eq" "Running"
                ConfigurationCheck "StartType" $winRMStartType.StartType "eq" "Automatic"
                ConfigurationCheck "Log On As" $WinRM_LogOnAs "eq" "LocalSystem"
            }
        }

        #Configuration Check
        htmlElement 'table' @{} {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Configuration Check" }
                    htmlElement 'th' @{class = "informationRow" } { "Target Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Current Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Result" }
                }
            }         
            htmlElement 'tbody' @{} {
                $info = Get-Item -Path WSMan:\localhost\MaxEnvelopeSizeKb
                ConfigurationCheck "MaxEnvelopeSize" $info.Value "eq" "8192"
                $info = Get-Item WSMan:\localhost\Client\TrustedHosts
                ConfigurationCheck "WSManConfig" $info.Name "eq" "TrustedHosts"
            }
        }

        #Public network profiles
        Write-Host "Fetching Network Configuration"
        htmlElement 'h2' @{} { "Network Configuration" }
        htmlElement 'h3' @{} { "Network Profile Configuration" }
        htmlElement 'table' @{} {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Configuration Check" }
                    htmlElement 'th' @{class = "informationRow" } { "Target Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Current Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Result" }
                }
            }
            htmlElement 'tbody' @{} {
                $info = Get-NetConnectionProfile
                ConfigurationCheck "NetworkCategory" $info.NetworkCategory "info" ""
                ConfigurationCheck "IPv4Connectivity" $info.IPv4Connectivity "info" ""
                ConfigurationCheck "IPv6Connectivity" $info.IPv6Connectivity "info" ""
            }
        }
        Write-Host "Fetching Proxy Configuration"
        htmlElement 'h3' @{} { "Proxy Configuration" }
        htmlElement 'table' @{} {
            htmlElement 'tbody' @{} {
                htmlElement 'td' @{} { $(netsh winhttp show Proxy) }
            }
        }


        #PSSessionConfiguration
        Write-Host "Fetching PSSessionConfiguration"
        htmlElement 'h2' @{} { "PSSessionConfiguration" }
        htmlElement 'table' @{} {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Configuration Check" }
                    htmlElement 'th' @{class = "informationRow" } { "Target Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Current Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Result" }
                }
            }
            htmlElement 'tbody' @{} {
                $lcmConfigs = Get-PSSessionConfiguration
                for ($i = 0; $i -lt $lcmConfigs.Count; $i++) {
                    if ($lcmConfigs[$i].Name -match "nfAdminJeaClientManagement") {
                        ConfigurationCheck "Name" $lcmConfigs[$i].Name "match" "nfAdminJeaClientManagement"
                    }
                    else {
                        ConfigurationCheck "Name" $lcmConfigs[$i].Name "info" ""
                    }
                    ConfigurationCheck "PSVersion" $lcmConfigs[$i].PSVersion "info" ""
                    ConfigurationCheck "Permission" $lcmConfigs[$i].Permission "info" ""
                }
            }
        }


        #Windows Defender Configuration
        Write-Host "Fetching Microsoft Defender Configuration"
        htmlElement 'h2' @{} { "Windows Defender Configuration" }
        htmlElement 'table' @{} {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Configuration Check" }
                    htmlElement 'th' @{class = "informationRow" } { "Target Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Current Configuration" }
                    htmlElement 'th' @{class = "informationRow" } { "Result" }
                }
            }
            $asrStatus = Get-ASRStatus
            htmlElement 'tbody' @{} {
                ConfigurationCheck "Windows Defender enabled" $((Get-MpComputerStatus).AntivirusEnabled) "eq" "True"
                ConfigurationCheck "ASR Rules enabled" $($asrStatus) "info" ""
                #if ASR rules are enabled
                if ($asrStatus -eq "True") {
                    #get list of active ASR rules
                    foreach ($rule in Get-MPPreference | Select-Object -ExpandProperty AttackSurfaceReductionRules_Ids) {
                        if ($rule -match "e6db77e5-3df2-4cf1-b95a-636979351e5b") { ConfigurationCheck "Active ASR Rule" $(Get-ASRRuleNameByID $rule) "eq" "False"; continue; }
                        if ($rule -match "d1e49aac-8f56-4280-b9ba-993a6d77406c") { ConfigurationCheck "Active ASR Rule" $(Get-ASRRuleNameByID $rule) "eq" "False"; continue; }
                        ConfigurationCheck "Active ASR Rule" $(Get-ASRRuleNameByID $rule) "info" ""
                    }
                }
            }
        }

        #System Logs
        Write-Host "Fetching Event Logs - PowerShell"
        htmlElement 'h2' @{} { "System Logs* (Last 30 Days)" }
        htmlElement 'h3' @{} { "Event Logs - PowerShell: $(Get-LogCountByName "Windows PowerShell")" }
        htmlElement 'label' @{for = "toggle" } { "Event Logs - PowerShell" }
        htmlElement 'input' @{type = "checkbox"; id = "togglePowerShell" } {}
        htmlElement 'table' @{id = "EventLogs_PowerShell" } {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Date" }
                    htmlElement 'th' @{class = "informationRow" } { "Id" }
                    htmlElement 'th' @{class = "informationRow" } { "LevelDisplayName" }
                    htmlElement 'th' @{class = "informationRow" } { "Message" }
                }
            }
            htmlElement 'tbody' @{} {
                Get-LogsByLogName "Windows PowerShell"
            }
        }

        Write-Host "Fetching Event Logs - Microsoft Defender"
        htmlElement 'h3' @{} { "Event Logs - Windows Defender: $(Get-LogCountByName "Microsoft-Windows-Windows Defender/Operational")" }
        htmlElement 'label' @{for = "toggle" } { "Event Logs - Windows Defender" }
        htmlElement 'input' @{type = "checkbox"; id = "toggleWindowsDefender" } {}
        htmlElement 'table' @{id = "EventLogs_WindowsDefender" } {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Date" }
                    htmlElement 'th' @{class = "informationRow" } { "Id" }
                    htmlElement 'th' @{class = "informationRow" } { "LevelDisplayName" }
                    htmlElement 'th' @{class = "informationRow" } { "Message" }
                }
            }
            htmlElement 'tbody' @{} {
                Get-LogsByLogName "Microsoft-Windows-Windows Defender/Operational"
            }
        }
        
        Write-Host "Fetching Event Logs - Windows Remote Management"
        htmlElement 'h3' @{} { "Event Logs - Windows Remote Management: $(Get-LogCountByName "Microsoft-Windows-WinRM/Operational")" }
        htmlElement 'label' @{for = "toggle" } { "Event Logs - Windows Remote Management" }
        htmlElement 'input' @{type = "checkbox"; id = "toggleWinRM" } {}
        htmlElement 'table' @{id = "EventLogs_WinRM" } {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Date" }
                    htmlElement 'th' @{class = "informationRow" } { "Id" }
                    htmlElement 'th' @{class = "informationRow" } { "LevelDisplayName" }
                    htmlElement 'th' @{class = "informationRow" } { "Message" }
                }
            }
            htmlElement 'tbody' @{} {
                Get-LogsByLogName "Microsoft-Windows-WinRM/Operational"
            }
        }

        Write-Host "Fetching Event Logs - DSC"
        htmlElement 'h3' @{} { "Event Logs - DSC: $(Get-LogCountByName "Microsoft-Windows-Dsc/Operational")" }
        htmlElement 'label' @{for = "toggle" } { "Event Logs - DSC" }
        htmlElement 'input' @{type = "checkbox"; id = "toggleDSC" } {}
        htmlElement 'table' @{id = "EventLogs_DSC" } {
            htmlElement 'thead' @{} {
                htmlElement 'tr' @{} {
                    htmlElement 'th' @{class = "informationRow" } { "Date" }
                    htmlElement 'th' @{class = "informationRow" } { "Id" }
                    htmlElement 'th' @{class = "informationRow" } { "LevelDisplayName" }
                    htmlElement 'th' @{class = "informationRow" } { "Message" }
                }
            }
            htmlElement 'tbody' @{} {
                Get-LogsByLogName "Microsoft-Windows-Dsc/Operational"
            }
        }
        htmlElement 'p' @{} { "*Excluded the following EventIDs as they are not relevant:" }
        htmlElement 'ul' @{} { 
            htmlElement 'li' @{} {"300"}    
            htmlElement 'li' @{} {"1002"}    
            htmlElement 'li' @{} {"2001"}    
            htmlElement 'li' @{} {"4252"}    
        }
    }

    Write-Host "Done"
    return $body
}
$Path = "C:\Temp\SystemValidatorOutput.html"
if (!(isAdmin)) {
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [System.Windows.Forms.MessageBox]::Show("Please run as administrator", "Insufficient permisions", 0, [System.Windows.Forms.MessageBoxIcon]::Error)
}
else {
    Write-Host "Initializing..."
    #If Path exists to a folder exists
    if ($Path -match ".html") {
        $name = Split-Path -Path $Path -Leaf
        $Path = Split-Path -Path $Path -Parent
        $html = Create-HTMLDocument
        New-Item -Path $Path -Name $name -ItemType File -Value $html -Force 
    }
}
