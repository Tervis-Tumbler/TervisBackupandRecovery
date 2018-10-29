$ModulePath = (Get-Module -ListAvailable TervisBackupAndRecovery).ModuleBase
. $ModulePath\Definition.ps1

function Get-TervisDPMServers{
    param(
        [String]$StorageArrayName
    )
    if($StorageArrayName){
        $TervisDPMServers | Where name -EQ $StorageArrayName
    }
    else{$TervisDPMServers}
}

function Invoke-SCDPM2016Provision {
    $EnvironmentName = "Infrastructure"
    $ApplicationName = "SCDPM2016"
    $TervisApplicationDefinition = Get-TervisApplicationDefinition -Name $ApplicationName
    Invoke-ApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $ApplicationAdministratorPrivilegeADGroupName = Get-ApplicationAdministratorPrivilegeADGroupName -EnvironmentName $EnvironmentName -ApplicationName $ApplicationName
    $DPMServiceAccount = Get-PasswordstatePassword -AsCredential -ID 4037
    $DPMServiceAccountUsername = ($DPMServiceAccount.username -split "\\")[1]
    Get-ADGroup $ApplicationAdministratorPrivilegeADGroupName | Add-ADGroupMember -Members $DPMServiceAccountUsername
    $Nodes | Update-TervisSNMPConfiguration
    $Nodes | Invoke-ClaimMPOI
    $Nodes | Invoke-InstallWindowsFeatureViaDISM -FeatureName "Microsoft-Hyper-V"
    $Nodes | Invoke-DPMSQLServer2014Install
    $Nodes | Invoke-DPMServer2016Install
}

function Invoke-SCDPM2016FSProvision {
    $EnvironmentName = "Infrastructure"
    $ApplicationName = "SCDPM2016FileServer"
    $TervisApplicationDefinition = Get-TervisApplicationDefinition -Name $ApplicationName
    Invoke-ApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $ApplicationAdministratorPrivilegeADGroupName = Get-ApplicationAdministratorPrivilegeADGroupName -EnvironmentName $EnvironmentName -ApplicationName $ApplicationName
    #$DPMServiceAccount = Get-PasswordstatePassword -AsCredential -ID $TervisApplicationDefinition.DPMServiceAccountPassword
    $DPMServiceAccount = Get-PasswordstatePassword -AsCredential -ID ($TervisApplicationDefinition.environments).DPMServiceAccountPassword
    $DPMServiceAccountUsername = ($DPMServiceAccount.username -split "\\")[1]
    Get-ADGroup $ApplicationAdministratorPrivilegeADGroupName | Add-ADGroupMember -Members $DPMServiceAccountUsername
    $Nodes | Update-TervisSNMPConfiguration
    $Nodes | Invoke-ClaimMPOI
    $Nodes | Invoke-InstallWindowsFeatureViaDISM -FeatureName "Microsoft-Hyper-V"
    $Nodes | Invoke-DPMSQLServer2014Install
    $Nodes | Invoke-DPMServer2016Install
#    $Nodes | Set-SQLSecurityBuiltInAdministratorsWithSysman
}

function Invoke-SCDPM2016SQLProvision {
    param (
        $EnvironmentName
    )
    $ApplicationName = "SCDPM2016SQL"
    Invoke-ApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes[1] | Invoke-DPMSQLServer2014Install
#    $Nodes | Set-SQLTCPEnabled -InstanceName CSI_Data -Architecture x86
#    $Nodes | Set-SQLTCPIPAllTcpPort -InstanceName CSI_Data -Architecture x86
#    $Nodes | New-SQLNetFirewallRule
    $Nodes | Set-SQLSecurityBuiltInAdministratorsWithSysman
}

function Get-TervisStoreDatabaseLogFileUsage {
    $BOComputerListFromAD = Get-BackOfficeComputers -Online
    $StoreBOSACred = Get-PasswordstatePassword -AsCredential -ID 56
    $BOExceptions = "1010osmgr02-pc","1010osbr-pc","1010osbo2-pc","LPTESTBO-VM","hambo-vm","1010OSMGR02-PC"
    $BOComputerListFromAD = $BOComputerListFromAD | Where {$BOExceptions -NotContains $_}
    
    Start-ParallelWork -ScriptBlock {
        param($Computer,$StoreBOSACred)
            $DBExceptions = "master","tempdb","model","msdb" 
            $dblist = Invoke-SQL -dataSource $Computer -database "master" -sqlCommand "dbcc sqlperf(logspace)" -Credential $StoreBOSACred
            $StoreDB = $dblist | Where {$DBExceptions -notcontains $_.'database name'}
            $StoreDBName = $StoreDB.'Database Name'    
            $RecoveryModel = Invoke-SQL -dataSource $Computer -database "master" -sqlCommand "SELECT DATABASEPROPERTYEX('$StoreDBName', 'RECOVERY') AS [Recovery Model]" -Credential $StoreBOSACred

            [pscustomobject][ordered]@{
                "Computername" = $Computer
                "Database Name" = $StoreDB.'Database Name'
                "Log Size (MB)" = "{0:0.00}" -f $StoreDB.'Log Size (MB)'
                "Log Consumed (%)" = "{0:.00}" -f $StoreDB.'Log Space Used (%)'
                "Recovery Model" = $RecoveryModel."recovery model"
            }
    } -Parameters $BOComputerListFromAD -OptionalParameters $StoreBOSACred | select * -ExcludeProperty RunspaceId | ft
}

function Invoke-SCDPMOraBackupServerProvision {
    param (
        $EnvironmentName = "Infrastructure"
    )
    $ApplicationName = "SCDPMOraBackups"
    $TervisApplicationDefinition = Get-TervisApplicationDefinition -Name $ApplicationName
    Invoke-ApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $ApplicationAdministratorPrivilegeADGroupName = Get-ApplicationAdministratorPrivilegeADGroupName -EnvironmentName $EnvironmentName -ApplicationName $ApplicationName
    $DPMServiceAccount = Get-PasswordstatePassword -AsCredential -ID $TervisApplicationDefinition.DPMServiceAccountPassword
    Get-ADGroup $ApplicationAdministratorPrivilegeADGroupName | Add-ADGroupMember -Members $DPMServiceAccount.Username
    $Nodes | Update-TervisSNMPConfiguration
    $Nodes | Invoke-ClaimMPOI
    $Nodes | Invoke-InstallWindowsFeatureViaDISM -FeatureName "Microsoft-Hyper-V"
    $Nodes | Invoke-DPMSQLServer2014Install
    $Nodes | Invoke-DPMServer2016Install
    $Nodes | Set-SQLSecurityBuiltInAdministratorsWithSysman
#    $Nodes | Set-SQLTCPEnabled -InstanceName CSI_Data -Architecture x86
#    $Nodes | Set-SQLTCPIPAllTcpPort -InstanceName CSI_Data -Architecture x86
#    $Nodes | New-SQLNetFirewallRule
}

#function Get-TervisStoreDatabaseLogFileUsage {
#    $BOComputerListFromAD = Get-BackOfficeComputers -online
#    $StoreBOSACred = Get-PasswordstatePassword -AsCredential -ID 56
#    $BOExceptions = "1010osmgr02-pc","1010osbr-pc","1010osbo2-pc","LPTESTBO-VM","hambo-vm","1010OSMGR02-PC"
#    $BOComputerListFromAD = $BOComputerListFromAD | Where {$BOExceptions -NotContains $_}
#    
#    Start-ParallelWork -ScriptBlock {
#        param($Computer,$StoreBOSACred)
#            $DBExceptions = "master","tempdb","model","msdb" 
#            $dblist = Invoke-SQL -dataSource $Computer -database "master" -sqlCommand "dbcc sqlperf(logspace)" -Credential $StoreBOSACred
#            $StoreDB = $dblist | Where {$DBExceptions -notcontains $_.'database name'}
#            $StoreDBName = $StoreDB.'Database Name'    
#            $RecoveryModel = Invoke-SQL -dataSource $Computer -database "master" -sqlCommand "SELECT DATABASEPROPERTYEX('$StoreDBName', 'RECOVERY') AS [Recovery Model]" -Credential $StoreBOSACred
#
#            [pscustomobject][ordered]@{
#                "Computername" = $Computer
#                "Database Name" = $StoreDB.'Database Name'
#                "Log Size (MB)" = "{0:0.00}" -f $StoreDB.'Log Size (MB)'
#                "Log Consumed (%)" = "{0:.00}" -f $StoreDB.'Log Space Used (%)'
#                "Recovery Model" = $RecoveryModel."recovery model"
#            }
#    } -Parameters $BOComputerListFromAD -OptionalParameters $StoreBOSACred | select * -ExcludeProperty RunspaceId | ft
#}

function Get-BackOfficeComputersNotProtectedByDPM {
    param (
        $DPMServerName = "inf-scdpm201601.tervis.prv"
    )
    $DPMProtectedStores = Invoke-Command -ComputerName $DPMServerName -ScriptBlock {Get-DPMProtectionGroup | where name -match "stores" | Get-Datasource | select computer}
    $BOComputerListFromAD = Get-BackOfficeComputers
    $BOExceptions = "1010osmgr02-pc","1010osbr-pc","1010osbo2-pc","hambo-vm","dlt-gkjono7","inf-dontestbo"
    $BOComputerListFromADWithoutExceptions = $BOComputerListFromAD | Where {$BOExceptions -NotContains $_}
    Compare-Object $DPMProtectedStores.computer $BOComputerListFromADWithoutExceptions
}

Function Get-StaleRecoveryPointsFromDPM { 
    [cmdletbinding()]
    param(
        [parameter]$Computername
    )
#    if(-not $Computername){
        Write-Verbose -Message "Getting DPM Servers from Active Directory"
        $DPMServers = Get-DPMServers
        Write-Verbose -Message "Comlete"
#    }
#    else{$DPMServers = $Computername}
    $OldestRecoveryPointTimeAllowed = (get-date).AddHours(-24)
    $DateTimeLowerBound = (Get-Date).AddYears(-10)
    Write-Verbose -Message "Fetching datasource information"
    $DPMDataSource = Start-ParallelWork -ScriptBlock {
        param($Server)
        $Server | Out-Null
        #Connect-DPMServer -DPMServerName $Server -WarningAction SilentlyContinue | Out-Null
        Get-DPMDatasource -DPMServerName $Server -Verbose
        $DPMDataSource | select latestrecoverypoint | Out-Null        
        Disconnect-DPMServer
    } -Parameters $DPMServers
    Write-Verbose -Message "Complete"

    if(-not($DPMDataSource | 
        Where-Object State -eq Valid | 
        Where-Object LatestRecoveryPoint -lt $OldestRecoveryPointTimeAllowed |
        Select-Object DPMServerName,Computer,Name,LatestRecoveryPoint)){
        Write-Verbose -Message "No Stale Recovery Points Found"
    }
    else {
        $DPMDataSource | 
        Where-Object State -eq Valid | 
        Where-Object LatestRecoveryPoint -lt $OldestRecoveryPointTimeAllowed |
        Select-Object DPMServerName,Computer,Name,LatestRecoveryPoint
    }
    
}

Function Get-DPMErrorLog{
    param (
        [Parameter(Mandatory)]$Path
    )
    $DPMLogFileContent = Get-Content -Path $Path
    $DPMLogFileContent | ConvertFrom-String -TemplateFile $PSScriptRoot\DPMErrorLogTemplate.txt
}

function Test-DPM2016Prerequisites {
    Param(
        $Computername
    )
Start-ParallelWork -Parameters $Computername -ScriptBlock {
        param($Computer)
        $DotNetVersion = Invoke-Command -ComputerName $Computer -ScriptBlock {
            Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -recurse |
            Get-ItemProperty -name Version,Release -EA 0` |
            Where { $_.PSChildName -match '^(?!S)\p{L}'} |
            Select PSChildName, Version, Release, @{
              name="Product"
              expression={
                  switch -regex ($_.Release) {
                    "378389" { [Version]"4.5" }
                    "378675|378758" { [Version]"4.5.1" }
                    "379893" { [Version]"4.5.2" }
                    "393295|393297" { [Version]"4.6" }
                    "394254|394271" { [Version]"4.6.1" }
                    "394802|394806" { [Version]"4.6.2" }
                    {$_ -gt 394806} { [Version]"Undocumented 4.6.2 or higher, please update script" }
                  }
                }
            } |
            Where {$_.PSChildName -eq "Client" -and $_.Product -like "4*"}
        }
        $Version = Invoke-Command -ComputerName $Computer -ScriptBlock {$PSVersionTable.PSVersion}
        $Chocolatey = Invoke-Command -ComputerName $Computer -ScriptBlock {Get-Command choco -erroraction SilentlyContinue | Out-Null; $?}
        $PendingReboot = (Get-PendingRestart $Computer)
        $HotfixInstalled = Invoke-Command -ComputerName $Computer -ScriptBlock {get-hotfix -Id kb3191566 -ErrorAction SilentlyContinue | Out-Null; $?}
        [pscustomobject][ordered]@{
            ComputerName = $Computer
            DotNet45 = $DotNetVersion.Product
            Choco = $Chocolatey
            PSVersion = $Version
            "PS5 Installed" = $HotfixInstalled
            "Pending Reboot" = $PendingReboot.RebootPending
            "Pending Windows Update Reboot" = $PendingReboot.WindowsUpdate
        }
    } | select * -ExcludeProperty RunspaceId
}

function Install-SoftwareRemotePowershell5{
    [CmdletBinding()]
    param(
        [parameter(Mandatory)] $Computerlist
    )
    Start-ParallelWork -Parameters $Computerlist -ScriptBlock {
        param($Computer)
        psexec -s \\$Computer -e choco install powershell -y | Out-Null
        $PendingReboot = (Get-PendingRestart $Computer)
        $HotfixInstalled = Invoke-Command -ComputerName $Computer -ScriptBlock {get-hotfix -Id kb3191566 -ErrorAction SilentlyContinue | Out-Null; $?}
        [pscustomobject][ordered]@{
            ComputerName = $Computer
            "PS5 Installed" = $HotfixInstalled
            "Pending Reboot" = $PendingReboot.RebootPending
            "Pending Windows Update Reboot" = $PendingReboot.WindowsUpdate
        }
    } | select * -ExcludeProperty RunspaceId | ft
}

function Test-RMSHQLogFileUtilization{
    $FromAddress = "MailerDaemon@tervis.com"
    $ToAddress = "WindowsServerApplicationsAdministrator@tervis.com"
    $Subject = "TERVIS_RMSHQ1 Database Log File Above Threshold"
    $LogFileThreshold = 25
    $Computer = "SQL.tervis.prv"
    $AllDB = Invoke-SQL -dataSource $Computer -database "master" -sqlCommand "dbcc sqlperf(logspace)"
    $RMSHQLogUtilization = ($AllDB | Where {$_.'database name' -eq "TERVIS_RMSHQ1"})."log space used (%)"
    
    if ($RMSHQLogUtilization -gt $LogFileThreshold){
        $OutputMessage = "TERVIS_RMSHQ1 Log Utilization is currently {0:N2}" -f $RMSHQLogUtilization + "%`n"
    }
    if ($OutputMessage){
        Send-TervisMailMessage -From $FromAddress -To $ToAddress -Subject $Subject -Body "$OutputMessage"
    }
}

function Invoke-DPMSQLServer2014Install {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node
    )
    $ApplicationName = $node.ApplicationName
    $ApplicationDefinition = Get-TervisApplicationDefinition -Name $node.ApplicationName 
    $SQLSACredentials = Get-PasswordstatePassword -ID ($ApplicationDefinition.Environments).SQLSAPassword
    $DPMServiceAccountCredentials = Get-PasswordstatePassword -ID ($ApplicationDefinition.Environments).DPMServiceAccountPassword
    $ChocolateyPackageParameters = "/SQLSYSADMINACCOUNTS=BUILTIN\Administrators /SAPWD=$($SQLSACredentials.Password) /AGTSVCACCOUNT=$($DPMServiceAccountCredentials.Username) /AGTSVCPASSWORD=$($DPMServiceAccountCredentials.Password) /SQLSVCACCOUNT=$($DPMServiceAccountCredentials.Username) /SQLSVCPASSWORD=$($DPMServiceAccountCredentials.Password) /RSSVCACCOUNT=$($DPMServiceAccountCredentials.Username) /RSSVCPASSWORD=$($DPMServiceAccountCredentials.Password)"
    $PackageArgs = "/IAcceptSQLServerLicenseTerms` 
    /ACTION=Install`
    /ENU=1`
    /QUIET=1`
    /QUIETSIMPLE=0`
    /UpdateEnabled=0`
    /ERRORREPORTING=0`
    /USEMICROSOFTUPDATE=1`
    /FEATURES=SQLENGINE,RS,SSMS,ADV_SSMS`
    /UpdateSource=MU`
    /HELP=0`
    /INDICATEPROGRESS=0`
    /X86=0`
    /INSTANCENAME=MSSQLSERVER`
    /SQMREPORTING=0`
    /INSTANCEID=MSSQLSERVER`
    /RSINSTALLMODE=DefaultNativeMode`
    /AGTSVCSTARTUPTYPE=Automatic`
    /COMMFABRICPORT=0`
    /COMMFABRICNETWORKLEVEL=0`
    /COMMFABRICENCRYPTION=0`
    /MATRIXCMBRICKCOMMPORT=0`
    /SQLSVCSTARTUPTYPE=Automatic`
    /FILESTREAMLEVEL=0`
    /ENABLERANU=0`
    /SQLCOLLATION=SQL_Latin1_General_CP1_CI_AS`
    /SQLSYSADMINACCOUNTS=BUILTIN\Administrators`
    /SECURITYMODE=SQL`
    /ADDCURRENTUSERASSQLADMIN=False`
    /TCPENABLED=1`
    /NPENABLED=0`
    /BROWSERSVCSTARTUPTYPE=Disabled `
    /RSSVCSTARTUPTYPE=Automatic
    /SAPWD=$($SQLSACredentials.Password)`
    /AGTSVCACCOUNT=$($DPMServiceAccountCredentials.Username)`
    /AGTSVCPASSWORD=$($DPMServiceAccountCredentials.Password)`
    /SQLSVCACCOUNT=$($DPMServiceAccountCredentials.Username)`
    /SQLSVCPASSWORD=$($DPMServiceAccountCredentials.Password)`
    /RSSVCACCOUNT=$($DPMServiceAccountCredentials.Username)`
    /RSSVCPASSWORD=$($DPMServiceAccountCredentials.Password)"

    Invoke-Command -ComputerName $Node.ComputerName -ScriptBlock {
        choco install -y '\\tervis.prv\Applications\Chocolatey\SQLServer2014SP2.1.0.1.nupkg' --package-parameters=$($using:ChocolateyPackageParameters)
    }
}

function Invoke-DPMServer2016Install {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$Computername
#        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ApplicationName
    )
#    $ApplicationDefinition = Get-TervisApplicationDefinition -Name $ApplicationName 
    $DPMProductKey = (Get-PasswordstatePassword -ID 4045).Password
#    $SQLSACredentials = Get-PasswordstatePassword -ID ($ApplicationDefinition.Environments).SQLSAPassword
    $DPMInstallSourcePath = "\\tervis.prv\Applications\Installers\Microsoft\SCDPM2016"
        
    $DPMInstallConfigFile = @"
    [OPTIONS]
    UserName = "Tervis"
    CompanyName = "Tervis"
    ProductKey = $DPMProductKey
    SQLMachineName = "$Computername"
    SQLInstanceName = "mssqlserver"
    ReportingMachineName = "$ComputerName"
    ReportingInstanceName = "mssqlserver"
"@
    Invoke-Command -ComputerName $ComputerName -ScriptBlock {
        $TempFile = [io.path]::GetTempFileName() 
        $ChocolateyPackageParameters = "/i /f $Tempfile"
        $using:DPMInstallConfigFile | Out-File -FilePath $tempFile
        & CMD.exe /C Start /wait $using:DPMInstallSourcePath\setup.exe /i /f $TempFile
#       $ChocolateyPackageParameters = "/i /f $TempFile"
        choco install -y "\\TERVIS.PRV\applications\Chocolatey\scdpm2016.2.0.0.nupkg" --package-parameters="/i /f $TempFile"
        Remove-Item $tempFile
        }
}

$DPMProtectionGroupDefinitions = [PSCustomObject][Ordered] @{
    Name = "1010OSBO3-pc"
},
[PSCustomObject][Ordered] @{
    Name = "Oracle"
}


function Get-TervisStoreDatabaseInformation {
    param(
        [parameter(Mandatory)]$Computername
    )
    $StoreBOSACred = Get-PasswordstatePassword -AsCredential -ID 56
    $StoreNumber = -join $Computername[0..3]
    $DBExceptions = "master","tempdb","model","msdb" 
    $DatabaseName = (Invoke-SQL -dataSource $Computername -database "master" -sqlCommand "select name from sys.databases WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb')" -Credential $StoreBOSACred).name
    [PSCustomObject][Ordered] @{
        DatabaseName = $DatabaseName
        StoreName = (Invoke-SQL -dataSource $Computername -database $DatabaseName -sqlCommand "select name from dbo.store WHERE id LIKE $StoreNumber" -Credential $StoreBOSACred).name
    }
}

function Get-DPMServers {
    param(
        [Switch]$Online
    )
    $DPMServers = Get-ADObject -Filter 'ObjectClass -eq "serviceConnectionPoint" -and Name -eq "MSDPM"'
    $DPMServerExclusionList
    $ADComputerObjects = Get-ADComputer -filter *
#    foreach($Computer in $DPMServers) {            
#        $ComputerObjectPath = ($Computer.DistinguishedName.split(",") | select -skip 1 ) -join ","
#            $DPMServerNames = get-adcomputer -Identity $ComputerObjectPath | select -ExpandProperty name #| where name -ne "inf-scdpmsql02" | select -ExpandProperty Name
#    }
    $Responses = Start-ParallelWork -ScriptBlock {
        param($ServerName,
            $ADComputerObjects
        )
        $ComputerObjectPath = ($ServerName.DistinguishedName.split(",") | select -skip 1 ) -join ","
#        $DPMServerName = get-adcomputer -Identity $ComputerObjectPath | select -ExpandProperty name 
        $DPMServerName = $ADComputerObjects | where DistinguishedName -eq $ComputerObjectPath | select -ExpandProperty name
[pscustomobject][ordered]@{
            DPMServerName = $DPMServerName;
            Online = $(Test-Connection -ComputerName $DPMServerName -Count 1 -Quiet);
        }
    } -Parameters $DPMServers -OptionalParameters $ADComputerObjects

    if ($Online) {
        $Responses |
        where Online -EQ $true |
        Select -ExpandProperty DPMServerName -ExcludeProperty RunspaceId
    } else {
        $Responses |
        Select -ExpandProperty DPMServerName -ExcludeProperty RunspaceId
    }
    #$Responses
}

function Invoke-DPMHealthCheck {
    param(
        [parameter(mandatory,ValueFromPipelineByPropertyName)]$DPMServerName
    )
    #$DPMServername = "inf-scdpmsql01"
    Connect-DPMServer $DPMServername | Out-Null
#    Write-Output "Getting Datasources"    
    $DPMDatasources = Get-DPMDatasource -DPMServerName $DPMServername | where state -eq "valid" # | Where-Object name -eq "TervisCustomizerApproval" #| Select-Object DPMServerName,Computer,Name,protectiongroupname
    $DPMDatasources | select latestrecoverypoint | Out-Null
#    write-output "getting protectiongroups"
    $DPMProtectionGroups = Get-DPMProtectionGroup -DPMServerName $DPMServername #| Where-Object name -eq "SQL-AllOthers"
    $StaleRecoveryPoints = @() #New-Object System.Object
    ForEach ($ProtectionGroup in $DPMProtectionGroups){
    #   $ProtectionGroup = $DPMProtectionGroups | where name -eq "fedex"
        $DatasourcesWithinProtectionGroup = $DPMDatasources | where ProtectionGroupName -eq $ProtectionGroup.Name
        $ProtectionGroupDiskSchedule = Get-DPMPolicySchedule -ProtectionGroup $ProtectionGroup -ShortTerm
        $ProtectionGroupOnlineSchedule = Get-DPMPolicySchedule -ProtectionGroup $ProtectionGroup -LongTerm Online
        $OldestIncrementalRecoveryPointPermitted = ""
        $DiskScheduleTimes = New-Object System.Collections.ArrayList
        $OnlineScheduleTimes = New-Object System.Collections.ArrayList
    
        $DiskTimesOfDay = $ProtectionGroupDiskSchedule.TimesofDay.ToShortTimeString()
        foreach($DiskRecoveryPointTime in $DiskTimesOfDay){
            $Timestamp = [datetime]("{0:HH:mm}" -f [datetime]$DiskRecoveryPointTime)
            if ($TimeStamp -gt (get-date)){
                $DiskScheduleTimes.Add($TimeStamp.AddDays(-1)) | Out-Null
            }
            else {
                $DiskScheduleTimes.Add($TimeStamp) | Out-Null
            }
        
        }
    
        $OnlineTimesOfDay = $ProtectionGroupOnlineSchedule.TimesofDay.ToShortTimeString()
        foreach($OnlineRecoveryPointTime in $OnlineTimesOfDay){
                $Timestamp = [datetime]("{0:HH:mm}" -f [datetime]$OnlineRecoveryPointTime)
                if ($TimeStamp -gt (get-date)){
                    $OnlineScheduleTimes.Add($TimeStamp.AddDays(-1)) | Out-Null
                }
                else {
                    $OnlineScheduleTimes.Add($TimeStamp) | Out-Null
                }
            
        }
    
#        $OldestDiskRecoveryPointPermitted = ($DiskScheduleTimes | Sort-Object -Descending | Select-Object -first 1).addminutes(-30)
#        $OldestOnlineRecoveryPointPermitted = $diskscheduletimes | where {$_ -lt ($OnlineScheduleTimes | Sort-Object -Descending | Select-Object -first 1)}
        
        if($ProtectionGroupDiskSchedule.JobType -eq "FullReplicationForApplication"){
            $IncrementalFrequency = $ProtectionGroupDiskSchedule.Frequency
            $OldestIncrementalRecoveryPointPermitted = (get-date).AddMinutes(-$IncrementalFrequency * 3)
            $OldestStoresIncrementalRecoveryPointPermitted = (get-date).AddHours(-18)
        }
            
        foreach ($Datasource in $DatasourcesWithinProtectionGroup){
     #      $Datasource = $DatasourcesWithinProtectionGroup | where name -eq "fedex"
             $DiskTimesOfDay = $ProtectionGroupDiskSchedule.TimesofDay.ToShortTimeString()
             foreach($DiskRecoveryPointTime in $DiskTimesOfDay){
                 $Timestamp = [datetime]("{0:HH:mm}" -f [datetime]$DiskRecoveryPointTime)
                 if ($TimeStamp -gt (get-date)){
                     $DiskScheduleTimes.Add($TimeStamp.AddDays(-1)) | Out-Null
                 }
                 else {
                     $DiskScheduleTimes.Add($TimeStamp) | Out-Null
                 }
             
             }
         
             $OnlineTimesOfDay = $ProtectionGroupOnlineSchedule.TimesofDay.ToShortTimeString()
             foreach($OnlineRecoveryPointTime in $OnlineTimesOfDay){
                     $Timestamp = [datetime]("{0:HH:mm}" -f [datetime]$OnlineRecoveryPointTime)
                     if ($TimeStamp -gt (get-date)){
                         $OnlineScheduleTimes.Add($TimeStamp.AddDays(-1)) | Out-Null
                     }
                     else {
                         $OnlineScheduleTimes.Add($TimeStamp) | Out-Null
                     }
                 
             }
         
            $OldestDiskRecoveryPointPermitted = ($DiskScheduleTimes | Sort-Object -Descending | Select-Object -first 1).addminutes(-30)
            $OldestOnlineRecoveryPointPermitted = $diskscheduletimes | where {$_ -lt ($OnlineScheduleTimes | Sort-Object -Descending | Select-Object -first 1)} | Select-Object -First 1
            $OldestSharepointRecoveryPointPermitted = ($DiskScheduleTimes | Sort-Object -Descending | Select-Object -first 1).addminutes(-30)


            $LatestOnlineRecoveryPoint = Get-DPMRecoveryPoint -Datasource $($DataSource) -Online -OnlyActive | Sort-Object BackupTime -Descending | Select-Object -first 1
            
            if ($OldestIncrementalRecoveryPointPermitted){
                if(($Datasource.protectiongroupname -match "Stores") -and ($Datasource.LatestRecoveryPoint -lt $OldestStoresIncrementalRecoveryPointPermitted)){
                    $Datasource | Add-Member -MemberType NoteProperty -Name RecoveryPointType -Value "Incremental" -Force
                    $Datasource | Add-Member -MemberType NoteProperty -Name LatestRecoveryPointTime -Value $Datasource.LatestRecoveryPoint -force
                    $Datasource | Add-Member -MemberType NoteProperty -Name OldestRecoveryPointPermitted -Value $OldestStoresIncrementalRecoveryPointPermitted -force
#                    $Output = $Datasource | Select-Object DPMServerName,Computer,Name,protectiongroupname,LatestRecoveryPointTime,OldestRecoveryPointPermitted,RecoveryPointType # | ft -AutoSize
#                    $StaleRecoveryPoint = [pscustomobject][ordered]@{
                    [pscustomobject][ordered]@{
                        DPMServerName = $Datasource.DPMServername
                        ComputerName = $Datasource.Computer
                        Name = $Datasource.Name
                        ProtectionGroupName = $Datasource.protectiongroupname
                        LatestRecoveryPointTime = $Datasource.LatestRecoveryPointTime
                        OldestRecoveryPointPermitted = $Datasource.OldestRecoveryPointPermitted
                        RecoveryPointType = $Datasource.RecoveryPointType
                    }
#                    [Array]$StaleRecoveryPoints += $StaleRecoveryPoint
                }
                elseif(($Datasource.LatestRecoveryPoint -lt $OldestIncrementalRecoveryPointPermitted) -and ($Datasource.protectiongroupname -notmatch "Stores") -and ($DatasourcesWithinProtectionGroup.protectiongroupname -notmatch "Sharepoint")){
                    $Datasource | Add-Member -MemberType NoteProperty -Name RecoveryPointType -Value "Incremental" -Force
                    $Datasource | Add-Member -MemberType NoteProperty -Name LatestRecoveryPointTime -Value $Datasource.LatestRecoveryPoint -force
                    $Datasource | Add-Member -MemberType NoteProperty -Name OldestRecoveryPointPermitted -Value $OldestIncrementalRecoveryPointPermitted -force
#                    $Output = $Datasource | Select-Object DPMServerName,Computer,Name,protectiongroupname,LatestRecoveryPointTime,OldestRecoveryPointPermitted,RecoveryPointType # | ft -AutoSize
#                    $StaleRecoveryPoint = [pscustomobject][ordered]@{
                    [pscustomobject][ordered]@{
                        DPMServerName = $Datasource.DPMServername
                        ComputerName = $Datasource.Computer
                        Name = $Datasource.Name
                        ProtectionGroupName = $Datasource.protectiongroupname
                        LatestRecoveryPointTime = $Datasource.LatestRecoveryPointTime
                        OldestRecoveryPointPermitted = $Datasource.OldestRecoveryPointPermitted
                        RecoveryPointType = $Datasource.RecoveryPointType
                    }
#                    [Array]$StaleRecoveryPoints += $StaleRecoveryPoint
                }
                elseif((($Datasource.LatestRecoveryPoint -lt $OldestSharepointRecoveryPointPermitted) -and ($datasource.protectiongroupname -match "Sharepoint"))){
                    $Datasource | Add-Member -MemberType NoteProperty -Name RecoveryPointType -Value "Incremental" -Force
                    $Datasource | Add-Member -MemberType NoteProperty -Name LatestRecoveryPointTime -Value $Datasource.LatestRecoveryPoint -force
                    $Datasource | Add-Member -MemberType NoteProperty -Name OldestRecoveryPointPermitted -Value $OldestSharepointRecoveryPointPermitted -force
#                    $Output = $Datasource | Select-Object DPMServerName,Computer,Name,protectiongroupname,LatestRecoveryPointTime,OldestRecoveryPointPermitted,RecoveryPointType # | ft -AutoSize
#                    $StaleRecoveryPoint = [pscustomobject][ordered]@{
                    [pscustomobject][ordered]@{
                        DPMServerName = $Datasource.DPMServername
                        ComputerName = $Datasource.Computer
                        Name = $Datasource.Name
                        ProtectionGroupName = $Datasource.protectiongroupname
                        LatestRecoveryPointTime = $Datasource.LatestRecoveryPointTime
                        OldestRecoveryPointPermitted = $Datasource.OldestRecoveryPointPermitted
                        RecoveryPointType = $Datasource.RecoveryPointType
                    }
#                    [Array]$StaleRecoveryPoints += $StaleRecoveryPoint
                }

            }
            else {
                if (($Datasource.LatestRecoveryPoint -lt $OldestDiskRecoveryPointPermitted) -and ($Datasource.protectiongroupname -notmatch "Sharepoint")) {
                    $Datasource | Add-Member -MemberType NoteProperty -Name RecoveryPointType -Value "Disk" -Force
                    $Datasource | Add-Member -MemberType NoteProperty -Name LatestRecoveryPointTime -Value $Datasource.LatestRecoveryPoint -force
                    $Datasource | Add-Member -MemberType NoteProperty -Name OldestRecoveryPointPermitted -Value $OldestDiskRecoveryPointPermitted -force
#                    $Output = $Datasource | Select-Object DPMServerName,Computer,Name,protectiongroupname,LatestRecoveryPointTime,OldestRecoveryPointPermitted,RecoveryPointType # | ft -AutoSize
#                    $StaleRecoveryPoint = [pscustomobject][ordered]@{
                    [pscustomobject][ordered]@{
                        DPMServerName = $Datasource.DPMServername
                        ComputerName = $Datasource.Computer
                        Name = $Datasource.Name
                        ProtectionGroupName = $Datasource.protectiongroupname
                        LatestRecoveryPointTime = $Datasource.LatestRecoveryPointTime
                        OldestRecoveryPointPermitted = $Datasource.OldestRecoveryPointPermitted
                        RecoveryPointType = $Datasource.RecoveryPointType
                    }
#                    [Array]$StaleRecoveryPoints += $StaleRecoveryPoint
                }
            }
            if (($LatestOnlineRecoveryPoint.BackupTime -lt $OldestOnlineRecoveryPointPermitted) -and ($Datasource.name -notmatch "ssp") -and ($Datasource.name -notmatch "spsearch")) {
                $Datasource | Add-Member -MemberType NoteProperty -Name RecoveryPointType -Value Online -Force
                $Datasource | Add-Member -MemberType NoteProperty -Name OldestRecoveryPointPermitted -Value $OldestOnlineRecoveryPointPermitted -force
                $Datasource | Add-Member -MemberType NoteProperty -Name LatestRecoveryPointTime -Value $($LatestOnlineRecoveryPoint.BackupTime) -force
#                $Output = $Datasource | Select-Object DPMServerName,Computer,Name,protectiongroupname,LatestRecoveryPointTime,OldestRecoveryPointPermitted,RecoveryPointType # | ft -AutoSize
#                    $StaleRecoveryPoint = [pscustomobject][ordered]@{
                    [pscustomobject][ordered]@{
                        DPMServerName = $Datasource.DPMServername
                        ComputerName = $Datasource.Computer
                        Name = $Datasource.Name
                        ProtectionGroupName = $Datasource.protectiongroupname
                        LatestRecoveryPointTime = $Datasource.LatestRecoveryPointTime
                        OldestRecoveryPointPermitted = $Datasource.OldestRecoveryPointPermitted
                        RecoveryPointType = $Datasource.RecoveryPointType
                    }
#                    [Array]$StaleRecoveryPoints += $StaleRecoveryPoint
            }    
#        $StaleRecoveryPoints
        }
    }
    Disconnect-DPMServer | Out-Null
}

 