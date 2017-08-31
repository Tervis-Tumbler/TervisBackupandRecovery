

$TervisDPMServers= [pscustomobject][ordered]@{
    DPmServerName="INF-SCDPM201601"
    Description = "SQL/Exchange Datasources "
    Role = "Primary"
    Location = "HQ"
},
[pscustomobject][ordered]@{
    DPmServerName="INF-SCDPM201602"
    Description = "Fileserver,Data Drive Datasources"
    Role = "Primary"
    Location = "HQ"
},
[pscustomobject][ordered]@{
    DPmServerName="INF-SCDPM201603"
    Description = "Secondary Off-Site"
    Role = "Secondary"
    Location = "Peak10"
},
[pscustomobject][ordered]@{
    DPmServerName="INF-DPM2016HQ1"
    Description = "DPM 2016 Primary"
    Role = "Primary"
    Location = "HQ"
}
[pscustomobject][ordered]@{
    DPmServerName="INF-DPM2016P10"
    Description = "DPM 2016 Secondary"
    Role = "Secondary"
    Location = "Peak10"
}

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
    param (
        $EnvironmentName
    )
    $ApplicationName = "SCDPM2016"
    Invoke-ApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    #$Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes | Set-SQLTCPEnabled -InstanceName CSI_Data -Architecture x86
    $Nodes | Set-SQLTCPIPAllTcpPort -InstanceName CSI_Data -Architecture x86
    $Nodes | New-SQLNetFirewallRule
}

function Invoke-SCDPM2016FSProvision {
    param (
        $EnvironmentName
    )
    $ApplicationName = "SCDPM2016FileServer"
    Invoke-ApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    #$Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    $Nodes | Set-SQLTCPEnabled -InstanceName CSI_Data -Architecture x86
    $Nodes | Set-SQLTCPIPAllTcpPort -InstanceName CSI_Data -Architecture x86
    $Nodes | New-SQLNetFirewallRule
}

function Invoke-SCDPM2016SQLProvision {
    param (
        $EnvironmentName
    )
    $ApplicationName = "SCDPM2016SQL"
    Invoke-ApplicationProvision -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
    #$Nodes = Get-TervisApplicationNode -ApplicationName $ApplicationName -EnvironmentName $EnvironmentName
#    $Nodes | Set-SQLTCPEnabled -InstanceName CSI_Data -Architecture x86
#    $Nodes | Set-SQLTCPIPAllTcpPort -InstanceName CSI_Data -Architecture x86
#    $Nodes | New-SQLNetFirewallRule
}

function Get-TervisStoreDatabaseLogFileUsage {
    $BOComputerListFromAD = Get-BackOfficeComputers 
    $StoreBOSACred = Get-PasswordstateCredential -PasswordID 56
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
    param (
        [Parameter(Mandatory)]$DPMServerName
    )
    $ScriptBlock = {
        $OldestRecoveryPointTimeAllowed = (get-date).AddHours(-24)
        Get-DPMDatasource | Where-Object { $_.LatestRecoveryPoint -lt $OldestRecoveryPointTimeAllowed -and $_.state -eq 'Valid'} | select computer,name,latestrecoverypoint,state | Out-Null
        Get-DPMDatasource | Where-Object { $_.LatestRecoveryPoint -lt $OldestRecoveryPointTimeAllowed -and $_.state -eq 'Valid'} | select computer,name,latestrecoverypoint -ExcludeProperty PSComputerName,RunspaceID
    }
    Invoke-Command -ComputerName $DPMServerName -ScriptBlock $ScriptBlock
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
    $OutputMessage = ""
    $FromAddress = "scheduledtasks@tervis.com"
    $ToAddress = "WindowsServerApplicationsAdministrator@tervis.com"
    $Subject = "TERVIS_RMSHQ1 Database Log File Above Threshold"
    $SMTPServer = "cudaspam.tervis.com"
    $LogFileThreshold = 10
    $Computer = "SQL.tervis.prv"
    $AllDB = Invoke-SQL -dataSource $Computer -database "master" -sqlCommand "dbcc sqlperf(logspace)"
    $RMSHQLogUtilization = ($AllDB | Where {$_.'database name' -eq "TERVIS_RMSHQ1"})."log space used (%)"
    
    if ($RMSHQLogUtilization -gt $LogFileThreshold){
        $OutputMessage += "TERVIS_RMSHQ1 Log Utilization is currently {0:N2}" -f $RMSHQLogUtilization + "%`n"
    }
    if ($OutputMessage){
        Send-MailMessage -From $FromAddress -to $ToAddress -subject $Subject -SmtpServer $SMTPServer -Body ($OutputMessage | FT -autosize | out-string -Width 200) 
    }
}

function Install-RMSHQLogFileUtilizationScheduledTasks {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $ScheduledTaskCredential = New-Object System.Management.Automation.PSCredential (Get-PasswordstateCredential -PasswordID 259)
        $Execute = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $Argument = '-NoProfile -Command Test-RMSHQLogFileUtilization'
    }
    process {
        $CimSession = New-CimSession -ComputerName $ComputerName
        If (-NOT (Get-ScheduledTask -TaskName Test-RMSHQLogFileUtilization -CimSession $CimSession -ErrorAction SilentlyContinue)) {
            Install-TervisScheduledTask -Credential $ScheduledTaskCredential -TaskName "RMSHQLogFileUtilizationMonitor" -Execute $Execute -Argument $Argument -RepetitionIntervalName EverWorkdayDuringTheDayEvery15Minutes -ComputerName $ComputerName
        }
    }
}

function Invoke-DPMSQLServer2014Install {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]$Node
    )
    $ApplicationName = $node.ApplicationName    $ApplicationDefinition = Get-TervisApplicationDefinition -Name $node.ApplicationName     $SQLSACredentials = Get-PasswordstateCredential -PasswordID ($ApplicationDefinition.Environments).SQLSAPassword -AsPlainText    $DPMServiceAccountCredentials = Get-PasswordstateCredential -PasswordID ($ApplicationDefinition.Environments).DPMServiceAccountPassword -AsPlainText    $ChocolateyPackageParameters = "/SAPWD=$($SQLSACredentials.Password) /AGTSVCACCOUNT=$($DPMServiceAccountCredentials.Username) /AGTSVCPASSWORD=$($DPMServiceAccountCredentials.Password) /SQLSVCACCOUNT=$($DPMServiceAccountCredentials.Username) /SQLSVCPASSWORD=$($DPMServiceAccountCredentials.Password) /RSSVCACCOUNT=$($DPMServiceAccountCredentials.Username) /RSSVCPASSWORD=$($DPMServiceAccountCredentials.Password)"    Invoke-Command -ComputerName $Node.ComputerName -ScriptBlock {        choco install -y "\\tervis.prv\Applications\Chocolatey\SQLServer2014SP2.1.0.1.nupkg" --package-parameters=$($using:ChocolateyPackageParameters)    }}function Invoke-DPMServer2016Install {    param (        [Parameter(Mandatory)]$Node
    )
        Begin {        $ApplicationDefinition = Get-TervisApplicationDefinition -Name $node.ApplicationName         $DPMProductKey = (Get-PasswordstateEntryDetails -PasswordID 4045).Password        $SQLSACredentials = Get-PasswordstateCredential -PasswordID ($ApplicationDefinition.Environments).SQLSAPassword -AsPlainText        $DPMInstallSourcePath = "\\tervis.prv\Applications\Installers\Microsoft\SCDPM2016"        
        $DPMInstallConfigFile = @"
        [OPTIONS]
        UserName = "Tervis"
        CompanyName = "Tervis"
        ProductKey = $DPMProductKey
        SQLMachineName = "$($Node.Computername)"
        SQLInstanceName = "mssqlserver"
        ReportingMachineName = "$($Node.ComputerName)"
        ReportingInstanceName = "mssqlserver"
"@    }    Process {        Invoke-Command -ComputerName $Node.ComputerName -ScriptBlock {            $TempFile = [io.path]::GetTempFileName() 
            $ChocolateyPackageParameters = "/i /f $Tempfile"            $using:DPMInstallConfigFile | Out-File -FilePath $tempFile            & CMD.exe /C Start /wait $using:DPMInstallSourcePath\setup.exe /i /f $TempFile            Remove-Item $tempFile        }    }}
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
    $StoreBOSACred = Get-PasswordstateCredential -PasswordID 56
    $StoreNumber = -join $Computername[0..3]
    $DBExceptions = "master","tempdb","model","msdb" 
    $DatabaseName = (Invoke-SQL -dataSource $Computername -database "master" -sqlCommand "select name from sys.databases WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb')" -Credential $StoreBOSACred).name
    [PSCustomObject][Ordered] @{
        DatabaseName = $DatabaseName
        StoreName = (Invoke-SQL -dataSource $Computername -database $DatabaseName -sqlCommand "select name from dbo.store WHERE id LIKE $StoreNumber" -Credential $StoreBOSACred).name
    }
}
