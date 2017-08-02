

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
        $PendingReboot = (Get-PendingReboot $Computer)
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
        $PendingReboot = (Get-PendingReboot $Computer)
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

Function Get-PendingReboot {
    <#
    .SYNOPSIS
        Gets the pending reboot status on a local or remote computer.
    
    .DESCRIPTION
        This function will query the registry on a local or remote computer and determine if the
        system is pending a reboot, from Microsoft updates, Configuration Manager Client SDK, Pending Computer 
        Rename, Domain Join or Pending File Rename Operations. For Windows 2008+ the function will query the 
        CBS registry key as another factor in determining pending reboot state.  "PendingFileRenameOperations" 
        and "Auto Update\RebootRequired" are observed as being consistant across Windows Server 2003 & 2008.
    	
        CBServicing = Component Based Servicing (Windows 2008+)
        WindowsUpdate = Windows Update / Auto Update (Windows 2003+)
        CCMClientSDK = SCCM 2012 Clients only (DetermineIfRebootPending method) otherwise $null value
        PendComputerRename = Detects either a computer rename or domain join operation (Windows 2003+)
        PendFileRename = PendingFileRenameOperations (Windows 2003+)
        PendFileRenVal = PendingFilerenameOperations registry value; used to filter if need be, some Anti-
                         Virus leverage this key for def/dat removal, giving a false positive PendingReboot
    
    .PARAMETER ComputerName
        A single Computer or an array of computer names.  The default is localhost ($env:COMPUTERNAME).
    
    .PARAMETER ErrorLog
        A single path to send error data to a log file.
    
    .EXAMPLE
        PS C:\> Get-PendingReboot -ComputerName (Get-Content C:\ServerList.txt) | Format-Table -AutoSize
    	
        Computer CBServicing WindowsUpdate CCMClientSDK PendFileRename PendFileRenVal RebootPending
        -------- ----------- ------------- ------------ -------------- -------------- -------------
        DC01           False         False                       False                        False
        DC02           False         False                       False                        False
        FS01           False         False                       False                        False
    
        This example will capture the contents of C:\ServerList.txt and query the pending reboot
        information from the systems contained in the file and display the output in a table. The
        null values are by design, since these systems do not have the SCCM 2012 client installed,
        nor was the PendingFileRenameOperations value populated.
    
    .EXAMPLE
        PS C:\> Get-PendingReboot
    	
        Computer           : WKS01
        CBServicing        : False
        WindowsUpdate      : True
        CCMClient          : False
        PendComputerRename : False
        PendFileRename     : False
        PendFileRenVal     : 
        RebootPending      : True
    	
        This example will query the local machine for pending reboot information.
    	
    .EXAMPLE
        PS C:\> $Servers = Get-Content C:\Servers.txt
        PS C:\> Get-PendingReboot -Computer $Servers | Export-Csv C:\PendingRebootReport.csv -NoTypeInformation
    	
        This example will create a report that contains pending reboot information.
    
    .LINK
        Component-Based Servicing:
        http://technet.microsoft.com/en-us/library/cc756291(v=WS.10).aspx
    	
        PendingFileRename/Auto Update:
        http://support.microsoft.com/kb/2723674
        http://technet.microsoft.com/en-us/library/cc960241.aspx
        http://blogs.msdn.com/b/hansr/archive/2006/02/17/patchreboot.aspx
    
        SCCM 2012/CCM_ClientSDK:
        http://msdn.microsoft.com/en-us/library/jj902723.aspx
    
    .NOTES
        Author:  Brian Wilhite
        Email:   bcwilhite (at) live.com
        Date:    29AUG2012
        PSVer:   2.0/3.0/4.0/5.0
        Updated: 27JUL2015
        UpdNote: Added Domain Join detection to PendComputerRename, does not detect Workgroup Join/Change
                 Fixed Bug where a computer rename was not detected in 2008 R2 and above if a domain join occurred at the same time.
                 Fixed Bug where the CBServicing wasn't detected on Windows 10 and/or Windows Server Technical Preview (2016)
                 Added CCMClient property - Used with SCCM 2012 Clients only
                 Added ValueFromPipelineByPropertyName=$true to the ComputerName Parameter
                 Removed $Data variable from the PSObject - it is not needed
                 Bug with the way CCMClientSDK returned null value if it was false
                 Removed unneeded variables
                 Added PendFileRenVal - Contents of the PendingFileRenameOperations Reg Entry
                 Removed .Net Registry connection, replaced with WMI StdRegProv
                 Added ComputerPendingRename
    #>
    
    [CmdletBinding()]
    param(
    	[Parameter(Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    	[Alias("CN","Computer")]
    	[String[]]$ComputerName="$env:COMPUTERNAME",
    	[String]$ErrorLog
    	)
    
    Begin {  }## End Begin Script Block
    Process {
      Foreach ($Computer in $ComputerName) {
    	Try {
    	    ## Setting pending values to false to cut down on the number of else statements
    	    $CompPendRen,$PendFileRename,$Pending,$SCCM = $false,$false,$false,$false
                            
    	    ## Setting CBSRebootPend to null since not all versions of Windows has this value
    	    $CBSRebootPend = $null
    						
    	    ## Querying WMI for build version
    	    $WMI_OS = Get-WmiObject -Class Win32_OperatingSystem -Property BuildNumber, CSName -ComputerName $Computer -ErrorAction Stop
    
    	    ## Making registry connection to the local/remote computer
    	    $HKLM = [UInt32] "0x80000002"
    	    $WMI_Reg = [WMIClass] "\\$Computer\root\default:StdRegProv"
    						
    	    ## If Vista/2008 & Above query the CBS Reg Key
    	    If ([Int32]$WMI_OS.BuildNumber -ge 6001) {
    		    $RegSubKeysCBS = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\")
    		    $CBSRebootPend = $RegSubKeysCBS.sNames -contains "RebootPending"		
    	    }
    							
    	    ## Query WUAU from the registry
    	    $RegWUAURebootReq = $WMI_Reg.EnumKey($HKLM,"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\")
    	    $WUAURebootReq = $RegWUAURebootReq.sNames -contains "RebootRequired"
    						
    	    ## Query PendingFileRenameOperations from the registry
    	    $RegSubKeySM = $WMI_Reg.GetMultiStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\Session Manager\","PendingFileRenameOperations")
    	    $RegValuePFRO = $RegSubKeySM.sValue
    
    	    ## Query JoinDomain key from the registry - These keys are present if pending a reboot from a domain join operation
    	    $Netlogon = $WMI_Reg.EnumKey($HKLM,"SYSTEM\CurrentControlSet\Services\Netlogon").sNames
    	    $PendDomJoin = ($Netlogon -contains 'JoinDomain') -or ($Netlogon -contains 'AvoidSpnSet')
    
    	    ## Query ComputerName and ActiveComputerName from the registry
    	    $ActCompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName\","ComputerName")            
    	    $CompNm = $WMI_Reg.GetStringValue($HKLM,"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName\","ComputerName")
    
    	    If (($ActCompNm -ne $CompNm) -or $PendDomJoin) {
    	        $CompPendRen = $true
    	    }
    						
    	    ## If PendingFileRenameOperations has a value set $RegValuePFRO variable to $true
    	    If ($RegValuePFRO) {
    		    $PendFileRename = $true
    	    }
    
    	    ## Determine SCCM 2012 Client Reboot Pending Status
    	    ## To avoid nested 'if' statements and unneeded WMI calls to determine if the CCM_ClientUtilities class exist, setting EA = 0
    	    $CCMClientSDK = $null
    	    $CCMSplat = @{
    	        NameSpace='ROOT\ccm\ClientSDK'
    	        Class='CCM_ClientUtilities'
    	        Name='DetermineIfRebootPending'
    	        ComputerName=$Computer
    	        ErrorAction='Stop'
    	    }
    	    ## Try CCMClientSDK
    	    Try {
    	        $CCMClientSDK = Invoke-WmiMethod @CCMSplat
    	    } Catch [System.UnauthorizedAccessException] {
    	        $CcmStatus = Get-Service -Name CcmExec -ComputerName $Computer -ErrorAction SilentlyContinue
    	        If ($CcmStatus.Status -ne 'Running') {
    	            Write-Warning "$Computer`: Error - CcmExec service is not running."
    	            $CCMClientSDK = $null
    	        }
    	    } Catch {
    	        $CCMClientSDK = $null
    	    }
    
    	    If ($CCMClientSDK) {
    	        If ($CCMClientSDK.ReturnValue -ne 0) {
    		        Write-Warning "Error: DetermineIfRebootPending returned error code $($CCMClientSDK.ReturnValue)"          
    		    }
    		    If ($CCMClientSDK.IsHardRebootPending -or $CCMClientSDK.RebootPending) {
    		        $SCCM = $true
    		    }
    	    }
                
    	    Else {
    	        $SCCM = $null
    	    }
    
    	    ## Creating Custom PSObject and Select-Object Splat
    	    $SelectSplat = @{
    	        Property=(
    	            'Computer',
    	            'CBServicing',
    	            'WindowsUpdate',
    	            'CCMClientSDK',
    	            'PendComputerRename',
    	            'PendFileRename',
    	            'PendFileRenVal',
    	            'RebootPending'
    	        )}
    	    New-Object -TypeName PSObject -Property @{
    	        Computer=$WMI_OS.CSName
    	        CBServicing=$CBSRebootPend
    	        WindowsUpdate=$WUAURebootReq
    	        CCMClientSDK=$SCCM
    	        PendComputerRename=$CompPendRen
    	        PendFileRename=$PendFileRename
    	        PendFileRenVal=$RegValuePFRO
    	        RebootPending=($CompPendRen -or $CBSRebootPend -or $WUAURebootReq -or $SCCM -or $PendFileRename)
    	    } | Select-Object @SelectSplat
    
    	} Catch {
    	    Write-Warning "$Computer`: $_"
    	    ## If $ErrorLog, log the file to a user specified location/path
    	    If ($ErrorLog) {
    	        Out-File -InputObject "$Computer`,$_" -FilePath $ErrorLog -Append
    	    }				
    	}			
      }## End Foreach ($Computer in $ComputerName)			
    }## End Process
    
    End {  }## End End
    
}## End Function Get-PendingReboot

function Invoke-DPMSQLServer2014Install {    [CmdletBinding(SupportsShouldProcess)]
    param (        [Parameter(Mandatory,ValueFromPipeline)]$Node
    )
    $ApplicationName = $node.ApplicationName    $ApplicationDefinition = Get-TervisApplicationDefinition -Name $node.ApplicationName     $SQLSACredentials = Get-PasswordstateCredential -PasswordID ($ApplicationDefinition.Environments).SQLSAPassword -AsPlainText    $DPMServiceAccountCredentials = Get-PasswordstateCredential -PasswordID ($ApplicationDefinition.Environments).DPMServiceAccountPassword -AsPlainText    $ChocolateyPackageParameters = "/SAPWD=$($SQLSACredentials.Password) /AGTSVCACCOUNT=$($DPMServiceAccountCredentials.Username) /AGTSVCPASSWORD=$($DPMServiceAccountCredentials.Password) /SQLSVCACCOUNT=$($DPMServiceAccountCredentials.Username) /SQLSVCPASSWORD=$($DPMServiceAccountCredentials.Password) /RSSVCACCOUNT=$($DPMServiceAccountCredentials.Username) /RSSVCPASSWORD=$($DPMServiceAccountCredentials.Password)"    Invoke-Command -ComputerName $Node.ComputerName -ScriptBlock {        choco install -y "\\tervis.prv\Applications\Chocolatey\SQLServer2014SP2.1.0.1.nupkg" --package-parameters=$($using:ChocolateyPackageParameters)    }}function Invoke-DPMServer2016Install {    param (        [Parameter(Mandatory)]$Node
    )
        Begin {        $ApplicationDefinition = Get-TervisApplicationDefinition -Name $node.ApplicationName         $DPMProductKey = (Get-PasswordstateEntryDetails -PasswordID 4045).Password        $SQLSACredentials = Get-PasswordstateCredential -PasswordID ($ApplicationDefinition.Environments).SQLSAPassword -AsPlainText        $DPMInstallSourcePath = "\\tervis.prv\Applications\Installers\Microsoft\SCDPM2016"        
        $DPMInstallConfigFile = @"
        [OPTIONS]
        UserName = "Tervis"
        CompanyName = "Tervis"
        ProductKey = $DPMProductKey
        SQLMachineName = "localhost"
        SQLInstanceName = "mssqlserver"
        ReportingMachineName = "localhost"
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
