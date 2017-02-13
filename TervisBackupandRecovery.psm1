﻿$TervisDPMServers= [pscustomobject][ordered]@{
    DPmServerName="DPM2012R2-1"
    Description = "FileServer Backups"
    Role = "Primary"
    Location = "HQ"
},
[pscustomobject][ordered]@{
    DPmServerName="DPM2012R2-2"
    Description = "Offsite Secondary"
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

function Get-TervisStoreDatabaseLogFileUsage {
    param(
        [string]$PasswordstateListAPIKey = $(Get-PasswordStateAPIKey)
    )
$DBLogFileList = @()
$finalbolist = @()
$DaysInactive = 15  
$EarliestDateInactive = (Get-Date).Adddays(-($DaysInactive)) 
$BOComputerListFromAD = Get-ADComputer -SearchBase "OU=Back Office Computers,OU=Remote Store Computers,OU=Computers,OU=Stores,OU=Departments,DC=tervis,DC=prv" -Filter {LastLogonTimeStamp -gt $EarliestDateInactive} -Properties LastLogonTimeStamp 
$StoreBOSACred = Get-PasswordstateCredential -PasswordID 56 -AsPlainText -PasswordstateListAPIKey $PasswordstateListAPIKey
$BOExceptions = "1010osmgr02-pc","1010osbr-pc","1010osbo2-pc","LPTESTBO-VM"
$DBExceptions = "master","tempdb","model","msdb" 
$BOComputerListFromAD = $BOComputerListFromAD | Where {$BOExceptions -NotContains $_.name}

Foreach ($Computer in $BOComputerListFromAD)
    {
        Write-host $computer.name
        $dblist = Invoke-Sqlcmd -ServerInstance $Computer.name -Username sa -Password $StoreBOSACred.password -Query "dbcc sqlperf(logspace)"
        $dblist = $dblist | Where {$DBExceptions -notcontains $_.'database name'}
        $DBOutput = [pscustomobject][ordered]@{
            "Computername" = $computer.Name
            "Database Name" = $dblist.'Database Name'
            "Log Size (MB)" = "{0:0.00}" -f $dblist.'Log Size (MB)'
            "Log Consumed (%)" = "{0:.00}" -f $dblist.'Log Space Used (%)'
        }
        $DBLogFileList += $DBOutput
    }
$DBLogFileList
}

function Get-BackOfficeComputersNotProtectedByDPM {
    $DaysInactive = 15  
    $LastLogonStartDateRange = (Get-Date).Adddays(-($DaysInactive)) 
    $DPMServerName = "dpm2012r2-1.tervis.prv"
    
    $DPMProtectedStores = Invoke-Command -ComputerName $DPMServerName -ScriptBlock {Get-DPMProtectionGroup | where name -eq "stores-bo" | Get-Datasource | select computer}
    $BOComputerListFromAD = Get-ADComputer -SearchBase "OU=Back Office Computers,OU=Remote Store Computers,OU=Computers,OU=Stores,OU=Departments,DC=tervis,DC=prv" -Filter {LastLogonTimeStamp -gt $LastLogonStartDateRange} -Properties LastLogonTimeStamp 
    $BOExceptions = "1010osmgr02-pc","1010osbr-pc","1010osbo2-pc","LPTESTBO-VM"
    $BOComputerListFromADWithoutExceptions = $BOComputerListFromAD | Where {$BOExceptions -NotContains $_.name}
    Compare-Object $DPMProtectedStores.computer $BOComputerListFromADWithoutExceptions.name
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
        [pscustomobject][ordered]@{
            ComputerName = $Computer
            DotNet45 = $DotNetVersion.Product
            Choco = $Chocolatey
            PSVersion = $Version
        }
    } | select * -ExcludeProperty RunspaceId | ft
}

function Install-SoftwareRemoteChocolatey{
    [CmdletBinding()]
    param(
        [parameter(Mandatory)] $Computerlist = "localhost"
    )
    Start-ParallelWork -Parameters $Computerlist -ScriptBlock {
        param($Computer)
        Invoke-Command -ComputerName $Computer -ScriptBlock {iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1'))} | Out-Null
        $Chocolatey = Invoke-Command -ComputerName $Computer -ScriptBlock {Get-Command choco -erroraction SilentlyContinue | Out-Null; $?}
        [pscustomobject][ordered]@{
            ComputerName = $Computer
            "Install Success" = $Chocolatey
        }
    } | select * -ExcludeProperty RunspaceId | ft

}

function Install-SoftwareRemotePowershell5{
    [CmdletBinding()]
    param(
        [parameter(Mandatory)] $Computerlist
    )
    Start-ParallelWork -Parameters $Computerlist -ScriptBlock {
        param($Computer)
        psexec -s \\$Computer -e choco install powershell -y
        Invoke-Command -ComputerName $Computer -ScriptBlock {shutdown /r /t 60 "This system will restart as scheduled in 60 seconds. Thank you - Tervis IT"}
        Wait-ForPortNotAvailable -ComputerName $Computer -PortNumbertoMonitor 5985
        Wait-ForPortAvailable -ComputerName $Computer -PortNumbertoMonitor 5985
        $PSVersion = Invoke-Command -ComputerName $Computer -ScriptBlock {$PSVersionTable.PSVersion}
        [pscustomobject][ordered]@{
            ComputerName = $Computer
            "PSVersion" = $PSVersion
        }
    } | select * -ExcludeProperty RunspaceId | ft
}

function Get-ComputerswithRSManEnabled{
    param(
        [Parameter(ValueFromPipeline)]$computer
    )
    $Responses = Start-RSParallelWork -ScriptBlock {
        param($Parameter)
        [pscustomobject][ordered]@{
            ComputerName = $Parameter;
            WSMan = $(Test-WSMan -ComputerName $Parameter -ErrorAction SilentlyContinue | Out-Null; $?);
        }
    } -Parameters $Computer

    $Responses | 
    where WSMan -eq $true |
    Select -ExpandProperty Computername
}
