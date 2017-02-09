$TervisDPMServers= [pscustomobject][ordered]@{
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
    DPmServerName="DPM2012R2-3"
    Description = "SQL Backups"
    Role = "Primary"
    Location = "HQ"
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
    $DotNet45Confirm = {
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
    $Computername | % {
        $DotNetVersion = Invoke-Command -ComputerName $_ -ScriptBlock $DotNet45Confirm
        $Version = Invoke-Command -ComputerName $_ -ScriptBlock {$PSVersionTable.PSVersion}
        [pscustomobject][ordered]@{
            ComputerName = $_;
            DotNet45 = $DotNetVersion.Product;
            PSVersion = $Version
        }        
    }
}
