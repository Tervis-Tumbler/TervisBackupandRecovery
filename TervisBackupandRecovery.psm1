function Get-TervisStoreDatabaseLogFileUsage {
$DBLogFileList = @()
$finalbolist = @()
$DaysInactive = 15  
$EarliestDateInactive = (Get-Date).Adddays(-($DaysInactive)) 
$BOComputerListFromAD = Get-ADComputer -SearchBase "OU=Back Office Computers,OU=Remote Store Computers,OU=Computers,OU=Stores,OU=Departments,DC=tervis,DC=prv" -Filter {LastLogonTimeStamp -gt $EarliestDateInactive} -Properties LastLogonTimeStamp 
$StoreBOSACred = Get-PasswordStateCredentialFromFile -SecuredAPIkeyFilePath "\\fs1\disasterrecovery\Source Controlled Items\SecuredCredential API Keys\StoreBOSA.APIKEY"
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