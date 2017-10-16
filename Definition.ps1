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

$BackupDefinition = [PSCustomObject][Ordered]@{
    Name = "UnifiController"

}