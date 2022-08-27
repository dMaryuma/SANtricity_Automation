### This script will automate basic configuration for SANtricity implementation
#################################################
## Wrote by Daniel Maryuma NetApp PS . dmaryuma@netapp.com
## Version 1.0
## 28-Aug-2022
#################################################


Param (
   [Parameter(Mandatory=$true)]
   [String]$username,
   [Parameter(Mandatory=$False)]
   [String]$password,
   [Parameter(Mandatory=$true)]
   [String]$uri,
   [Parameter(Mandatory=$true,HelpMessage="Enter the full path to 'drivesSelected.json'")]
   [String]$drivesSelected,
   [Parameter(Mandatory=$true)]
   [String]$volumeGroup,
   [Parameter(Mandatory=$true)]
   [String]$volumes,
   [Parameter(Mandatory=$true)]
   [String]$hosts,
   [Parameter(Mandatory=$true)]
   [String]$mapLuns
)
# Ignore Self-Signed Certificate:
add-type @"
   using System.Net;
   using System.Security.Cryptography.X509Certificates;
   public class TrustAllCertsPolicy : ICertificatePolicy {
       public bool CheckValidationResult(
           ServicePoint srvPoint, X509Certificate certificate,
           WebRequest request, int certificateProblem) {
           return true;
       }
   }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# example
$username = "admin"
$password = "Netapp1!"
$uri = "https://192.168.0.61:8443/devmgr/v2/"
$drivesSelected = get-content "C:\scripts\drives_selected.json"
$volumeGroup = Get-Content "C:\scripts\volume_group1.json" | Convertfrom-Json
$volumes = get-content "C:\scripts\volumes.json" | ConvertFrom-Json
$hosts = get-content "C:\scripts\hosts.json" | ConvertFrom-Json
$mapLuns = get-content "C:\scripts\map_lun.json" | ConvertFrom-Json
$cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $($password | ConvertTo-SecureString -AsPlainText -Force)

# Getting storage system
try{
    $StorageSystem = Invoke-RestMethod -Method get -Credential $cred -ContentType "application/json" -uri $uri"storage-systems" -ErrorAction stop
}catch{Write-Host $_}

## Create VolumeGroup
# Select drives for storage-pool creation
try{
    $Drives = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/drives" -Body $($drivesSelected) -ErrorAction stop 
    # parse only DriveRef
    $a = @()
    foreach ($drive in $Drives){
        $a += $drive.driveRef
    }
    # Create Storage Pool (VolumeGroup)
    $volumeGroup.diskDriveIds = $a
    $result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/storage-pools" -Body ($volumeGroup|ConvertTo-Json) -ErrorAction stop 
    $volumeGroupRef = $result.extents.VolumeGroupRef
}catch{Write-Host $_}

### Get volumeGroupRef (maintenence) will delete
$volumeGroupRef = Invoke-RestMethod -Method get -Credential $cred -ContentType "application/json" -uri "$($uri)storage-systems/$($StorageSystem.id)/storage-pools" -ErrorAction stop
$volumeGroupRef = $volumeGroupRef.extents.volumeGroupRef

## Create Volumes
# Adding VolumeGroup to 'poolId'
foreach ($vol in $volumes){
    $vol.poolId = $volumeGroupRef
}
# Create Volumes
foreach ($vol in $volumes){
    try{
        $vol_post_result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/volumes" -Body ($vol|ConvertTo-Json) -ErrorAction stop
        $vol | Add-Member -MemberType NoteProperty "VolumeRef" -Value $vol_post_result.volumeRef -Force
    }catch{Write-Host "$_ For Creating volume $($vol.name)"}
}

## Creating Host
# Retrieving the Host Type and Host Ports
try{
    $HostsTypes = Invoke-RestMethod -Method get -Credential $cred -ContentType "application/json" -uri "$($uri)storage-systems/$($StorageSystem.id)/host-types" -ErrorAction stop
    $HostsPorts = Invoke-RestMethod -Method get -Credential $cred -ContentType "application/json" -uri "$($uri)storage-systems/$($StorageSystem.id)/unassociated-host-ports" -ErrorAction stop
}catch{Write-Host "$_"}

## Create Hosts
# replace the hosttype from name to index
foreach ($h in $hosts){
    foreach ($hostType in $hostsTypes){
        if ($h.hostType.index -like $hostType.code){
            $h.hostType.index = $hosttype.index
            break
        }
    }
    # create hosts
    try{
        $host_result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/hosts" -Body ($h|ConvertTo-Json) -ErrorAction stop
        $h | Add-Member -NotePropertyName "HostRef" -NotePropertyValue $host_result.hostRef
        }catch{write-host "$_ `r`n For creating host $($h.name)"}
}

## Map Luns
# replace 'mappableObjectid' and 'targetId' from names to ID
foreach ($lun in $mapLuns){
    foreach ($h in $hosts){
        if ($lun.targetId -like $h.name){
            $lun.targetId = $h.HostRef
            break
        }
    }
    foreach ($vol in $volumes){
        if ($lun.mappableObjectId -like $vol.name){
            $lun.mappableObjectId = $vol.VolumeRef
            break
        }
    }
}
# Mapping luns
foreach ($lun in $mapLuns){
    try{
        $lun_map_result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/volume-mappings" -Body ($lun|ConvertTo-Json) -ErrorAction stop
    }catch{write-host "$_ `r`n for lun mapping - volume ref: $($lun.mappableObjectId) to host ref: $($lun.targetId)"}
}

