### This script will automate basic configuration for SANtricity implementation
#################################################
## Wrote by Daniel Maryuma NetApp PS . dmaryuma@netapp.com
## Version 1.1
## 28-Aug-2022
#################################################

Param (
   [Parameter(Mandatory=$true)]
   [String]$username,
   [Parameter(Mandatory=$False)]
   [String]$password,
   [Parameter(Mandatory=$true)]
   [String]$ipAddress
)
#### Functions ####
function GetEthernetInterface($storageSystem){
    $ethernetInterfaces = Invoke-RestMethod -Method get -Credential $cred -ContentType "application/json" -uri "$($uri)storage-systems/$($StorageSystem.id)/configuration/ethernet-interfaces" 
    return $ethernetInterfaces
}
function GetControllers($StorageSystem){
    $controllers = Invoke-RestMethod -Method get -Credential $cred -ContentType "application/json" -uri "$($uri)storage-systems/$($StorageSystem.id)/controllers" 
    return $controllers
}
function SetManagementInterface($StorageSystem, $interface){
    $result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/configuration/ethernet-interfaces" -Body ($interface|ConvertTo-Json -Depth 5)
    return $result
}
function PrepareManamegemntInterface(){
    #set controllerRef
    for ($i = 0; $i -lt $managementInterfaces.Length; $i++){
        $managementInterfaces[$i].controllerRef = $controllers[$i].controllerRef
    }
    #set interfaceRef
    foreach ($int in $managementInterfaces){
        foreach ($eth in $ethernetInterfaces){
            if ($int.interfaceName -like $eth.interfaceName -and $int.controllerRef -like $eth.controllerRef){
                $int.interfaceRef = $eth.interfaceRef
            }
        }
    }
}
function GetStorageSystem(){
    $StorageSystem = Invoke-RestMethod -Method get -Credential $cred -ContentType "application/json" -uri "$($uri)storage-systems" 
    return $StorageSystem
}
function CreateVolumeGroup(){
    $Drives = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/drives" -Body $($drivesSelected)
    # parse only DriveRef
    $a = @()
    foreach ($drive in $Drives){
        $a += $drive.driveRef
    }
    # Create Storage Pool (VolumeGroup)
    $volumeGroup.diskDriveIds = $a
    $result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/storage-pools" -Body ($volumeGroup|ConvertTo-Json)
    $volumeGroupRef = $result.extents.VolumeGroupRef
    return $volumeGroupRef
}
function CreateWorkloads(){
    foreach($workload in $workloads){
        $workload_post_result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/workloads" -Body ($workload|ConvertTo-Json)
        $workload | Add-Member -NotePropertyName "id" -NotePropertyValue $workload_post_result.id -Force
    }
}
function PrepareVolumesCreation(){
    # Adding VolumeGroup to 'poolId'
    foreach ($vol in $volumes){
        $vol.poolId = $volumeGroupRef
    }
    # Change workload name to id
    for ($i=0; $i -lt $volumes.Length; $i++){
        for ($j=0; $j -lt $volumes[$i].metaTags.length; $j++){
            for ($k=0; $k -lt $workloads.Length; $k++){
                if ($volumes[$i].metaTags[$j].value -like $workloads[$k].name){
                    $volumes[$i].metaTags[$j].value = $workloads[$k].id
                }
            }
        }
    }
}
function CreateVolumes(){
    # Create Volumes
    foreach ($vol in $volumes){
        try{
            $vol_post_result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/volumes" -Body ($vol|ConvertTo-Json) 
            $vol | Add-Member -MemberType NoteProperty "VolumeRef" -Value $vol_post_result.volumeRef -Force
        }catch{Write-Host "$_ For Creating volume $($vol.name)"}
    }
}
function GetHostTypes(){
    # Retrieving the Host Type and Host Ports
    $global:HostsTypes = Invoke-RestMethod -Method get -Credential $cred -ContentType "application/json" -uri "$($uri)storage-systems/$($StorageSystem.id)/host-types" 
    $global:HostsPorts = Invoke-RestMethod -Method get -Credential $cred -ContentType "application/json" -uri "$($uri)storage-systems/$($StorageSystem.id)/unassociated-host-ports" 
}
function CreateHost(){
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
            $host_result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/hosts" -Body ($h|ConvertTo-Json)
            $h | Add-Member -NotePropertyName "HostRef" -NotePropertyValue $host_result.hostRef -force
        }catch{Write-Host $_}
    }
}
function CreateHostCluster(){
    ## Create Host Cluster
    # retrieving host ref and add-member by $hosts
    for ($i=0; $i -lt $hostCluster.Length; $i++){
        for ($j=0; $j -lt $hostCluster[$i].hosts.length; $j++){
            for ($k=0; $k -lt $hosts.Length; $k++){
                if ($hostCluster[$i].hosts[$j] -like $hosts[$k].name){
                    $hostCluster[$i].hosts[$j] = $hosts[$k].hostRef
                }
            }
        }
    }
    foreach ($host_cluster in $hostCluster){
        try{
            $host_cluster_post_result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/host-groups" -Body ($host_cluster|ConvertTo-Json)
            }catch{Write-Host $_}
    }
}
function MapLun(){
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
            $lun_map_result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/volume-mappings" -Body ($lun|ConvertTo-Json)
            }catch{Write-Host $_}
    }
}
#### END Functions
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

# initialize parameters and json files
$ErrorActionPreference = "STOP"
#$username = "admin"
#$password = "Netapp1!"
try{
    $uri = "https://$($ipAddress):8443/devmgr/v2/"
    $drivesSelected = get-content "$PSScriptRoot\drives_selected.json"
    $volumeGroup = Get-Content "$PSScriptRoot\volume_group.json" 
    $volumes = get-content "$PSScriptRoot\volumes.json" | ConvertFrom-Json
    $hosts = get-content "$PSScriptRoot\hosts.json" | ConvertFrom-Json
    $hostCluster = Get-Content "$PSScriptRoot\hostCluster.json"| ConvertFrom-Json
    $mapLuns = get-content "$PSScriptRoot\map_lun.json" | ConvertFrom-Json
    $workloads = get-content "$PSScriptRoot\workloads.json" | ConvertFrom-Json
    $managementInterfaces = get-content "$PSScriptRoot\management_interfaces.json" | ConvertFrom-Json
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $($password | ConvertTo-SecureString -AsPlainText -Force)
}catch{write-host $_}

############ MAIN ############



### Get volumeGroupRef (maintenence) will delete
#    $volumeGroupRef = Invoke-RestMethod -Method get -Credential $cred -ContentType "application/json" -uri "$($uri)storage-systems/$($StorageSystem.id)/storage-pools"
#    $volumeGroupRef = $volumeGroupRef.extents.volumeGroupRef


# Getting storage system
try{
    $StorageSystem = GetStorageSystem
    ## Create VolumeGroup
    #$volumeGroupRef = CreateVolumeGroup
    ## Create Workloads
    Write-Host "Creating Workloads..." -ForegroundColor Green
    CreateWorkloads
    ## Create Volumes
    Write-Host "Creating Volumes..." -ForegroundColor Green
    PrepareVolumesCreation
    CreateVolumes
    ## Creating Host
    Write-Host "Creating Hosts..." -ForegroundColor Green
    GetHostTypes
    CreateHost
    ## Creating Host Cluster group
    Write-Host "Creating Hosts Group..." -ForegroundColor Green
    CreateHostCluster
    ## Map Luns
    Write-Host "Map Luns to Hosts..." -ForegroundColor Green
    MapLun
    ## Set Management Inferface:
    # get ethernetInterfaces and controllers

    $ethernetInterfaces = GetEthernetInterface $StorageSystem
    $controllers = GetControllers $StorageSystem
    PrepareManamegemntInterface
    # Set interface ip address:
    foreach ($interface in $managementInterfaces){
        try{
            Write-Host "Setting ip, dns, ntp to controller $($interface.controllerRef)..." -ForegroundColor Green
            SetManagementInterface -StorageSystem $StorageSystem -interface $interface
        }
        catch{write-host $_}
    }
}catch{Write-Host $_}
