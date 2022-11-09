### This script will automate basic configuration for SANtricity implementation
#################################################
## Wrote by Daniel Maryuma NetApp PS . dmaryuma@netapp.com
## Version 1.1
## 28-Aug-2022

## Updated 1.2
## Add new functions and bug fixes 11/2022
#################################################


$username = "admin"
$password = "1q2w3e4R"
$ipAddress = "10.0.20.246"
#Param (
#   [Parameter(Mandatory=$true)]
#   [String]$username,
#   [Parameter(Mandatory=$true)]
#   [String]$password,
#   [Parameter(Mandatory=$true)]
#   [String]$ipAddress
#)
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
    foreach ($int in $managementInterfaces){
        foreach ($cont in $controllers){
            if ($int.controllerRef -eq 0){
                $int.controllerRef = $controllers[0].controllerRef
            }
            if ($int.controllerRef -eq 1){
                $int.controllerRef = $controllers[1].controllerRef
            }
        }
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
        foreach ($hostType in $HostsTypes){
            if ($h.hostType.index -like $hostType.name){
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
function FindiSCSIPortsReference(){
    $hardware_inventory = Invoke-RestMethod -Method get -Credential $cred -ContentType "application/json" -uri "$($uri)storage-systems/$($StorageSystem.id)/hardware-inventory" 
    $interfaces = Invoke-RestMethod -Method get -Credential $cred -ContentType "application/json" -uri "$($uri)storage-systems/$($StorageSystem.id)/interfaces?interfaceType=iscsi&channelType=hostside"
    # Add ControllerRef to $iscsiPorts
    foreach ($port in $iscsiPorts){
        if ($port.controller -like 'a'){
            $port | Add-Member -NotePropertyName "ControllerRef" -NotePropertyValue $controllers[0].controllerRef -force
        }
        elseif ($port.controller -like 'b'){
            $port | Add-Member -NotePropertyName "ControllerRef" -NotePropertyValue $controllers[1].controllerRef -force
        }
    }
    
    foreach ($port in $iscsiPorts){
        foreach ($channelPort in $hardware_inventory.channelPorts){
            if ($channelPort.physicalLocation.label -like $port.port){
                $tempPortRef = $channelPort.portRef
                foreach ($int in $interfaces){
                    if (($int.channelPortRef -like $tempPortRef) -and ($port.ControllerRef -like $int.controllerRef)){
                        # Found correct port with correct controllerRef
                        $port.iscsiInterface = $int.interfaceRef
                    }
                }
            }    
        }
    }
}
function ConfigureiSCSIPorts(){
    # Replace port with portRef
    foreach ($port in $iscsiPorts){
        $iscsiPorts_result = $null
        Write-Host "Configuring iSCSI port $($port.port) on controller $($port.controller)..."
        if ($port.controller -like 'a'){

            $port.psobject.Properties.Remove('controller')
            $port.psobject.Properties.Remove('port')
            $port.psobject.Properties.Remove('controllerRef')
            $iscsiPorts_result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/symbol/setIscsiInterfaceProperties?controller=a" -Body ($port | ConvertTo-Json -Depth 5)
        }
        elseif ($port.controller -like 'b'){
            $port.psobject.Properties.Remove('controller')
            $port.psobject.Properties.Remove('port')
            $port.psobject.Properties.Remove('controllerRef')
            $iscsiPorts_result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/symbol/setIscsiInterfaceProperties?controller=b" -Body ($port | ConvertTo-Json -Depth 5)
        }
        if ($iscsiPorts_result -like 'ok'){
            Write-Host "Successfuly configured port with ip address: $($port.settings.ipv4Address)" -ForegroundColor Green
        }
    }
}
function GetiSCSITarget(){
    $iscsi_target_result = Invoke-RestMethod -Method get -Credential $cred -ContentType "application/json" -uri "$($uri)storage-systems/$($StorageSystem.id)/iscsi/target-settings" 
    return $iscsi_target_result.nodeName.iscsiNodeName
}
function ConfigureSANtricityName(){
    $SANtricityName_result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/configuration" -Body ($SANtricityName | ConvertTo-Json)
}
function ChangeUnnamedDiscoverySessions(){
    $UnnamedDiscoverySession_result = Invoke-RestMethod -Method post -Credential $cred -Headers @{"accept"="application/json"; "Content-Type"="application/json"} -uri "$($uri)storage-systems/$($StorageSystem.id)/iscsi/entity" -Body ($UnnamedDiscoverySession | ConvertTo-Json)
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
try{

    $uri = "https://$($ipAddress):8443/devmgr/v2/"
	$drivesSelected = get-content "$PSScriptRoot\drives_selected.json"
    $volumeGroup = Get-Content "$PSScriptRoot\volume_group.json" | ConvertFrom-Json
    $volumes = get-content "$PSScriptRoot\volumes.json" | ConvertFrom-Json
    $hosts = get-content "$PSScriptRoot\hosts.json" | ConvertFrom-Json
    $hostCluster = Get-Content "$PSScriptRoot\hostCluster.json"| ConvertFrom-Json
    $mapLuns = get-content "$PSScriptRoot\map_lun.json" | ConvertFrom-Json
    $workloads = get-content "$PSScriptRoot\workloads.json" | ConvertFrom-Json
    $managementInterfaces = get-content "$PSScriptRoot\management_interfaces.json" | ConvertFrom-Json
    $iscsiPorts = Get-Content "$PSScriptRoot\iscsi_ports.json" | ConvertFrom-Json
    $SANtricityName = Get-Content "$PSScriptRoot\SANtricity_name.json" | ConvertFrom-Json
    $UnnamedDiscoverySession = Get-Content "$PSScriptRoot\unnamed_Discovery_Sessions.json" | ConvertFrom-Json
    $cred = new-object -typename System.Management.Automation.PSCredential -argumentlist $username, $($password | ConvertTo-SecureString -AsPlainText -Force)
}catch{write-host $_}



############ MAIN ############




try{
    $StorageSystem = GetStorageSystem
    ## Create VolumeGroup
    $controllers = GetControllers $StorageSystem
    Write-Host "Setting Storage Name..."
    ConfigureSANtricityName
    Write-Host "Storage name changed to '$($SANtricityName.name)'" -ForegroundColor Green
    Write-Host "Creating Volume Group..."
    $volumeGroupRef = CreateVolumeGroup
    Write-Host "Successfully created Volume Group" -ForegroundColor Green
    ## Create Workloads
    Write-Host "Creating Workloads..."
    CreateWorkloads
    Write-Host "Successfully created Workloads" -ForegroundColor Green
    ## Create Volumes
    Write-Host "Creating Volumes..."
	write-host $StorageSystem
    PrepareVolumesCreation
    CreateVolumes
    Write-Host "Successfully created Volumes" -ForegroundColor Green
    ## Creating Host
    Write-Host "Creating Hosts..."
    GetHostTypes ## Need to fill json with exact name as parameter $HostsTypes
    CreateHost
    Write-Host "Successfully created Hosts" -ForegroundColor Green
    ## Creating Host Cluster group
    Write-Host "Creating Hosts Group..."
    CreateHostCluster
    Write-Host "Successfully created Hosts Group" -ForegroundColor Green
    ## Map Luns
    Write-Host "Map Luns to Hosts..."
    MapLun
    Write-Host "Successfully mapped Luns" -ForegroundColor Green
    Write-Host "Chaning Unnamed Discovery Session..."
    ChangeUnnamedDiscoverySessions
    Write-Host "Unnamed Discovery Session changed to '$($UnnamedDiscoverySession.unnamedDiscoverySessionsEnabled)'" -ForegroundColor Green
    # Configure iSCSi ports:
    Write-Host "Configuring iSCSI interfaces..."
    FindiSCSIPortsReference
    ConfigureiSCSIPorts
    Write-Host "Successfully configured iscsi interfaces" -ForegroundColor Green

    # Get Target iSCSI iqn
    Write-Host "Printing Target IQN"
    $iscsi_target_iqn = GetiSCSITarget
    $iscsi_target_iqn | Out-File -FilePath "$PSScriptRoot\eseries_iqn.txt" -Force -NoNewline
    Write-Host "Printed IQN to file successfully" -ForegroundColor Green

    # If need to config dhcp, change field 'ipv4AddressConfigMethod' to 'configDhcp'
    Write-Host "Setting Management Interfaces..."
    $ethernetInterfaces = GetEthernetInterface $StorageSystem

    PrepareManamegemntInterface # Contoller B is index 0, Contoller A is index 1
    
    # Set interface ip address:
    foreach ($interface in $managementInterfaces){
        try{
            Write-Host "Setting ip, dns, ntp to controller $($interface.controllerRef)..."
            SetManagementInterface -StorageSystem $StorageSystem -interface $interface | Out-Null
            Write-Host "Mgmt ip Successfully configured on node $($interface.controllerRef)" -ForegroundColor Green
        }
        catch{write-host $_}
    }
}catch{Write-Host $_ -ForegroundColor Red}
