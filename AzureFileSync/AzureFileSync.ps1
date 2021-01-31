[cmdletbinding()]
param(
	[Parameter(Mandatory=$true)]
	[string]$AzureRegion,
	[Parameter(Mandatory=$true)]
	[string]$ResourceGroupName,
	[Parameter(Mandatory=$true)]
	[string]$StorageSyncServiceName,
	[Parameter(Mandatory=$true)]
	[string]$StorageSyncGroupName,
	[Parameter(Mandatory=$true)]
	[string]$StorageAccountName,
	[Parameter(Mandatory=$true)]
	[string]$FileShareName,
	[Parameter(Mandatory=$true)]
	[string]$LocalPath,
	[int]$FreeSpacePercentage = 20,
	[ValidateSet("NamespaceOnly", "NamespaceThenModifiedFiles", "AvoidTieredFiles")]
	[string]$InitialDownloadPolicy = "NamespaceOnly"
)

#Prepare Windows Server to use with Azure File Sync
$installType = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\").InstallationType

# This step is not required for Server Core
if ($installType -ne "Server Core") {
	# Disable Internet Explorer Enhanced Security Configuration for Administrators
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0 -Force
    
	# Disable Internet Explorer Enhanced Security Configuration for Users
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Value 0 -Force
    
	# Force Internet Explorer closed, if open. This is required to fully apply the setting.
	# Save any work you have open in the IE browser. This will not affect other browsers, including Microsoft Edge.
	Stop-Process -Name iexplore -ErrorAction SilentlyContinue
}

#Deploy the Storage Sync Service
$hostType = (Get-Host).Name

if ($installType -eq "Server Core" -or $hostType -eq "ServerRemoteHost") {
	Connect-AzAccount -UseDeviceAuthentication
}else{
	Connect-AzAccount
}

# this variable holds the Azure region you want to deploy Azure File Sync into
$region = $AzureRegion

# Check to ensure Azure File Sync is available in the selected Azure region.
$regions = @()
Get-AzLocation | ForEach-Object { 
	if ($_.Providers -contains "Microsoft.StorageSync") { 
		$regions += $_.Location 
	} 
}

if ($regions -notcontains $region) {
	throw [System.Exception]::new("Azure File Sync is either not available in the selected Azure Region or the region is mistyped.")
}

# the resource group to deploy the Storage Sync Service into
$resourceGroup = $ResourceGroupName

# Check to ensure resource group exists and create it if doesn't
$resourceGroups = @()
Get-AzResourceGroup | ForEach-Object { 
	$resourceGroups += $_.ResourceGroupName 
}

if ($resourceGroups -notcontains $resourceGroup) {
	New-AzResourceGroup -Name $resourceGroup -Location $region
}

$storageSyncName = $StorageSyncServiceName
$storageSync = New-AzStorageSyncService -ResourceGroupName $resourceGroup -Name $storageSyncName -Location $region

#Install the Azure File Sync agent
# Gather the OS version
$osver = [System.Environment]::OSVersion.Version

# Download the appropriate version of the Azure File Sync agent for your OS.
if ($osver.Equals([System.Version]::new(10, 0, 17763, 0))) {
	Invoke-WebRequest `
		-Uri https://aka.ms/afs/agent/Server2019 `
		-OutFile "StorageSyncAgent.msi" 
} elseif ($osver.Equals([System.Version]::new(10, 0, 14393, 0))) {
	Invoke-WebRequest `
		-Uri https://aka.ms/afs/agent/Server2016 `
		-OutFile "StorageSyncAgent.msi" 
} elseif ($osver.Equals([System.Version]::new(6, 3, 9600, 0))) {
	Invoke-WebRequest `
		-Uri https://aka.ms/afs/agent/Server2012R2 `
		-OutFile "StorageSyncAgent.msi" 
} else {
	throw [System.PlatformNotSupportedException]::new("Azure File Sync is only supported on Windows Server 2012 R2, Windows Server 2016, and Windows Server 2019")
}

# Install the MSI. Start-Process is used to PowerShell blocks until the operation is complete.
# Note that the installer currently forces all PowerShell sessions closed - this is a known issue.
Start-Process -FilePath "StorageSyncAgent.msi" -ArgumentList "/quiet" -Wait

# Note that this cmdlet will need to be run in a new session based on the above comment.
# You may remove the temp folder containing the MSI and the EXE installer
Remove-Item -Path ".\StorageSyncAgent.msi" -Recurse -Force


#Register Windows Server with Storage Sync Service
$registeredServer = Register-AzStorageSyncServer -ParentObject $storageSync


#Create a sync group and a cloud endpoint
$syncGroupName = $StorageSyncGroupName
$syncGroup = New-AzStorageSyncGroup -ParentObject $storageSync -Name $syncGroupName

# Get or create a storage account with desired name
#$storageAccountName = "<my-storage-account>"
$storageAccount = Get-AzStorageAccount -ResourceGroupName $resourceGroup | Where-Object {
	$_.StorageAccountName -eq $storageAccountName
}

if ($storageAccount -eq $null) {
	$storageAccount = New-AzStorageAccount `
		-Name $storageAccountName `
		-ResourceGroupName $resourceGroup `
		-Location $region `
		-SkuName Standard_LRS `
		-Kind StorageV2 `
		-EnableHttpsTrafficOnly:$true
}

# Get or create an Azure file share within the desired storage account
#$fileShareName = "<my-file-share>"
$fileShare = Get-AzStorageShare -Context $storageAccount.Context | Where-Object {
	$_.Name -eq $fileShareName -and $_.IsSnapshot -eq $false
}

if ($fileShare -eq $null) {
	$fileShare = New-AzStorageShare -Context $storageAccount.Context -Name $fileShareName
}

# Create the cloud endpoint
New-AzStorageSyncCloudEndpoint `
	-Name $fileShare.Name `
	-ParentObject $syncGroup `
	-StorageAccountResourceId $storageAccount.Id `
	-AzureFileShareName $fileShare.Name


#Create a server endpoint
$serverEndpointPath = $LocalPath
$cloudTieringDesired = $true
$volumeFreeSpacePercentage = $FreeSpacePercentage
# Optional property. Choose from: [NamespaceOnly] default when cloud tiering is enabled. [NamespaceThenModifiedFiles] default when cloud tiering is disabled. [AvoidTieredFiles] only available when cloud tiering is disabled.
#$initialDownloadPolicy = NamespaceOnly

if ($cloudTieringDesired) {
	# Ensure endpoint path is not the system volume
	$directoryRoot = [System.IO.Directory]::GetDirectoryRoot($serverEndpointPath)
	$osVolume = "$($env:SystemDrive)\"
	if ($directoryRoot -eq $osVolume) {
		throw [System.Exception]::new("Cloud tiering cannot be enabled on the system volume")
	}

	# Create server endpoint
	New-AzStorageSyncServerEndpoint `
		-Name $registeredServer.FriendlyName `
		-SyncGroup $syncGroup `
		-ServerResourceId $registeredServer.ResourceId `
		-ServerLocalPath $serverEndpointPath `
		-CloudTiering `
		-VolumeFreeSpacePercent $volumeFreeSpacePercentage `
		-InitialDownloadPolicy $initialDownloadPolicy
} else {
	# Create server endpoint
	New-AzStorageSyncServerEndpoint `
		-Name $registeredServer.FriendlyName `
		-SyncGroup $syncGroup `
		-ServerResourceId $registeredServer.ResourceId `
		-ServerLocalPath $serverEndpointPath `
		-InitialDownloadPolicy $initialDownloadPolicy
}
