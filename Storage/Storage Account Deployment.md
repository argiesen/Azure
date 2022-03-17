# Create storage account
```
<Insert code here>
```

# Enable AD DS authentication
```
# Download AzFilesHybrid module
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri https://github.com/Azure-Samples/azure-files-samples/releases/latest/download/AzFilesHybrid.zip -OutFile AzFilesHybrid.zip
Expand-Archive -Path AzFilesHybrid.zip -DestinationPath .\

# Run from a domain joined machine
Set-Location .\AzFilesHybrid
.\CopyToPSPath.ps1

# Import AzFilesHybrid module
Import-Module -Name AzFilesHybrid
```
Allow PowerShell to download any necessary modules. Restarting PowerShell and re-running the Import-Module command multiple times may be required.

Once complete, restart PowerShell before proceeding.
```
# Import AzFilesHybrid module
Import-Module -Name AzFilesHybrid

# Login with an Azure AD credential that has either storage account owner or contributer Azure role assignment
# If you are logging into an Azure environment other than Public (ex. AzureUSGovernment) you will need to specify that.
# See https://docs.microsoft.com/azure/azure-government/documentation-government-get-started-connect-with-ps
# for more information.
Connect-AzAccount

# Define parameters, $StorageAccountName currently has a maximum limit of 15 characters
$SubscriptionId = "<your-subscription-id-here>"
$ResourceGroupName = "<resource-group-name-here>"
$StorageAccountName = "<storage-account-name-here>"
$DomainAccountType = "<ComputerAccount|ServiceLogonAccount>" # Default is set as ComputerAccount
# If you don't provide the OU name as an input parameter, the AD identity that represents the storage account is created under the root directory.
$OuDistinguishedName = "<ou-distinguishedname-here>"
# Specify the encryption agorithm used for Kerberos authentication. Default is configured as "'RC4','AES256'" which supports both 'RC4' and 'AES256' encryption.
$EncryptionType = "<AES256|RC4|AES256,RC4>"

# Select the target subscription for the current session
Select-AzSubscription -SubscriptionId $SubscriptionId 

# Register the target storage account with your active directory environment under the target OU (for example: specify the OU with Name as "UserAccounts" or DistinguishedName as "OU=UserAccounts,DC=CONTOSO,DC=COM"). 
# You can use to this PowerShell cmdlet: Get-ADOrganizationalUnit to find the Name and DistinguishedName of your target OU. If you are using the OU Name, specify it with -OrganizationalUnitName as shown below. If you are using the OU DistinguishedName, you can set it with -OrganizationalUnitDistinguishedName. You can choose to provide one of the two names to specify the target OU.
# You can choose to create the identity that represents the storage account as either a Service Logon Account or Computer Account (default parameter value), depends on the AD permission you have and preference. 
# Run Get-Help Join-AzStorageAccountForAuth for more details on this cmdlet.

Join-AzStorageAccount `
        -ResourceGroupName $ResourceGroupName `
        -StorageAccountName $StorageAccountName `
        -DomainAccountType $DomainAccountType `
        -OrganizationalUnitDistinguishedName $OuDistinguishedName `
        -EncryptionType $EncryptionType

#Run the command below if you want to enable AES 256 authentication. If you plan to use RC4, you can skip this step.
Update-AzStorageAccountAuthForAES256 -ResourceGroupName $ResourceGroupName -StorageAccountName $StorageAccountName
```

# Create file share and assign permissions
```
New-AzRmStorageShare `
	-ResourceGroupName $resourceGroupName `
	-StorageAccountName $storageAccountName `
	-Name $shareName `
	-QuotaGiB 1024

# Assign file share permissions
# Get the name of the custom role
$FileShareContributorRole = Get-AzRoleDefinition "<role-name>" #Use one of the built-in roles: Storage File Data SMB Share Reader, Storage File Data SMB Share Contributor, Storage File Data SMB Share Elevated Contributor
# Constrain the scope to the target file share
$scope = "/subscriptions/<subscription-id>/resourceGroups/<resource-group>/providers/Microsoft.Storage/storageAccounts/<storage-account>/fileServices/default/fileshares/<share-name>"
# Assign the custom role to the target identity with the specified scope.
New-AzRoleAssignment -SignInName <user-principal-name> -RoleDefinitionName $FileShareContributorRole.Name -Scope $scope
```
