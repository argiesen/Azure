# First remove duplicate synced users, if any

################# STEP 1 ###########################
#  COLLECT CLOUD ONLY USER ACCOUNTS FROM AZURE AD  #
####################################################

# Export Azure AD only users to CSV for further manipulation against on premise AD
# Requires AzureAD module, use Connect-AzureAD
$azObjectId = @{l='AzObjectId';e={$_.ObjectId}}
Get-AzureADUser -All $true | select DisplayName,SamAccountName,UserPrincipalName,Mail,ImmutableId,$azObjectId,AdObjectId,ObjectType,UsageLocation,DirSyncEnabled,Notes | Export-Csv -NoTypeInformation .\AzureADUsers.csv




################# STEP 2 ####################
#  GENERATE IMMUTABLEID FROM ON-PREMISE AD  #
#############################################

# Import Azure AD users except users who are already synced
# Require ActiveDirectory module
$aadUsers = Import-Csv .\AzureADUsers.csv | where DirSyncEnabled -ne true | where Mail -ne ""

# Iterate through users matching on DisplayName/Name to get ObjectGUID and convert to Base64 string for ImmutableId and update aadUsers variable
# DISPLAY NAME MUST BE AN EXACT MATCH
foreach ($user in $aadUsers){
	$userOut = Get-ADUser -Filter * -Properties Mail | where Mail -eq $user.Mail
	$user.SamAccountName = $userOut.SamAccountName
	$ObjectGUID = $userOut.ObjectGUID
	if ($ObjectGUID -ne $null){
		$user.ImmutableId = [System.Convert]::ToBase64String($ObjectGUID.tobytearray())
		Add-Content ADLog.txt "$(Get-Date -Format yyyy.MM.dd-HH.mm.ss)"
		Add-Content ADLog.txt "$($user.DisplayName)"
		Add-Content ADLog.txt "$($user.UserPrincipalName)"
		Add-Content ADLog.txt "ObjectGUID: $ObjectGUID"
		Add-Content ADLog.txt "ImmutableId: $($user.ImmutableId)"
		Add-Content ADLog.txt ""
	}
}

# Assumes you might be switching machines between doing on premise and Azure AD, if not, no need to export/import CSV
# Export to second CSV to preserve original CSV
$aadUsers | Export-Csv -NoTypeInformation .\AzureADUsers-Updated.csv




############# STEP 3 ###############
#  UPDATE IMMUTABLEID IN AZURE AD  #
####################################


# Import to update Azure AD with ImmutableId
$aadUsers = Import-Csv .\AzureADUsers-Updated.csv | where ImmutableId -ne ""

# Iterate through users to update ImmutableId
# Requires AzureAD module
foreach ($user in $aadUsers){
	Add-Content AzureADLog.txt "$(Get-Date -Format yyyy.MM.dd-HH.mm.ss)"
	Add-Content AzureADLog.txt "$($user.DisplayName)"
	Add-Content AzureADLog.txt "$($user.UserPrincipalName)"
	Add-Content AzureADLog.txt "ObjectGUID: $ObjectGUID"
	Add-Content AzureADLog.txt "ImmutableId: $($user.ImmutableId)"
	Set-AzureADUser -ObjectId $user.AzObjectId -ImmutableId $user.ImmutableId
	Add-Content AzureLog.txt ""
}


# UPDATE UPN SUFFIX

$oldSuffix = "api.local"
$newSuffix = "winglets.com"

$aadUsers = Import-Csv .\AzureADUsers-Updated.csv | where SamAccountName -ne ""

foreach ($user in $aadUsers){
	$newUpn = (Get-ADUser $user.SamAccountName).UserPrincipalName.Replace($oldSuffix,$newSuffix)
	Set-ADUser $user.SamAccountName -UserPrincipalName $newUpn
}

