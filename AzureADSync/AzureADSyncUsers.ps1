################# STEP 1 ###########################
#    COLLECT CLOUD USER ACCOUNTS FROM AZURE AD     #
####################################################

# Export Azure AD only users to CSV for further manipulation against on premise AD
# Requires AzureAD module, use Connect-AzureAD
$proxyAddreses = @{l='ProxyAddresses';e={($_.ProxyAddresses -match '^SMTP:|^SIP:') -join ';'}}
$azObjectId = @{l='AzObjectId';e={$_.ObjectId}}
Get-AzureADUser -All $true | select DisplayName,SamAccountName,UserPrincipalName,Mail,$proxyAddreses,Description,ImmutableId,$azObjectId,AdObjectGuid,ObjectType,UsageLocation,DirSyncEnabled,Notes | Export-Csv -NoTypeInformation .\AzureADUsers.csv



################# STEP 2 ###########################
#  UPDATE USER LIST WITH ON PREMISE INFORMATION: SAMACCOUNTNAME, OBJECTID
####################################################

# Require ActiveDirectory module
$aadUsers = Import-Csv .\AzureADUsers.csv

# Iterate through users to get ObjectGUID and convert to Base64 string for ImmutableId and update aadUsers variable
$upnSuffixes = Get-AdForest | select UPNSuffixes -ExpandProperty UPNSuffixes
$upnSuffixes += (Get-AdForest).Name
foreach ($user in $aadUsers){
	$userOut = $null
	
	#Match based on UserPrincipalName attribute
	$upnDomain = $($user.UserPrincipalName -split "@")[1]
	$upn = $user.UserPrincipalName
	if (($upnSuffixes | foreach {$upnDomain -match $_}) -and ($userOut = Get-ADUser -Filter 'UserPrincipalName -eq $upn' -Properties Mail)){
		if ($userOut.Mail -eq $user.Mail){
			Write-Host "UPN and Mail: $($user.UserPrincipalName)"
		}else{
			Write-Host "UPN: $($user.UserPrincipalName)"
		}
	}
	
	#Match based on Mail attribute
	$mail = $user.Mail
	if ($userOut -eq $null -and $user.Mail -ne "" -and $($userOut = Get-ADUser -Filter 'Mail -eq $mail' -Properties Mail)){
		Write-Host "Mail: $($user.Mail)"
	}
	
	#Last restort match based on DisplayName attribute
	$displayName = $user.DisplayName
	if ($userOut -eq $null -and $($userOut = Get-ADUser -Filter 'Name -eq $displayName')){
		Write-Host "DisplayName: $($user.DisplayName)"
	}
	
	#Update user properties and calculate ImmutableId
	if ($userOut){
		$user.SamAccountName = $userOut.SamAccountName
		$user.AdObjectGUID = $userOut.ObjectGUID
		if ($user.AdObjectGUID -ne $null -and $user.ImmutableId -eq ""){
			$user.ImmutableId = [System.Convert]::ToBase64String($($userOut.ObjectGUID).tobytearray())
		}
	}else{
		Write-Host "No match: $($user.UserPrincipalName)"
	}
}

# Assumes you might be switching machines between doing on premise and Azure AD, if not, no need to export/import CSV
# Export to second CSV to preserve original CSV
$aadUsers | Export-Csv -NoTypeInformation .\AzureADUsers.csv



############# STEP 3 ###############
#  UPDATE IMMUTABLEID IN AZURE AD  #
####################################


# Import to update Azure AD with ImmutableId
$aadUsers = Import-Csv .\AzureADUsers.csv | where ImmutableId -ne ""

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

############# STEP 4 ###############
#   UPDATE ON PREMISE UPN SUFFIX   #
####################################

$oldSuffix = "domain.local"
$newSuffix = "domain.com"

$aadUsers = Import-Csv .\AzureADUsers.csv | where SamAccountName -ne ""

foreach ($user in $aadUsers){
	$newUpn = (Get-ADUser $user.SamAccountName).UserPrincipalName.Replace($oldSuffix,$newSuffix)
	Set-ADUser $user.SamAccountName -UserPrincipalName $newUpn
}
