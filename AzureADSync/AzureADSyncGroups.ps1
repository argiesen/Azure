################# STEP 1 ###########################
#        COLLECT CLOUD GROUPS FROM AZURE AD        #
####################################################

# Export Azure AD only groups to CSV for further manipulation against on premise AD
# Requires AzureAD module, use Connect-AzureAD
$proxyAddreses = @{l='ProxyAddresses';e={($_.ProxyAddresses -join ';')}}
$azObjectId = @{l='AzObjectId';e={$_.ObjectId}}
Get-AzureADGroup -All $true | select DisplayName,SamAccountName,MailEnabled,Mail,MailNickName,$proxyAddreses,Description,ImmutableId,$azObjectId,AdObjectGuid,ObjectType,DirSyncEnabled,Notes | Export-Csv -NoTypeInformation .\AzureADGroups.csv



################# STEP 2 ###########################
#  UPDATE GROUP LIST WITH ON PREMISE INFORMATION: SAMACCOUNTNAME, OBJECTID
####################################################

# Require ActiveDirectory module
$aadGroups = Import-Csv .\AzureADGroups.csv

# Iterate through groups to get ObjectGUID and convert to Base64 string for ImmutableId and update aadGroups variable
$upnSuffixes = Get-AdForest | select UPNSuffixes -ExpandProperty UPNSuffixes
$upnSuffixes += (Get-AdForest).Name
foreach ($group in $aadGroups){
	$groupOut = $null
	
	#Match based on Mail attribute
	$mail = $group.Mail
	if ($groupOut -eq $null -and $group.Mail -ne "" -and $($groupOut = Get-ADGroup -Filter 'Mail -eq $mail' -Properties Mail)){
		Write-Host "Mail: $($group.Mail)"
	}
	
	#Last restort match based on DisplayName attribute
	$displayName = $group.DisplayName
	if ($groupOut -eq $null -and $($groupOut = Get-ADGroup -Filter 'Name -eq $displayName')){
		Write-Host "DisplayName: $($group.DisplayName)"
	}
	
	#Update group properties and calculate ImmutableId
	if ($groupOut){
		$group.SamAccountName = $groupOut.SamAccountName
		$group.AdObjectGUID = $groupOut.ObjectGUID
		if ($group.AdObjectGUID -ne $null -and $group.ImmutableId -eq ""){
			$group.ImmutableId = [System.Convert]::ToBase64String($($groupOut.ObjectGUID).tobytearray())
		}
	}else{
		Write-Host "No match: $($group.SamAccountName)"
	}
}

# Assumes you might be switching machines between doing on premise and Azure AD, if not, no need to export/import CSV
# Export to second CSV to preserve original CSV
$aadGroups | Export-Csv -NoTypeInformation .\AzureADGroups.csv



############# STEP 3 ###############
#  UPDATE IMMUTABLEID IN AZURE AD  #
####################################


# Import to update Azure AD with ImmutableId
$aadGroups = Import-Csv .\AzureADGroups.csv | where ImmutableId -ne ""

# Iterate through groups to update ImmutableId
# Requires AzureAD module
foreach ($group in $aadGroups){
	Add-Content AzureADLog.txt "$(Get-Date -Format yyyy.MM.dd-HH.mm.ss)"
	Add-Content AzureADLog.txt "$($group.DisplayName)"
	Add-Content AzureADLog.txt "$($group.SamAccountName)"
	Add-Content AzureADLog.txt "ObjectGUID: $ObjectGUID"
	Add-Content AzureADLog.txt "ImmutableId: $($group.ImmutableId)"
	Set-AzureADGroup -ObjectId $group.AzObjectId -ImmutableId $group.ImmutableId
	Add-Content AzureLog.txt ""
}
