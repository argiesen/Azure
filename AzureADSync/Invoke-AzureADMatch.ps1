[cmdletbinding()]
param (
	[Alias("Step1")]
	[switch]$ExportAzureAD,
	[Alias("Step2")]
	[switch]$MatchActiveDirectory,
	[Alias("Step3")]
	[switch]$UpdateImmutableId,
	[Alias("Step4")]
	[switch]$UpdateGroups,
	[string]$UserCSV = "AzureADUsers.csv",
	[string]$GroupCSV = "AzureADGroups.csv",
	[bool]$IncludeUsers = $true,
	[bool]$IncludeGroups = $true
)

function Write-Log {
	param(
		[string]$Message,
		[ValidateSet("File", "Screen", "FileAndScreen")]
		[string]$OutTo = "FileAndScreen",
		[ValidateSet("Info", "Warn", "Error", "Verb", "Debug")]
		[string]$Level = "Info",
		[ValidateSet("Black", "DarkMagenta", "DarkRed", "DarkBlue", "DarkGreen", "DarkCyan", "DarkYellow", "Red", "Blue", "Green", "Cyan", "Magenta", "Yellow", "DarkGray", "Gray", "White")]
		[String]$ForegroundColor = "White",
		[ValidateRange(1,30)]
		[int]$Indent = 0,
		[switch]$Clobber,
		[switch]$NoNewLine
	)

	if (!($LogPath)){
		$LogPath = "$($env:ComputerName)-$(Get-Date -f yyyyMMdd).log"
	}

	$msg = "{0} : {1,-5} : {2}{3}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Level.ToUpper(), ("  " * $Indent), $Message
	if ($OutTo -match "File"){
		if (($Level -ne "Verb") -or ($VerbosePreference -eq "Continue")){
			if ($Clobber){
				$msg | Out-File $LogPath -Force
			}else{
				$msg | Out-File $LogPath -Append
			}
		}
	}

	$msg = "{0}{1}" -f ("  " * $Indent), $Message
	if ($OutTo -match "Screen"){
		switch ($Level){
			"Info" {
				if ($NoNewLine){
					Write-Host $msg -ForegroundColor $ForegroundColor -NoNewLine
				}else{
					Write-Host $msg -ForegroundColor $ForegroundColor
				}
			}
			"Warn" {Write-Warning $msg}
			"Error" {$host.ui.WriteErrorLine($msg)}
			"Verb" {Write-Verbose $msg}
			"Debug" {Write-Debug $msg}
		}
	}
}

$LogPath = "AzureADMatch.log"
#$LogOutTo = "FileAndScreen"
$Indent = 0

#COLLECT CLOUD OBJECTS FROM AZURE AD
if ($ExportAzureAD){
	#Require AzureAD module, use Connect-AzureAD

	if ($IncludeUsers){
		#Export Azure AD users to CSV for further manipulation against on premise AD
		Write-Log "Exporting Azure AD user information to $UserCSV" -OutTo Screen
		$proxyAddresses = @{l='ProxyAddresses';e={($_.ProxyAddresses -match '^SMTP:|^SIP:') -join ';'}}
		$azObjectId = @{l='AzObjectId';e={$_.ObjectId}}
		$aadUsers = Get-AzureADUser -All $true | Select-Object DisplayName,SamAccountName,UserPrincipalName,Mail,$proxyAddresses,Description,GivenName,Surname,JobTitle,Department,CompanyName,StreetAddress,City,State,Country,PostalCode,TelephoneNumber,Mobile,AccountEnabled,ImmutableId,$azObjectId,AdObjectGuid,AdOU,ObjectType,UsageLocation,DirSyncEnabled,Notes

		#Filter out external identities
		$aadUsers | Where-Object {$_.UserPrincipalName -notmatch "#EXT#"} | Export-Csv -NoTypeInformation $UserCSV
	}

	if ($IncludeGroups){
		#Export Azure AD groups to CSV for further manipulation against on premise AD
		Write-Log "Exporting Azure AD group information to $GroupCSV" -OutTo Screen
		$proxyAddresses = @{l='ProxyAddresses';e={($_.ProxyAddresses -match '^SMTP:') -join ';'}}
		$azObjectId = @{l='AzObjectId';e={$_.ObjectId}}
		$aadGroups = Get-AzureADGroup -All $true | Select-Object DisplayName,SamAccountName,MailEnabled,Mail,MailNickName,$proxyAddresses,Members,Description,ImmutableId,OnPremisesSecurityIdentifier,$azObjectId,AdObjectGuid,AdOU,ObjectType,SecurityEnabled,DirSyncEnabled,Notes

		foreach ($group in $aadGroups){
			$group.Members = (Get-AzureADGroup -ObjectId $group.azObjectId | Get-AzureADGroupMember).UserPrincipalName -join ';'
		}

		$aadGroups | Export-Csv -NoTypeInformation $GroupCSV
	}
}

#UPDATE OBJECT LISTS WITH ON PREMISE INFORMATION: SAMACCOUNTNAME, OBJECTID, IMMUTABLEID
if ($MatchActiveDirectory){
	#Require ActiveDirectory module

	if ($IncludeUsers){
		$LogPath = "AzureADMatchUsers.log"
		Write-Log "Matching users"

		$aadUsers = Import-Csv $UserCSV

		#Iterate through users to get ObjectGUID and convert to Base64 string for ImmutableId and update aadUsers variable
		$upnSuffixes = Get-AdForest | Select-Object UPNSuffixes -ExpandProperty UPNSuffixes
		$upnSuffixes += (Get-AdForest).Name
		foreach ($user in $aadUsers){
			$userOut = $null

			#Match based on UserPrincipalName attribute
			$upnDomain = $($user.UserPrincipalName -split "@")[1]
			$upn = $user.UserPrincipalName
			if (($upnSuffixes | Foreach-Object {$upnDomain -match $_}) -and ($userOut = Get-ADUser -Filter 'UserPrincipalName -eq $upn' -Properties Mail)){
				if ($userOut.Mail -eq $user.Mail){
					Write-Log "UPN+MAIL: $($user.UserPrincipalName)"
				}else{
					Write-Log "UPN: $($user.UserPrincipalName)"
				}
			}

			#Match based on Mail attribute
			$mail = $user.Mail
			if ($null -eq $userOut){
				if ($user.Mail -ne "" -and ($userOut = Get-ADUser -Filter 'Mail -eq $mail' -Properties Mail)){
					Write-Log "MAIL: $($user.Mail)"
				}
			}

			#Last restort match based on DisplayName attribute
			$displayName = $user.DisplayName
			if ($null -eq $userOut){
				if (($userOut = Get-ADUser -Filter 'Name -eq $displayName')){
					Write-Log "DISPLAYNAME: $($user.DisplayName)"
				}
			}

			#Update user properties and calculate ImmutableId
			if ($userOut){
				$user.SamAccountName = $userOut.SamAccountName
				$user.AdObjectGUID = $userOut.ObjectGUID
				$user.AdOU = ($userOut.DistinguishedName -split "^(.+?),")[2]
				if ($null -ne $user.AdObjectGUID -and $user.ImmutableId -eq ""){
					$user.ImmutableId = [System.Convert]::ToBase64String($($userOut.ObjectGUID).ToByteArray())
				}
			}else{
				Write-Log "NOMATCH: $($user.UserPrincipalName)" -Level Warn
			}
		}

		#Assumes you might be switching machines between doing on premise and Azure AD, if not, no need to export/import CSV
		$aadUsers | Export-Csv -NoTypeInformation $UserCSV
		
		Write-Log #Create gap in logs
	}

	if ($IncludeGroups){
		$LogPath = "AzureADMatchGroups.log"
		Write-Log "Matching groups"

		$aadGroups = Import-Csv $GroupCSV

		#Iterate through groups to get ObjectGUID and convert to Base64 string for ImmutableId and update aadGroups variable
		$upnSuffixes = Get-AdForest | Select-Object UPNSuffixes -ExpandProperty UPNSuffixes
		$upnSuffixes += (Get-AdForest).Name
		foreach ($group in $aadGroups){
			$groupOut = $null

			#Match based on Mail attribute
			$mail = $group.Mail
			if ($group.Mail -ne "" -and ($groupOut = Get-ADGroup -Filter 'Mail -eq $mail' -Properties Mail)){
				Write-Log "MAIL: $($group.Mail)"
			}

			#Last restort match based on DisplayName attribute
			$displayName = $group.DisplayName
			if ($null -eq $groupOut -and ($groupOut = Get-ADGroup -Filter 'Name -eq $displayName')){
				Write-Log "DISPLAYNAME: $($group.DisplayName)"
			}

			#Update group properties and calculate ImmutableId
			if ($groupOut){
				$group.SamAccountName = $groupOut.SamAccountName
				$group.AdObjectGUID = $groupOut.ObjectGUID
				$group.AdOU = ($groupOut.DistinguishedName -split "^(.+?),")[2]
				if ($null -ne $group.AdObjectGUID -and $group.ImmutableId -eq ""){
					$group.ImmutableId = $groupOut.ObjectGUID
				}
			}else{
				Write-Log "NOMATCH: $($group.DisplayName)" -Level Warn
			}
		}

		#Assumes you might be switching machines between doing on premise and Azure AD, if not, no need to export/import CSV
		$aadGroups | Export-Csv -NoTypeInformation $GroupCSV
		
		Write-Log #Create gap in logs
	}
}

#UPDATE IMMUTABLEID IN AZURE AD
if ($UpdateImmutableId){
	if ($IncludeUsers){
		$LogPath = "AzureADMatchUsers.log"
		Write-Log "Updating ImmutableId for users"

		#Import to update Azure AD with ImmutableId
		$aadUsers = Import-Csv $UserCSV | Where-Object {$_.ImmutableId -ne ""}

		#Iterate through users to update ImmutableId
		foreach ($user in $aadUsers){
			Set-AzureADUser -ObjectId $user.AzObjectId -ImmutableId $user.ImmutableId

			if ($?){
				Write-Log "Updated ImmutableId for user: $($user.UserPrincipalName) / $($user.AzObjectId) / $($user.ImmutableId)"
			}else{
				Write-Log "Failed updating ImmutableId for user: $($user.UserPrincipalName) : $($Error[0].Exception.Message)" -Level Error
			}
		}
	}
}

#UPDATE GROUP PROXYADDRESSES IN AD
if ($UpdateGroups){
	if ($IncludeGroups){
		$LogPath = "AzureADMatchGroups.log"
		Write-Log "Updating ProxyAddresses for groups"

		#Import to update Azure AD with ImmutableId
		$aadGroups = Import-Csv $GroupCSV | Where-Object {$_.DirSyncEnabled -eq ""}

		#Iterate through groups to update ImmutableId
		foreach ($group in $aadGroups){
			foreach ($proxyAddress in ($group.ProxyAddresses -split ';')){
				Set-ADGroup -Identity $group.AdObjectGuid -Add @{'proxyAddresses'=$proxyAddress} -ErrorAction SilentlyContinue

				if ($?){
					Write-Log "Added ProxyAddress for group: $($group.DisplayName) / $proxyAddress"
				}else{
					Write-Log "Failed adding ProxyAddresses for group: $($group.DisplayName) / $proxyAddress : $($Error[0].Exception.Message)" -Level Error
				}
			}
		}
	}
}