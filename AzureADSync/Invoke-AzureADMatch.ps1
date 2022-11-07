[cmdletbinding()]
param (
	[Alias("Step1")]
	[switch]$ExportAzureAD,
	[Alias("Step2")]
	[switch]$MatchActiveDirectory,
	[Alias("Step3")]
	[switch]$UpdateImmutableId,
	[string]$UserCSV = "AzureADUsers.csv",
	[string]$GroupCSV = "AzureADGroups.csv",
	[string]$UserUPNFilter,
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
	Import-Module AzureAD -ErrorAction SilentlyContinue | Out-Null
	if (!$?){
		Write-Log "Unable to import AzureAD PS module. Quitting." -Level "Error"
		return
	}

	#Connect to Azure AD
	try{
		$AzureConnectivity = Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue
	}catch{
		#Continue
	}
	if (!$AzureConnectivity){
		Write-Log "Connecting to AzureAD..."
		try{
			Connect-AzureAD -ErrorAction SilentlyContinue | Out-Null
		}catch{
			Write-Log "Unable to connect to Azure AD. Quitting." -Level "Error"
			return
		}
	}

	if ($IncludeUsers){
		#Export Azure AD users to CSV for further manipulation against on premise AD
		$proxyAddresses = @{l='ProxyAddresses';e={($_.ProxyAddresses -match '^SMTP:|^SIP:') -join ';'}}
		$azObjectId = @{l='AzObjectId';e={$_.ObjectId}}
		if ($UserUPNFilter){
			$aadUsers = Get-AzureADUser -All $true | Where-Object {$_.DirSyncEnabled -eq $null -and $_.AccountEnabled -eq $true -and $_.UserPrincipalName -notmatch "#EXT#" -and $_.UserPrincipalName -notmatch $UserUPNFilter} | Select-Object DisplayName,SamAccountName,UserPrincipalName,Mail,AdMail,$proxyAddresses,AdProxyAddresses,Description,GivenName,Surname,JobTitle,Department,CompanyName,StreetAddress,City,State,Country,PostalCode,TelephoneNumber,Mobile,ImmutableId,$azObjectId,AdObjectGuid,AdDN,AdOU,ObjectType,Created,UsageLocation,Notes
		}else{
			$aadUsers = Get-AzureADUser -All $true | Where-Object {$_.DirSyncEnabled -eq $null -and $_.AccountEnabled -eq $true -and $_.UserPrincipalName -notmatch "#EXT#"} | Select-Object DisplayName,SamAccountName,UserPrincipalName,Mail,AdMail,$proxyAddresses,AdProxyAddresses,Description,GivenName,Surname,JobTitle,Department,CompanyName,StreetAddress,City,State,Country,PostalCode,TelephoneNumber,Mobile,ImmutableId,$azObjectId,AdObjectGuid,AdDN,AdOU,ObjectType,Created,UsageLocation,Notes
		}

		Write-Log "Exporting Azure AD user information to $UserCSV" -OutTo Screen
		$aadUsers | Export-Csv -NoTypeInformation $UserCSV
	}

	if ($IncludeGroups){
		#Export Azure AD groups to CSV for further manipulation against on premise AD
		$proxyAddresses = @{l='ProxyAddresses';e={($_.ProxyAddresses -match '^SMTP:') -join ';'}}
		$members = @{l='Members';e={(Get-AzureADGroup -ObjectId $_.ObjectId | Get-AzureADGroupMember).UserPrincipalName -join ';'}}
		$azObjectId = @{l='AzObjectId';e={$_.ObjectId}}
		$aadGroups = Get-AzureADGroup -All $true | Where-Object {$_.DirSyncEnabled -eq $null -and ((($_.ProxyAddresses -match '^SMTP:|^SPO:') -join ';') -notmatch "SPO:")} | Select-Object DisplayName,SamAccountName,MailEnabled,Mail,AdMail,MailNickName,$proxyAddresses,AdProxyAddresses,$members,Description,SecurityEnabled,ImmutableId,OnPremisesSecurityIdentifier,$azObjectId,AdObjectGuid,AdDN,AdOU,ObjectType,Created,Notes

		#Define group type
		foreach ($group in $aadGroups){
			if ($group.SecurityEnabled -eq $true){
				if ($group.MailEnabled -eq $true){
					$group.ObjectType = "GroupMailSecurity"
				}else{
					$group.ObjectType = "GroupSecurity"
				}
			}elseif ($group.MailEnabled -eq $true){
				$group.ObjectType = "GroupDistribution"
			}
		}

		#Export non-M365 groups
		Write-Log "Exporting Azure AD group information to $GroupCSV" -OutTo Screen
		$aadGroups | Export-Csv -NoTypeInformation $GroupCSV
	}
}

#UPDATE OBJECT LISTS WITH ON PREMISE INFORMATION: SAMACCOUNTNAME, OBJECTID, IMMUTABLEID
if ($MatchActiveDirectory){
	#Require ActiveDirectory module
	Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
	if (!$?){
		Write-Log "Unable to import ActiveDirectory PS module. Quitting." -Level "Error"
		return
	}

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
			if (($upnSuffixes | Foreach-Object {$upnDomain -match $_}) -and ($userOut = Get-ADUser -Filter 'UserPrincipalName -eq $upn' -Properties Mail,ProxyAddresses)){
				if ($userOut.Mail -eq $user.Mail){
					Write-Log "UPN+MAIL: $($user.UserPrincipalName)"
				}else{
					Write-Log "UPN: $($user.UserPrincipalName)"
				}
			}

			#Match based on Mail attribute
			$mail = $user.Mail
			if ($null -eq $userOut){
				if ($user.Mail -ne "" -and ($userOut = Get-ADUser -Filter 'Mail -eq $mail' -Properties Mail,ProxyAddresses)){
					Write-Log "MAIL: $($user.Mail)"
				}
			}

			#Last restort match based on DisplayName attribute
			$displayName = $user.DisplayName
			if ($null -eq $userOut){
				if (($userOut = Get-ADUser -Filter 'Name -eq $displayName' -Properties Mail,ProxyAddresses)){
					Write-Log "DISPLAYNAME: $($user.DisplayName)"
				}
			}

			#Update user properties and calculate ImmutableId
			if ($userOut){
				$user.SamAccountName = $userOut.SamAccountName
				$user.AdMail = $userOut.Mail
				$user.AdProxyAddresses = ($userOut.ProxyAddresses -match '^SMTP:|^SIP:') -join ';'
				$user.AdObjectGUID = $userOut.ObjectGUID
				$user.AdDN = $userOut.DistinguishedName
				$user.AdOU = ($userOut.DistinguishedName -split "^(.+?),")[2]
				if ($null -ne $user.AdObjectGUID -and $user.ImmutableId -eq ""){
					$user.ImmutableId = [System.Convert]::ToBase64String($($userOut.ObjectGUID).ToByteArray())
				}
			}else{
				Write-Log "NOMATCH: $($user.UserPrincipalName)" -Level Warn
			}
		}

		#Assumes you might be switching machines between doing on premise and Azure AD
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
			if ($null -eq $groupOut -and ($groupOut = Get-ADGroup -Filter 'Name -eq $displayName' -Properties Mail)){
				Write-Log "DISPLAYNAME: $($group.DisplayName)"
			}

			#Update group properties and calculate ImmutableId
			if ($groupOut){
				$group.SamAccountName = $groupOut.SamAccountName
				$group.AdMail = $groupOut.Mail
				$group.AdProxyAddresses = ($groupOut.ProxyAddresses -match '^SMTP:') -join ';'
				$group.AdObjectGUID = $groupOut.ObjectGUID
				$group.AdDN = $groupOut.DistinguishedName
				$group.AdOU = ($groupOut.DistinguishedName -split "^(.+?),")[2]
				if ($null -ne $group.AdObjectGUID -and $group.ImmutableId -eq ""){
					$group.ImmutableId = [System.Convert]::ToBase64String($($groupOut.ObjectGUID).ToByteArray())
				}
			}else{
				Write-Log "NOMATCH: $($group.DisplayName)" -Level Warn
			}
		}

		#Assumes you might be switching machines between doing on premise and Azure AD
		$aadGroups | Export-Csv -NoTypeInformation $GroupCSV

		Write-Log #Create gap in logs
	}
}

#UPDATE IMMUTABLEID IN AZURE AD
if ($UpdateImmutableId){
	#Require AzureAD module, use Connect-AzureAD
	Import-Module AzureAD -ErrorAction SilentlyContinue | Out-Null
	if (!$?){
		Write-Log "Unable to import AzureAD PS module. Quitting." -Level "Error"
		return
	}

	#Connect to Azure AD
	try{
		$AzureConnectivity = Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue
	}catch{
		#Continue
	}
	if (!$AzureConnectivity){
		Write-Log "Connecting to AzureAD..."
		try{
			Connect-AzureAD -ErrorAction SilentlyContinue | Out-Null
		}catch{
			Write-Log "Unable to connect to Azure AD. Quitting." -Level "Error"
			return
		}
	}
	
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
