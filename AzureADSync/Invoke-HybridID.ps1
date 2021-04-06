[cmdletbinding()]
param (
	[Alias("Step1")]
	[switch]$ExportAzureAD,
	[Alias("Step2")]
	[switch]$MatchActiveDirectory,
	[Alias("Step3")]
	[switch]$UpdateActiveDirectory,
	[Alias("Step4")]
	[switch]$UpdateAzureAD,
	[string]$UserCSV = "AzureADUsers.csv",
	[string]$GroupCSV = "AzureADGroups.csv",
	[string]$UserUPNFilter,
	[string]$UserPassword,
	[bool]$CreateADObjects = $true,
	[bool]$UpdateADObjects = $false,
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

#$LogPath = "AzureADMatch.log"
$LogPath = "HybridID.log"
#$LogOutTo = "FileAndScreen"
$Indent = 0

#COLLECT CLOUD OBJECTS FROM AZURE AD
if ($ExportAzureAD){
	#https://docs.microsoft.com/en-us/microsoft-365/community/all-about-groups

	#Require AzureAD module, use Connect-AzureAD
	Import-Module AzureAD -ErrorAction SilentlyContinue | Out-Null
	if (!$?){
		Write-Log "Unable to import AzureAD PS module. Quitting." -Level "Error"
		return
	}

	#Require ExchangeOnlineManagement module, use Connect-ExchangeOnline
	Import-Module ExchangeOnlineManagement -ErrorAction SilentlyContinue | Out-Null
	if (!$?){
		Write-Log "Unable to import ExchangeOnlineManagement PS module. Quitting." -Level "Error"
		return
	}

	#Connect to Azure AD
	try{
		$AzureConnectivity = Get-AzureADCurrentSessionInfo -ErrorAction SilentlyContinue
	}catch{
		#Continue
	}
	if (!$AzureConnectivity){
		Write-Log "Connecting to Azure AD..."
		try{
			Connect-AzureAD -ErrorAction SilentlyContinue | Out-Null
		}catch{
			Write-Log "Unable to connect to Azure AD. Quitting." -Level "Error"
			return
		}
	}

	#Connect to Exchange Online
	$ExchangeConnectivity = Get-Command Get-UnifiedGroup -ErrorAction SilentlyContinue
	if (!$ExchangeConnectivity){
		Write-Log "Connecting to Exchange Online..."
		try{
			Connect-ExchangeOnline -ErrorAction SilentlyContinue | Out-Null
		}catch{
			Write-Log "Unable to connect to Exchange Online. Quitting." -Level "Error"
			return
		}
	}

	if ($IncludeUsers){
		#Export Azure AD users to CSV for further manipulation against on premise AD
		$proxyAddresses = @{l='ProxyAddresses';e={($_.ProxyAddresses -match '^SMTP:|^SIP:') -join ';'}}
		$azObjectId = @{l='AzObjectId';e={$_.ObjectId}}
		if ($UserUPNFilter){
			$aadUsers = Get-AzureADUser -All $true | Where-Object {$_.DirSyncEnabled -eq $null -and $_.AccountEnabled -eq $true -and $_.UserPrincipalName -notmatch "#EXT#" -and $_.UserPrincipalName -notmatch $UserUPNFilter} | `
				Select-Object DisplayName,SamAccountName,UserPrincipalName,Mail,AdMail,$proxyAddresses,AdProxyAddresses,Description,GivenName,Surname,JobTitle,Department,CompanyName,StreetAddress,City,State,Country,PostalCode,`
				TelephoneNumber,Mobile,ImmutableId,$azObjectId,AdObjectGuid,AdDN,AdOU,ObjectType,Created,UsageLocation,Notes
		}else{
			$aadUsers = Get-AzureADUser -All $true | Where-Object {$_.DirSyncEnabled -eq $null -and $_.AccountEnabled -eq $true -and $_.UserPrincipalName -notmatch "#EXT#"} | `
				Select-Object DisplayName,SamAccountName,UserPrincipalName,Mail,AdMail,$proxyAddresses,AdProxyAddresses,Description,GivenName,Surname,JobTitle,Department,CompanyName,StreetAddress,City,State,Country,PostalCode,`
				TelephoneNumber,Mobile,ImmutableId,$azObjectId,AdObjectGuid,AdDN,AdOU,ObjectType,Created,UsageLocation,Notes
		}

		foreach ($user in $aadUsers){
			if (Get-Mailbox -Identity $user.azObjectId -RecipientTypeDetails SharedMailbox -ErrorAction SilentlyContinue){
				$user.ObjectType = "SharedMailbox"
			}
		}

		Write-Log "Exporting Azure AD user information to $UserCSV" -OutTo Screen
		$aadUsers | Sort-Object DisplayName | Export-Csv -NoTypeInformation $UserCSV
	}

	if ($IncludeGroups){
		#Export Azure AD groups to CSV for further manipulation against on premise AD
		$proxyAddresses = @{l='ProxyAddresses';e={($_.ProxyAddresses -match '^SMTP:') -join ';'}}
		$members = @{l='Members';e={(Get-AzureADGroup -ObjectId $_.ObjectId | Get-AzureADGroupMember).UserPrincipalName -join ';'}}
		$azObjectId = @{l='AzObjectId';e={$_.ObjectId}}
		#Filter out non-dir synced groups and obvious M365 groups (SPO:) for speed
		$aadGroups = Get-AzureADGroup -All $true | Where-Object {$_.DirSyncEnabled -eq $null -and ((($_.ProxyAddresses -match '^SMTP:|^SPO:') -join ';') -notmatch "SPO:")} | `
			Select-Object DisplayName,SamAccountName,MailEnabled,Mail,AdMail,MailNickName,$proxyAddresses,AdProxyAddresses,$members,Description,SecurityEnabled,ImmutableId,OnPremisesSecurityIdentifier,`
			$azObjectId,AdObjectGuid,AdDN,AdOU,ObjectType,Created,Notes

		#Define group type
		foreach ($group in $aadGroups){
			if (Get-UnifiedGroup -Identity $group.azObjectId -ErrorAction SilentlyContinue){
				$group.ObjectType = "GroupUnified"
			}elseif ($group.SecurityEnabled -eq $true){
				if ($group.MailEnabled -eq $true){
					$group.ObjectType = "GroupMailSecurity"
				}else{
					$group.ObjectType = "GroupSecurity"
					$group.MailNickName = $null
				}
			}elseif ($group.MailEnabled -eq $true){
				$group.ObjectType = "GroupDistribution"
			}
		}

		#Export non-M365 groups
		Write-Log "Exporting Azure AD group information to $GroupCSV" -OutTo Screen
		$aadGroups | Where-Object {$_.ObjectType -ne "GroupUnified"} | Sort-Object DisplayName | Export-Csv -NoTypeInformation $GroupCSV
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
		#$LogPath = "AzureADMatchUsers.log"
		Write-Log
		Write-Log "Matching users"
		Write-Log

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
		#$LogPath = "AzureADMatchGroups.log"
		Write-Log
		Write-Log "Matching groups"
		Write-Log

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

if ($UpdateActiveDirectory){
	#Import System.Web assembly for password generator
	Add-Type -AssemblyName System.Web

	if ($CreateADObjects){
		#$LogPath = "AzureADCreate.log"

		if ($IncludeUsers){
			Write-Log
			Write-Log "Creating users"
			Write-Log

			$aadUsers = Import-Csv $UserCSV

			#Process users that did not match and therefor do not have a discovered DN
			foreach ($user in ($aadUsers | Where-Object {$_.AdDN -eq ""})){
				#Use defined password or randomly generate and convert to secure string
				if ($UserPassword){
					$userPasswordString = $UserPassword
				}else{
					$userPasswordString = [System.Web.Security.Membership]::GeneratePassword(12,2)
				}
				$userPasswordSecure = ConvertTo-SecureString $userPasswordString -AsPlainText -Force

				#Derive SamAccountName from UPN if no custom SamAccountName
				if ($user.SamAccountName -eq ""){
					$user.SamAccountName = ($user.UserPrincipalName -split '@')[0]
				}

				#Create user; try/catch for error handling
				try {
					New-ADUser -Name $user.DisplayName -DisplayName $user.DisplayName -SamAccountName $user.SamAccountName -UserPrincipalName $user.UserPrincipalName -EmailAddress $user.Mail -Organization $user.OU -Enabled $true `
					-AccountPassword $userPasswordSecure -ErrorAction SilentlyContinue
				}catch{
					#Continue
				}

				#If creation is successful, set additional user properties
				if ($?){
					Write-Log "Created user: $($user.UserPrincipalName) / $userPasswordString"
					$user.Created = $true

					$upn = $user.UserPrincipalName
					$userOut = Get-ADUser -Filter 'UserPrincipalName -eq $upn' -ErrorAction SilentlyContinue
					$user.AdObjectGUID = $userOut.ObjectGUID
					$user.AdDN = $userOut.DistinguishedName
					$user.AdOU = ($userOut.DistinguishedName -split "^(.+?),")[2]
					$user.ImmutableId = [System.Convert]::ToBase64String($($userOut.ObjectGUID).ToByteArray())

					#Set ProxyAddresses
					Set-ADUser -Identity $user.AdDN -Replace @{ProxyAddresses=$user.ProxyAddresses} -ErrorAction SilentlyContinue

					if ($?){
						Write-Log "Set ProxyAddresses: $($user.ProxyAddresses)" -Indent 1
					}else{
						Write-Log "Failed setting ProxyAddresses: $($user.ProxyAddresses): $($Error[0].Exception.Message)" -Indent 1 -Level Error
					}

					#Set email address
					Set-ADUser -Identity $user.AdDN -EmailAddress $user.Mail -ErrorAction SilentlyContinue

					if ($?){
						Write-Log "Set EmailAddress: $($user.Mail)" -Indent 1
					}else{
						Write-Log "Failed setting EmailAddress: $($user.Mail): $($Error[0].Exception.Message)" -Indent 1 -Level Error
					}

					#Set name
					if ($user.GivenName -eq ""){$user.GivenName = $null}
					if ($user.Surname -eq ""){$user.Surname = $null}
					Set-ADUser -Identity $user.AdDN -GivenName $user.GivenName -Surname $user.Surname -ErrorAction SilentlyContinue

					if ($?){
						Write-Log "Set GivenName ($($user.GivenName)), Surname ($($user.Surname))" -Indent 1
					}else{
						Write-Log "Failed setting GivenName ($($user.GivenName)), Surname ($($user.Surname)): $($Error[0].Exception.Message)" -Indent 1 -Level Error
					}

					#Set title, department, company
					if ($user.JobTitle -eq ""){$user.JobTitle = $null}
					if ($user.Department -eq ""){$user.Department = $null}
					if ($user.CompanyName -eq ""){$user.CompanyName = $null}
					Set-ADUser -Identity $user.AdDN -Title $user.JobTitle -Department $user.Department -Company $user.CompanyName -ErrorAction SilentlyContinue

					if ($?){
						Write-Log "Set Title, Department, Company" -Indent 1
					}else{
						Write-Log "Failed setting Title, Department, Company: $($Error[0].Exception.Message)" -Indent 1 -Level Error
					}

					#Set address
					if ($user.StreetAddress -eq ""){$user.StreetAddress = $null}
					if ($user.City -eq ""){$user.City = $null}
					if ($user.State -eq ""){$user.State = $null}
					if ($user.Country -eq "" -or ($user.County).Length -gt 2){$user.Country = $null}
					if ($user.PostalCode -eq ""){$user.PostalCode = $null}
					Set-ADUser -Identity $user.AdDN -StreetAddress $user.StreetAddress -City $user.City -State $user.State -Country $user.Country -PostalCode $user.PostalCode -ErrorAction SilentlyContinue

					if ($?){
						Write-Log "Set StreetAddress, City, State, Country, PostalCode" -Indent 1
					}else{
						Write-Log "Failed setting StreetAddress, City, State, Country, PostalCode: $($Error[0].Exception.Message)" -Indent 1 -Level Error
					}

					#Set phone numbers
					if ($user.TelephoneNumber -eq ""){$user.TelephoneNumber = $null}
					if ($user.Mobile -eq ""){$user.Mobile = $null}
					Set-ADUser -Identity $user.AdDN -OfficePhone $user.TelephoneNumber -MobilePhone $user.Mobile -ErrorAction SilentlyContinue

					if ($?){
						Write-Log "Set OfficePhone, MobilePhone" -Indent 1
					}else{
						Write-Log "Failed setting OfficePhone, MobilePhone: $($Error[0].Exception.Message)" -Indent 1 -Level Error
					}
				}else{
					Write-Log "Failed creating user: $($user.UserPrincipalName): $($Error[0].Exception.Message)" -Level Error
				}
			}

			$aadUsers | Export-Csv -NoTypeInformation $UserCSV
		}

		if ($IncludeGroups){
			Write-Log
			Write-Log "Creating groups"
			Write-Log

			$aadGroups = Import-Csv $GroupCSV

			#Process groups that did not match and therefor do not have a discovered DN
			foreach ($group in ($aadGroups | Where-Object {$_.AdDN -eq ""})){
				#Derive SamAccountName from UPN if no custom SamAccountName
				if ($group.SamAccountName -eq ""){
					$group.SamAccountName = $group.DisplayName
				}

				#Create group; try/catch for error handling
				try {
					if ($group.SecurityEnabled -eq "True"){
						New-ADGroup -Name $group.DisplayName -DisplayName $group.DisplayName -SamAccountName $group.SamAccountName -Description $group.Description -GroupCategory Security -GroupScope Universal -ErrorAction SilentlyContinue
					}else{
						New-ADGroup -Name $group.DisplayName -DisplayName $group.DisplayName -SamAccountName $group.SamAccountName -Description $group.Description -GroupCategory Distribution -GroupScope Universal -ErrorAction SilentlyContinue
					}
				}catch{
					#Continue
				}

				if ($?){
					$displayName = $group.DisplayName
					$groupOut = Get-ADGroup -Filter 'Name -eq $displayName' -Properties Mail
					$group.AdObjectGUID = $groupOut.ObjectGUID
					$group.AdDN = $groupOut.DistinguishedName
					$group.AdOU = ($groupOut.DistinguishedName -split "^(.+?),")[2]
					$group.ImmutableId = [System.Convert]::ToBase64String($($groupOut.ObjectGUID).ToByteArray())

					Write-Log "Created group: $($group.AdDN)"
					$group.Created = $true

					#Set email address
					if ($group.Mail -ne ""){
						Set-ADGroup -Identity $group.AdDN -Replace @{'mail'=$group.Mail} -ErrorAction SilentlyContinue

						if ($?){
								Write-Log "Set Mail: $($group.Mail)" -Indent 1
							}else{
								Write-Log "Failed setting Mail: $($group.Mail): $($Error[0].Exception.Message)" -Indent 1 -Level Error
						}
					}

					#Set ProxyAddresses
					if ($group.ProxyAddresses -ne ""){
						foreach ($proxyAddress in ($group.ProxyAddresses -split ';')){
							Set-ADGroup -Identity $group.AdDN -Add @{'proxyAddresses'=$proxyAddress} -ErrorAction SilentlyContinue

							if ($?){
								Write-Log "Added ProxyAddress: $proxyAddress" -Indent 1
							}else{
								Write-Log "Failed adding ProxyAddresses: $($proxyAddress): $($Error[0].Exception.Message)" -Indent 1 -Level Error
							}
						}
					}
				}else{
					Write-Log "Failed creating group: $($group.DisplayName): $($Error[0].Exception.Message)" -Level Error
				}

				#Add group members
				if ($group.Members -ne ""){
					foreach ($member in ($group.Members -split ';')){
						Add-ADGroupMember -Identity $group.DisplayName -Members (Get-ADUser -Filter 'UserPrincipalName -eq $member' -ErrorAction SilentlyContinue).DistinguishedName -ErrorAction SilentlyContinue

						if ($?){
							Write-Log "Added member: $member" -Indent 1
						}else{
							Write-Log "Failed adding member: $($member): $($Error[0].Exception.Message)" -Indent 1 -Level Error
						}
					}
				}
			}

			$aadGroups | Export-Csv -NoTypeInformation $GroupCSV
		}
	}

	#UPDATE AD OBJECTS
	if ($UpdateADObjects){
		#$LogPath = "AzureADUpdate.log"

		if ($IncludeUsers){
			Write-Log
			Write-Log "Updating attributes for users"
			Write-Log

			$aadUsers = Import-Csv $UserCSV

			foreach ($user in ($aadUsers | Where-Object {$_.Created -ne "True"})){
				Write-Log "Updating: $($user.UserPrincipalName)"

				#Set email address
				Set-ADUser -Identity $user.adDN -EmailAddress $user.Mail -ErrorAction SilentlyContinue

				if ($?){
					Write-Log "Set EmailAddress: $($user.Mail)" -Indent 1
				}else{
					Write-Log "Failed setting EmailAddress: $($user.Mail): $($Error[0].Exception.Message)" -Indent 1 -Level Error
				}

				#Set ProxyAddresses
				foreach ($proxyAddress in $user.ProxyAddresses){
					Set-ADUser -Identity $user.AdDN -Add @{ProxyAddresses=$proxyAddress} -ErrorAction SilentlyContinue

					if ($?){
						Write-Log "Added ProxyAddress: $proxyAddress" -Indent 1
					}else{
						Write-Log "Failed setting ProxyAddress: $($proxyAddress): $($Error[0].Exception.Message)" -Indent 1 -Level Error
					}
				}
			}
		}

		if ($IncludeGroups){
			Write-Log
			Write-Log "Updating attributes for groups"
			Write-Log

			$aadGroups = Import-Csv $GroupCSV

			#Iterate through groups to update ProxyAddresses and Mail
			foreach ($group in ($aadGroups | Where-Object {$_.Created -ne "True"})){
				Write-Log "Updating group: $($group.AdDN)"

				#Set email address
				if ($group.Mail -ne ""){
					Set-ADGroup -Identity $group.AdDN -Replace @{'mail'=$group.Mail} -ErrorAction SilentlyContinue

					if ($?){
							Write-Log "Added Mail: $($group.Mail)" -Indent 1
						}else{
							Write-Log "Failed adding Mail: $($group.Mail): $($Error[0].Exception.Message)" -Indent 1 -Level Error
					}
				}

				#Set ProxyAddresses
				if ($group.ProxyAddresses -ne ""){
					foreach ($proxyAddress in ($group.ProxyAddresses -split ';')){
						Set-ADGroup -Identity $group.AdDN -Add @{'proxyAddresses'=$proxyAddress} -ErrorAction SilentlyContinue

						if ($?){
							Write-Log "Added ProxyAddress: $proxyAddress" -Indent 1
						}else{
							Write-Log "Failed adding ProxyAddresses: $($proxyAddress): $($Error[0].Exception.Message)" -Indent 1 -Level Error
						}
					}
				}

				#Add group members
				if ($group.Members -ne ""){
					foreach ($member in ($group.Members -split ';')){
						Add-ADGroupMember -Identity $group.AdDN -Members (Get-ADUser -Filter 'UserPrincipalName -eq $member' -ErrorAction SilentlyContinue).DistinguishedName -ErrorAction SilentlyContinue

						if ($?){
							Write-Log "Added member: $member" -Indent 1
						}else{
							Write-Log "Failed adding member: $($member): $($Error[0].Exception.Message)" -Indent 1 -Level Error
						}
					}
				}
			}
		}
	}
}

#UPDATE IMMUTABLEID IN AZURE AD
if ($UpdateAzureAD){
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
		Write-Log "Connecting to Azure AD..."
		try{
			Connect-AzureAD -ErrorAction SilentlyContinue | Out-Null
		}catch{
			Write-Log "Unable to connect to Azure AD. Quitting." -Level "Error"
			return
		}
	}

	if ($IncludeUsers){
		#$LogPath = "AzureADMatchUsers.log"
		Write-Log
		Write-Log "Updating ImmutableId for users"
		Write-Log

		#Import to update Azure AD with ImmutableId
		$aadUsers = Import-Csv $UserCSV

		#Iterate through users to update ImmutableId
		foreach ($user in ($aadUsers | Where-Object {$_.ImmutableId -ne ""})){
			Set-AzureADUser -ObjectId $user.AzObjectId -ImmutableId $user.ImmutableId

			if ($?){
				Write-Log "Updated ImmutableId for user: $($user.UserPrincipalName) / $($user.AzObjectId) / $($user.ImmutableId)"
			}else{
				Write-Log "Failed updating ImmutableId for user: $($user.UserPrincipalName) : $($Error[0].Exception.Message)" -Level Error
			}
		}
	}
}
