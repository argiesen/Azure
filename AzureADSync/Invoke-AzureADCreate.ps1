[cmdletbinding()]
param (
	[string]$UserCSV = "AzureADUsers.csv",
	[string]$GroupCSV = "AzureADGroups.csv",
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

#Require ActiveDirectory module

#$LogPath = "AzureADCreate.log"
#$LogOutTo = "FileAndScreen"
$Indent = 0

#Import System.Web assembly for password generator
Add-Type -AssemblyName System.Web

if ($CreateADObjects){
	$LogPath = "AzureADCreate.log"

	if ($IncludeUsers){
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
				New-ADUser -Name $user.DisplayName -DisplayName $user.DisplayName -SamAccountName $user.SamAccountName -UserPrincipalName $user.UserPrincipalName -EmailAddress $user.Mail -Organization $user.OU -Enabled $true -AccountPassword $userPasswordSecure -ErrorAction SilentlyContinue
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
		$aadGroups = Import-Csv $GroupCSV

		#Process groups that did not match and therefor do not have a discovered DN
		foreach ($group in ($aadGroups | Where-Object {$_.AdDN -eq ""})){
			#Create group; try/catch for error handling
			try {
				if ($group.SecurityEnabled -eq "True"){
					New-ADGroup -Name $group.DisplayName -DisplayName $group.DisplayName -SamAccountName $group.DisplayName -Description $group.Description -GroupCategory Security -GroupScope Universal -ErrorAction SilentlyContinue
				}else{
					New-ADGroup -Name $group.DisplayName -DisplayName $group.DisplayName -SamAccountName $group.DisplayName -Description $group.Description -GroupCategory Distribution -GroupScope Universal -ErrorAction SilentlyContinue
				}
			}catch{
				#Continue
			}

			if ($?){
				$displayName = $group.DisplayName
				$groupOut = Get-ADGroup -Filter 'Name -eq $displayName' -Properties Mail
				$group.AdDN = $groupOut.DistinguishedName
				$group.AdObjectGUID = $groupOut.ObjectGUID
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
				foreach ($proxyAddress in ($group.ProxyAddresses -split ';')){
					Set-ADGroup -Identity $group.AdDN -Add @{'proxyAddresses'=$proxyAddress} -ErrorAction SilentlyContinue

					if ($?){
						Write-Log "Added ProxyAddress: $proxyAddress" -Indent 1
					}else{
						Write-Log "Failed adding ProxyAddresses: $($proxyAddress): $($Error[0].Exception.Message)" -Indent 1 -Level Error
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
	$LogPath = "AzureADUpdate.log"

	if ($IncludeUsers){
		Write-Log "Updating attributes for users"
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
		Write-Log "Updating attributes for groups"
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
