[cmdletbinding()]
param (
	[string]$UserCSV = "AzureADUsers.csv",
	[string]$GroupCSV = "AzureADGroups.csv",
	[string]$UserPassword,
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

$LogPath = "AzureADCreate.log"
#$LogOutTo = "FileAndScreen"
$Indent = 0

#Import System.Web assembly for password generator
Add-Type -AssemblyName System.Web

if ($IncludeUsers){
	$aadUsers = Import-Csv $UserCSV | Where-Object {$_.ImmutableId -eq ""}

	foreach ($user in $aadUsers){
		#Use defined password or randomly generate and convert to secure string
		if ($UserPassword){
			$userPasswordString = $UserPassword
		}else{
			$userPasswordString = [System.Web.Security.Membership]::GeneratePassword(12,2)
		}
		$userPasswordSecure = ConvertTo-SecureString $userPasswordString -AsPlainText -Force
		
		#Derive SamAccountName from UPN if no custom SamAccountName
		if ($user.SamAccountName -eq ""){
			$samAccountName = ($user.UserPrincipalName -split '@')[0]
		}else{
			$samAccountName = $user.SamAccountName
		}

		#Create user; try/catch for error handling
		try {
			New-ADUser -Name $user.DisplayName -DisplayName $user.DisplayName -SamAccountName $samAccountName -UserPrincipalName $user.UserPrincipalName -EmailAddress $user.Mail -Organization $user.OU -Enabled $true -AccountPassword $userPasswordSecure -ErrorAction SilentlyContinue
		}catch{
			#Continue
		}

		#If creation is successful, set additional user properties
		if ($?){
			Write-Log "Created user: $($user.UserPrincipalName) / $userPasswordString"
			$upn = $user.UserPrincipalName
			$userOut = Get-ADUser -Filter 'UserPrincipalName -eq $upn' -ErrorAction SilentlyContinue

			#Set ProxyAddresses
			Set-ADUser -Identity $userOut.DistinguishedName -Replace @{ProxyAddresses=$user.ProxyAddresses} -ErrorAction SilentlyContinue

			if ($?){
				Write-Log "Set ProxyAddresses" -Indent 1
			}else{
				Write-Log "Failed setting ProxyAddresses : $($Error[0].Exception.Message)" -Indent 1 -Level Error
			}

			#Set email address
			Set-ADUser -Identity $userOut.DistinguishedName -EmailAddress $user.Mail -ErrorAction SilentlyContinue

			if ($?){
				Write-Log "Set EmailAddress" -Indent 1
			}else{
				Write-Log "Failed setting EmailAddress : $($Error[0].Exception.Message)" -Indent 1 -Level Error
			}

			#Set name
			Set-ADUser -Identity $userOut.DistinguishedName -GivenName $user.GivenName -Surname $user.Surname -ErrorAction SilentlyContinue

			if ($?){
				Write-Log "Set GivenName, Surname" -Indent 1
			}else{
				Write-Log "Failed setting GivenName, Surname : $($Error[0].Exception.Message)" -Indent 1 -Level Error
			}

			#Set title, department, company
			if ($user.JobTitle -eq ""){$user.JobTitle = $null}
			if ($user.Department -eq ""){$user.Department = $null}
			if ($user.CompanyName -eq ""){$user.CompanyName = $null}
			Set-ADUser -Identity $userOut.DistinguishedName -Title $user.JobTitle -Department $user.Department -Company $user.CompanyName -ErrorAction SilentlyContinue

			if ($?){
				Write-Log "Set Title, Department, Company" -Indent 1
			}else{
				Write-Log "Failed setting Title, Department, Company : $($Error[0].Exception.Message)" -Indent 1 -Level Error
			}

			#Set address
			if ($user.StreetAddress -eq ""){$user.StreetAddress = $null}
			if ($user.City -eq ""){$user.City = $null}
			if ($user.State -eq ""){$user.State = $null}
			if ($user.Country -eq ""){$user.Country = $null}
			if ($user.PostalCode -eq ""){$user.PostalCode = $null}
			
			if (($user.County).Length -gt 2){
				Set-ADUser -Identity $userOut.DistinguishedName -StreetAddress $user.StreetAddress -City $user.City -State $user.State -Country $user.Country -PostalCode $user.PostalCode -ErrorAction SilentlyContinue
			}else{
				Set-ADUser -Identity $userOut.DistinguishedName -StreetAddress $user.StreetAddress -City $user.City -State $user.State -PostalCode $user.PostalCode -ErrorAction SilentlyContinue
			}
			
			if ($?){
				Write-Log "Set StreetAddress, City, State, Country, PostalCode" -Indent 1
			}else{
				Write-Log "Failed setting StreetAddress, City, State, Country, PostalCode : $($Error[0].Exception.Message)" -Indent 1 -Level Error
			}

			#Set phone numbers
			if ($user.TelephoneNumber -eq ""){$user.TelephoneNumber = $null}
			if ($user.Mobile -eq ""){$user.Mobile = $null}
			Set-ADUser -Identity $userOut.DistinguishedName -OfficePhone $user.TelephoneNumber -MobilePhone $user.Mobile -ErrorAction SilentlyContinue

			if ($?){
				Write-Log "Set OfficePhone, MobilePhone" -Indent 1
			}else{
				Write-Log "Failed setting OfficePhone, MobilePhone : $($Error[0].Exception.Message)" -Indent 1 -Level Error
			}
		}else{
			Write-Log "Failed creating user: $($user.UserPrincipalName) : $($Error[0].Exception.Message)" -Level Error
		}
	}
}

if ($IncludeGroups){
	$aadGroups = Import-Csv $GroupCSV | Where-Object {$_.ImmutableId -eq ""}

	foreach ($group in $aadGroups){
		#Create group; try/catch for error handling
		try {
			New-ADGroup -Name $group.DisplayName -DisplayName $group.DisplayName -SamAccountName $group.DisplayName -Description $group.Description -GroupScope Universal -OtherAttributes @{'Mail'=$group.Mail; 'ProxyAddresses'=$group.ProxyAddresses} -ErrorAction SilentlyContinue
		}catch{
			#Continue
		}

		if ($?){
			Write-Log "Created group: $($group.DisplayName)"
		}else{
			Write-Log "Failed creating group: $($group.DisplayName) : $($Error[0].Exception.Message)" -Level Error
		}

		#Add group members
		if ($group.Members -ne ""){
			foreach ($member in ($group.Members -split ';')){
				Add-ADGroupMember -Identity $group.DisplayName -Members (Get-ADUser -Filter 'UserPrincipalName -eq $member' -ErrorAction SilentlyContinue).DistinguishedName -ErrorAction SilentlyContinue

				if ($?){
					Write-Log "Added member to $($group.DisplayName): $member"
				}else{
					Write-Log "Failed adding member to $($group.DisplayName): $member : $($Error[0].Exception.Message)" -Level Error
				}
			}
		}
	}
}
