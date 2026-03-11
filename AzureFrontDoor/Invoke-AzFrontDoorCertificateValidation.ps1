<#
  .SYNOPSIS
    Validates custom domains on Azure Front Door by regenerating validation tokens for pending domains and updating DNS TXT records via the UltraDNS API.

    Requires an Azure Automation credential named 'azurefrontdoor_api' with the UltraDNS API username and password.

  .DESCRIPTION
    This script connects to Azure using the system-assigned managed identity, retrieves all Azure Front Door CDN profiles and their custom domains, regenerates validation tokens for pending domains, and updates the corresponding DNS TXT records using the UltraDNS API.

  .PARAMETER AzureSubscriptionId
    The ID of the Azure subscription to use for retrieving Front Door CDN profiles and custom domains.

  .NOTES
    Name: Invoke-AzFrontDoorCertificateValidation.ps1
    DateCreated: 2026-01-26
    Author: Andy Giesen (agiesen@compunet.biz)
#>

[cmdletbinding()]
param(
    [Parameter(Mandatory = $true)]
    [String]$AzureSubscriptionId
)

# https://github.com/ili101/PowerShell/blob/master/Get-Domain.ps1
function Get-Domain {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [String]$Fqdn
    )
    
    # Create TLDs List as save it to "script" for faster next run.
    if (!$TldsList){
        $TldsListRow = Invoke-RestMethod -Uri https://publicsuffix.org/list/public_suffix_list.dat
        $script:TldsList = ($TldsListRow -split "`n" | Where-Object {$_ -notlike '//*' -and $_})
        [array]::Reverse($TldsList)
    }

    $Ok = $false
    foreach ($Tld in $TldsList){
        if ($Fqdn -Like "*.$Tld"){
            $Ok = $true
            break
        }
    }

    if ($Ok){
        ($Fqdn -replace "\.$Tld" -split '\.')[-1] + ".$Tld"
    }else{
        throw 'Not a valid TLD'
    }
}

# Connect to Azure subscription
Connect-AzAccount -Identity -SubscriptionId $AzureSubscriptionId | Out-Null

# Get API credentials
$apiCredential = Get-AutomationPSCredential -Name 'azurefrontdoor_api'

if ($null -eq $apiCredential) {
    Throw "Unable to retrieve the external API credentials."
}else{
    Write-Output "API credentials retreived"
}

# Extract username and password
$DnsUsername = $apiCredential.UserName
$DnsPassword = $apiCredential.GetNetworkCredential().Password

# Initialize an array to hold the domain validation tokens
$domainTokens = @()

# Initialize an array to hold list of validated domains for TXT cleanup
$approvedDomains = @()

# Get all CDN profiles in the subscription
$cdnProfiles = Get-AzFrontDoorCdnProfile

# Iterate through each CDN profile
foreach ($cdnProfile in $cdnProfiles){
    $profileName = $cdnProfile.Name
    $resourceGroupName = $cdnProfile.ResourceGroupName

    Write-Output "Processing $profileName in $resourceGroupName"

    # Get custom domains
    $customDomains = Get-AzFrontDoorCdnCustomDomain -ResourceGroupName $resourceGroupName -ProfileName $profileName | Select-Object *
    $approvedDomains += $customDomains | Select-Object * | Where-Object DomainValidationState -eq "Approved" | Sort-Object HostName
    $pendingDomains = $customDomains | Select-Object * | Where-Object DomainValidationState -match "Pending|Rejected|TimedOut" | Sort-Object HostName

    foreach ($domain in $pendingDomains){
        if ($domain.DomainValidationState -match "PendingRevalidation|TimedOut|Rejected" -and $domain.Hostname -notmatch "placeholder"){
            Write-Output "Regenerating validation token for $($domain.HostName): "

            $Error.Clear()
            Update-AzFrontDoorCdnCustomDomainValidationToken -ResourceGroupName $resourceGroupName -ProfileName $profileName -CustomDomainName $domain.Name -ErrorAction SilentlyContinue

            if ($Error){
                Write-Output "Failed to regenerate validation token: $($error.Exception)"
            }else {
                Write-Output "Success!"
            }
        }
    }

    $pendingDomains = Get-AzFrontDoorCdnCustomDomain -ResourceGroupName $resourceGroupName -ProfileName $profileName | Select-Object * | Where-Object DomainValidationState -match "Pending" | Sort-Object HostName

    if (-not $pendingDomains){
        Write-Output "No pending domains found."
        continue
    }else{
        Write-Output "$($pendingDomains.Count) domains found. Processing."
    }

    # Iterate through each custom domain
    foreach ($domain in $pendingDomains) {
        # Collect the data
        $domainTokens += [PSCustomObject]@{
            record = "_dnsauth.$($domain.HostName)"
            ownerName = Get-Domain $domain.HostName
            rrtype = "TXT (16)"
            ttl = 3600
            rdata = $domain.ValidationPropertyValidationToken
        }
    }
}

if ($domainTokens){
    # UltraDNS API documentation: https://ultra-portalstatic.ultradns.com/static/docs/REST-API_User_Guide.pdf
    # https://docs.ultradns.com/Default.htm

    # Authentication URL
    $url = "https://api.ultradns.com/authorization/token"

    # Hashtable to create x-www-form-urlencoded body
    $body = @{
        grant_type="password";
        username="$DnsUsername";
        password="$DnsPassword"
    }

    # Get authenticaton token
    try {
        $error.Clear()
        $authResponse = Invoke-WebRequest -Uri $url -Method Post -ContentType "application/x-www-form-urlencoded" -Body $body -UseBasicParsing
        $authResponseJson = ($authResponse).Content | ConvertFrom-Json

        if (-not $authResponseJson.accessToken){
            Write-Output "Authentication failed"
            return
        }else{
            $authToken = $authResponseJson.accessToken
        }
    }catch{
        Write-Output "Error making authentication request (URL: $url): $($Error.Exception.Message)"
        return
    }

    # Proceed if authentication is successful
    if ($authToken){
        Write-Output "Domain                                                           Status"
        Write-Output "----------------------------------------------------------------------------------------------"

        # Process provided records
        foreach ($record in $domainTokens){
            $recordLog = ($record.record).PadRight(64)

            $url = "https://api.ultradns.com/zones/$($record.ownerName)/rrsets/TXT/$($record.record)"
            $body = @{
                "ownerName"="$($record.ownerName)"
                "rrtype"="TXT (16)"
                "ttl"=3600
                "rdata"=[array]$record.rdata
            } | ConvertTo-Json

            # Check if TXT record exists and convert response to JSON
            try {
                $getResponse = Invoke-WebRequest -Uri $url -Method Get -ContentType "application/json" -Headers @{Authorization="Bearer $authToken"} -UseBasicParsing
                $getResponseJson = ($getResponse).Content | ConvertFrom-Json
            }catch{
                # Continue
            }

            # If record exists, update. ElseIf record does not exist, create
            try {
                if ($getResponseJson.resultInfo.returnedCount -eq 1){
                    $error.Clear()
                    $updateResponse = Invoke-WebRequest -Uri $url -Method Patch -ContentType "application/json" -Headers @{Authorization="Bearer $authToken"} -Body $body -UseBasicParsing
                    $success = $true
                }elseif ($Error.Exception.Message -match "404 \(Not Found\)"){
                    $error.Clear()
                    $updateResponse = Invoke-WebRequest -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization="Bearer $authToken"} -Body $body -UseBasicParsing
                    $success = $true
                }elseif ($Error){
                    Write-Output "$($recordLog) Error getting record: $($Error.Exception.Message)"
                    $success = $false
                }
            }catch{
                #Write-Output $Error.Exception.Response
                Write-Output "$($recordLog) Error updating/creating record: $($Error.Exception.Message)"
                $success = $false
            }

            # Convert response to JSON and handle known error codes
            $updateResponseJson = ($updateResponse).Content | ConvertFrom-Json
            switch ($updateResponseJson.ErrorCode){
                "56001" { Write-Output "$($recordLog) Record does not exist, use POST request to create it"; continue }
                "2111" { Write-Output "$($recordLog) Record already exists, use PATCH request to update it"; continue }
                "1801" { Write-Output "$($recordLog) Zone does not exist in the system"; continue }
            }

            # Verify success
            if ($success){
                Write-Output "$($recordLog) Record updated successfully"
            }
        }
    }
}