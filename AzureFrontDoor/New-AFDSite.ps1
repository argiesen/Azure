<#
Prereqs:
  Install-Module Az -Scope CurrentUser

Notes:
  - This is for Front Door Standard/Premium (Az.Cdn "FrontDoorCdn*" cmdlets).
  - DNS validation / certificate enablement for the custom domain is separate from merely creating the domain resource.
#>

# To Do Items
# 1. Vibe code double check, finish validation of command, syntax, and logic
# 2. Test end to end
# 3. Add support for multiple domains
# 4. Add trigger for automation account runbook to validate domains

<# param (
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]$ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]$ProfileName,
    [Parameter(Mandatory = $true)]
    [string]$EndpointName,
    [Parameter(Mandatory = $true)]
    [string]$SecurityPolicyName,
    [Parameter(Mandatory = $true)]
    [string]$PrimaryDomainName,
    [Parameter(Mandatory = $true)]
    [string[]]$CustomDomainName
) #>

$ErrorActionPreference = "Stop"

# -----------------------------
# Inputs (edit these)
# -----------------------------
$SubscriptionId         = "42676ccd-57a1-4fc2-9584-3b3975de9e56"
$ResourceGroupName      = "ag-afd-wus3"
$ProfileName            = "ag-afd"
$EndpointName           = "ag-afd1"
$SecurityPolicyName     = "ag-afd-secpolicy"
$PrimaryDomainName      = "agiesen.com"                                   # your primary domain name
$CustomDomainName       = "agiesen.com","www.agiesen.com"                      # your vanity hostname (CNAME target is the afd endpoint)

# Origin group + origin to create
$OriginGroupName        = $PrimaryDomainName.Replace(".", "-") + "-origin-group"
$OriginName             = $PrimaryDomainName.Replace(".", "-") + "-origin"
$OriginHostName         = $PrimaryDomainName.Substring(0, $PrimaryDomainName.IndexOf(".")) + "-origin" + $PrimaryDomainName.Substring($PrimaryDomainName.IndexOf(".")) # backend hostname
$OriginHostHeader       = $PrimaryDomainName.Substring(0, $PrimaryDomainName.IndexOf(".")) + "-origin" + $PrimaryDomainName.Substring($PrimaryDomainName.IndexOf(".")) # usually same as origin hostname
$OriginHttpPort         = 80
$OriginHttpsPort        = 443
$OriginPriority         = 1
$OriginWeight           = 1000

# Route to create on existing endpoint
$RouteName              = $PrimaryDomainName.Replace(".", "-") + "-route"
$PatternsToMatch        = @("/*")

# If you don't want the script to *attempt* discovery, set this explicitly:
$WafPolicyId            = ""  # e.g. "/subscriptions/.../resourceGroups/.../providers/Microsoft.Network/frontdoorWebApplicationFirewallPolicies/<wafName>"

# -----------------------------
# Connect / Context
# -----------------------------
Select-AzSubscription -SubscriptionId $SubscriptionId | Out-Null

# -----------------------------
# 1) Add a custom domain to the existing AFD profile
# -----------------------------
# Get endpoint
$endpoint = Get-AzFrontDoorCdnEndpoint `
  -ResourceGroupName $ResourceGroupName `
  -ProfileName       $ProfileName `
  -EndpointName      $EndpointName

$DnsRecords = @()
$customDomains = @()

foreach ($domain in $CustomDomainName) {
    #Write-Host "Processing custom domain: $domain"
    $checkCustomDomain = Get-AzFrontDoorCdnCustomDomain `
      -ResourceGroupName $ResourceGroupName `
      -ProfileName $ProfileName `
      -ErrorAction SilentlyContinue | `
      Where-Object { $_.HostName -eq $domain }

    if ($null -ne $checkCustomDomain) {
      $customDomain = $checkCustomDomain
      Write-Host "Custom domain already exists: $($checkCustomDomain.Name) ($domain)"
    } else {
      $customDomain = New-AzFrontDoorCdnCustomDomain `
        -ResourceGroupName $ResourceGroupName `
        -ProfileName       $ProfileName `
        -CustomDomainName  $domain.Replace(".", "-") `
        -HostName          $domain

      # Validation token (TXT record value)
      #$validationToken = $customDomain.ValidationPropertyValidationToken

      # Endpoint hostname (CNAME target)
      #$endpointHostName = $endpoint.HostName

      # Output
      #Write-Host "DNS records to validate then migrate the domain:"
      $DnsRecords += [PSCustomObject]@{
        TxtRecord           = "_auth." + $customDomain.HostName
        TxtValue            = $customDomain.ValidationPropertyValidationToken
        CnameRecord         = $customDomain.HostName
        CnameValue          = $endpoint.HostName
      }

      Write-Host "Created custom domain: $($customDomain.Name) ($domain)"
      $customDomains += $customDomain
    }
}

# -----------------------------
# 2) Create origin group + origin
# -----------------------------
$checkOriginGroup = Get-AzFrontDoorCdnOriginGroup `
  -ResourceGroupName $ResourceGroupName `
  -ProfileName       $ProfileName `
  -OriginGroupName   $OriginGroupName `
  -ErrorAction SilentlyContinue

if ($null -ne $checkOriginGroup) {
  $originGroup = $checkOriginGroup
  Write-Host "Origin group already exists: $($checkOriginGroup.Name)"
} else {
  $healthProbe = New-AzFrontDoorCdnOriginGroupHealthProbeSettingObject `
    -ProbeIntervalInSecond 60 `
    -ProbePath "/" `
    -ProbeProtocol "Https" `
    -ProbeRequestType "GET"

  $loadBalancing = New-AzFrontDoorCdnOriginGroupLoadBalancingSettingObject `
    -AdditionalLatencyInMillisecond 50 `
    -SampleSize 4 `
    -SuccessfulSamplesRequired 3

  $originGroup = New-AzFrontDoorCdnOriginGroup `
    -ResourceGroupName  $ResourceGroupName `
    -ProfileName        $ProfileName `
    -OriginGroupName    $OriginGroupName `
    -HealthProbeSetting $healthProbe `
    -LoadBalancingSetting $loadBalancing

  Write-Host "Created origin group: $($originGroup.Name)"

  $origin = New-AzFrontDoorCdnOrigin `
    -ResourceGroupName   $ResourceGroupName `
    -ProfileName         $ProfileName `
    -OriginGroupName     $OriginGroupName `
    -OriginName          $OriginName `
    -HostName            $OriginHostName `
    -OriginHostHeader    $OriginHostHeader `
    -HttpPort            $OriginHttpPort `
    -HttpsPort           $OriginHttpsPort `
    -Priority            $OriginPriority `
    -Weight              $OriginWeight

  Write-Host "Created origin: $($origin.Name) ($OriginHostName)"
}

# -----------------------------
# 3) Create a route on an existing endpoint and attach the origin group
#    Also attach the custom domain to the route.
# -----------------------------
$checkRoute = Get-AzFrontDoorCdnRoute `
  -ResourceGroupName $ResourceGroupName `
  -ProfileName       $ProfileName `
  -EndpointName      $EndpointName `
  -ErrorAction SilentlyContinue | `
  Where-Object { $_.Name -eq $RouteName }

if ($null -ne $checkRoute) {
  Write-Host "Route already exists: $($checkRoute.Name)"
} else {
  $customDomainRef = @()
  foreach ($domainId in $customDomains) {
    $customDomainRef += New-AzFrontDoorCdnResourceReferenceObject -Id $domainId.Id
  }  

  $route = New-AzFrontDoorCdnRoute `
    -ResourceGroupName     $ResourceGroupName `
    -ProfileName           $ProfileName `
    -EndpointName          $EndpointName `
    -Name                  $RouteName `
    -OriginGroupId         $originGroup.Id `
    -PatternsToMatch       $PatternsToMatch `
    -SupportedProtocol     @("Http","Https") `
    -ForwardingProtocol    "MatchRequest" `
    -HttpsRedirect         "Enabled" `
    -EnabledState          "Enabled" `
    -CustomDomain          $customDomainRef

  Write-Host "Created route: $($route.Name) on endpoint: $EndpointName"
}

# -----------------------------
# 4) Associate the custom domain to an existing security policy
#    (WAF security policy associations are "domain + patterns".)
# -----------------------------
$secPolicy = Get-AzFrontDoorCdnSecurityPolicy `
  -ResourceGroupName $ResourceGroupName `
  -ProfileName       $ProfileName `
  -Name              $SecurityPolicyName

# Try to discover WAF Policy ID if not provided
if ([string]::IsNullOrWhiteSpace($WafPolicyId)) {
  # Depending on Az.Cdn version, this property shape can vary; we try a couple common paths.
  $WafPolicyId =
    $secPolicy.Parameter.WafPolicyId `
    ?? $secPolicy.Parameters.WafPolicyId `
    ?? $secPolicy.Properties.Parameters.WafPolicyId

  if ([string]::IsNullOrWhiteSpace($WafPolicyId)) {
    throw "Couldn't discover WafPolicyId from security policy '$SecurityPolicyName'. Set `$WafPolicyId explicitly."
  }
}

# Preserve existing associations if present, then add ours
$existingAssociations =
  $secPolicy.Parameter.Association `
  ?? $secPolicy.Parameters.Association `
  ?? $secPolicy.Properties.Parameters.Association

if ($null -eq $existingAssociations) { $existingAssociations = @() }

$updatedAssociations = @()
$updatedAssociations += $existingAssociations

foreach ($domainId in $customDomains) {
  if ($existingAssociations -match $domainId.HostName) { 
    Write-Host "Custom domain is already associated with security policy: $SecurityPolicyName ($($domainId.HostName))"
    continue
  }

  # Build new association for the CUSTOM DOMAIN (note: Domain takes Id references)
  $newAssociation = New-AzFrontDoorCdnSecurityPolicyWebApplicationFirewallAssociationObject `
    -PatternsToMatch @("/*") `
    -Domain @(@{ Id = $domainId.Id })
  $updatedAssociations += $newAssociation
  $addedAssociation = $true

  Write-Host "Associating domanin to security policy: $SecurityPolicyName ($($domainId.HostName))"
}

if ($addedAssociation) {
  $updateWafParams = New-AzFrontDoorCdnSecurityPolicyWebApplicationFirewallParametersObject `
    -Association $updatedAssociations `
    -WafPolicyId $WafPolicyId

  $updatedPolicy = Update-AzFrontDoorCdnSecurityPolicy `
    -ResourceGroupName $ResourceGroupName `
    -ProfileName       $ProfileName `
    -Name              $SecurityPolicyName `
    -Parameter         $updateWafParams

  Write-Host "Updated security policy: $($updatedPolicy.Name)"
}

Write-Host "DNS records to first validate then migrate the domain(s):"
$DnsRecords | Format-Table -AutoSize