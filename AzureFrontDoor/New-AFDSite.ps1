<#
Prereqs:
  Install-Module Az -Scope CurrentUser
  Install-Module Az.Cdn -Scope CurrentUser

Notes:
  - This is for Front Door Standard/Premium (Az.Cdn "FrontDoorCdn*" cmdlets).
  - DNS validation / certificate enablement for the custom domain is separate from merely creating the domain resource.
#>

# To Do Items
# 1. Vibe code double check, finish validation of command, syntax, and logic
# 2. Test end to end
# 3. Add support for multiple domains
# 4. Add trigger for automation account runbook to validate domains

$ErrorActionPreference = "Stop"

# -----------------------------
# Inputs (edit these)
# -----------------------------
$SubscriptionId         = "<sub-guid>"
$ResourceGroupName      = "<afd-rg-name>"
$ProfileName            = "<afd-profile-name>"
$EndpointName           = "<afd-endpoint-name>"
$SecurityPolicyName     = "<security-policy-name>"
$CustomDomainName       = "<custom-domain-name>"                       # your vanity hostname (CNAME target is the afd endpoint)

# Origin group + origin to create
$OriginGroupName        = $CustomDomainName.Replace(".", "-") + "-origin-group"
$OriginName             = $CustomDomainName.Replace(".", "-") + "-origin"
$OriginHostName         = $CustomDomainName.Substring(0, $CustomDomainName.IndexOf(".")) + "-origin" + $CustomDomainName.Substring($CustomDomainName.IndexOf(".")) # backend hostname
$OriginHostHeader       = $CustomDomainName.Substring(0, $CustomDomainName.IndexOf(".")) + "-origin" + $CustomDomainName.Substring($CustomDomainName.IndexOf(".")) # usually same as origin hostname
$OriginHttpPort         = 80
$OriginHttpsPort        = 443
$OriginPriority         = 1
$OriginWeight           = 1000

# Route to create on existing endpoint
$RouteName              = $CustomDomainName.Replace(".", "-") + "-route"
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
$customDomain = New-AzFrontDoorCdnCustomDomain `
  -ResourceGroupName $ResourceGroupName `
  -ProfileName       $ProfileName `
  -CustomDomainName  $CustomDomainName

# Validation token (TXT record value)
$validationToken = $customDomain.ValidationProperties.ValidationToken

# Get endpoint
$endpoint = Get-AzFrontDoorCdnEndpoint `
  -ResourceGroupName $ResourceGroupName `
  -ProfileName       $ProfileName `
  -Name              $EndpointName

# Endpoint hostname (CNAME target)
$endpointHostName = $endpoint.HostName

# Output
[PSCustomObject]@{
  CustomDomain        = $customDomain.HostName
  ValidationToken     = $validationToken
  EndpointHostName    = $endpointHostName
}

Write-Host "Created custom domain: $($customDomain.Name) ($CustomDomainName)"

# -----------------------------
# 2) Create origin group + origin
# -----------------------------
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

# -----------------------------
# 3) Create a route on an existing endpoint and attach the origin group
#    Also attach the custom domain to the route.
# -----------------------------
$customDomainRef = New-AzFrontDoorCdnResourceReferenceObject -Id $customDomain.Id

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
  -LinkToDefaultDomain   "Enabled" `
  -EnabledState          "Enabled" `
  -CustomDomain          @($customDomainRef)

Write-Host "Created route: $($route.Name) on endpoint: $EndpointName"

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

# Build new association for the CUSTOM DOMAIN (note: Domain takes Id references)
$newAssociation = New-AzFrontDoorCdnSecurityPolicyWebApplicationFirewallAssociationObject `
  -PatternsToMatch @("/*") `
  -Domain @(@{ Id = $customDomain.Id })

$updatedAssociations = @()
$updatedAssociations += $existingAssociations
$updatedAssociations += $newAssociation

$updateWafParams = New-AzFrontDoorCdnSecurityPolicyWebApplicationFirewallParametersObject `
  -Association $updatedAssociations `
  -WafPolicyId $WafPolicyId

$updatedPolicy = Update-AzFrontDoorCdnSecurityPolicy `
  -ResourceGroupName $ResourceGroupName `
  -ProfileName       $ProfileName `
  -Name              $SecurityPolicyName `
  -Parameter         $updateWafParams

Write-Host "Updated security policy: $($updatedPolicy.Name) (associated $CustomDomainName)"