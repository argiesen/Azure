# Prepare an array to hold the NSG rules for CSV export
$nsgRules = @()

# Counter for NSG index
$nsgCounter = 1

# Get all subscriptions
$subscriptions = Get-AzSubscription

# Iterate through each subscription
foreach ($subscription in $subscriptions) {
    # Set the current subscription context
    Set-AzContext -SubscriptionId $subscription.Id

    # Retrieve all NSGs in the current subscription
    $nsgs = Get-AzNetworkSecurityGroup

    # Iterate through each NSG to get detailed information
    foreach ($nsg in $nsgs) {
        # Get the attached subnets
        $subnets = $nsg.Subnets | ForEach-Object {
            $_.Id
        }

        # Get the attached NICs
        $nics = $nsg.NetworkInterfaces | ForEach-Object {
            $_.Id
        }

        # Get the rules using Get-AzNetworkSecurityRuleConfig
        $rules = Get-AzNetworkSecurityRuleConfig -NetworkSecurityGroup $nsg | Select-Object Name,Description,Priority,Direction,Access,SourceAddressPrefix,@{l='SourceASG';e={$_.SourceApplicationSecurityGroups}},Protocol,SourcePortRange,DestinationAddressPrefix,@{l='DestinationASG';e={$_.DestinationApplicationSecurityGroups}},DestinationPortRange | Sort-Object -Property Priority

        # Add rules to the array for CSV export
        foreach ($rule in $rules) {
            $ruleDetail = [PSCustomObject]@{
                SubscriptionId              = $subscription.Id
                SubscriptionName            = $subscription.Name
                Index                       = $nsgCounter
                Guid                        = $nsg.ResourceGuid
                Name                        = $nsg.Name
                Region                      = $nsg.Location
                Subnets                     = if ($subnets) { ($subnets.Split("/virtualNetworks/")[-1] -replace "/subnets","") -join ", " } else { $null }
                Nics                        = if ($nics) { $nics.Split("/networkInterfaces/")[-1] -join ", " } else { $null }
                RuleName                    = $rule.Name
                RuleDescription             = $rule.Description
                RulePriority                = $rule.Priority
                RuleDirection               = $rule.Direction
                RuleAccess                  = $rule.Access
                RuleSourceAddress           = $rule.SourceAddressPrefix -join ", "
                RuleSourceASG               = ($rule.SourceASG.Id).Split("/applicationSecurityGroups/")[-1] -join ", "
                RuleProtocol                = $rule.Protocol.ToUpper()
                RuleSourcePortRange         = $rule.SourcePortRange -join ", "
                RuleDestinationAddress      = $rule.DestinationAddressPrefix -join ", "
                RuleDestinationASG          = ($rule.DestinationASG.Id).Split("/applicationSecurityGroups/")[-1] -join ", "
                RuleDestinationPortRange    = $rule.DestinationPortRange -join ", "
                Notes                       = $null
            }
            $nsgRules += $ruleDetail
        }

        if ($rules) { $nsgCounter++ }
    }
}

$nsgRules

# Export the rules to a CSV file
$csvOutputFile = "AzureNsgRules.csv"
$nsgRules | Export-Csv -Path $csvOutputFile -NoTypeInformation

Write-Host "NSG rules exported to $csvOutputFile"
