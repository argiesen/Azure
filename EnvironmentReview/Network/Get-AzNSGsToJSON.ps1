# https://www.jsonvisual.com/

# Prepare an array to hold the NSG details
$nsgDetails = @()

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
        # Get the region
        $region = $nsg.Location

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

        # Create an object with the NSG details
        $nsgDetail = [PSCustomObject]@{
            Name                = $nsg.Name
            Region              = $region
            Subscription        = $subscription.Name
            Subnets             = $subnets
            NetworkInterfaces   = $nics
            Rules               = $rules
        }

        # Add the details to the array
        $nsgDetails += $nsgDetail
    }
}

# Convert the array to JSON
$nsgDetails = $subscriptionDetails | ConvertTo-Json -Depth 10

# Export the JSON to a file
$outputFile = "AllAzureNsgDetails.json"
$nsgDetails | Out-File -FilePath $outputFile

Write-Host "NSG details exported to $outputFile"
