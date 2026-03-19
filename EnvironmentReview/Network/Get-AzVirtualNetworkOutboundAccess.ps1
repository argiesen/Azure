# https://omute.net/editor
# https://jsonvisualizer-v2.web.app/visualize

# Prepare a hashtable to hold the subscription details
$subscriptionDetails = @{}

# Get all subscriptions
$subscriptions = Get-AzSubscription

# Iterate through each subscription
foreach ($subscription in $subscriptions) {
    # Set the current subscription context
    Set-AzContext -SubscriptionId $subscription.Id

    # Initialize an array to hold the vNet details
    $vNetDetails = @()

    # Get all virtual networks in the current subscription
    $vNets = Get-AzVirtualNetwork

    foreach ($vNet in $vNets) {
        $vNetInfo = [PSCustomObject]@{
            #SubscriptionId              = $subscription.Id
            SubscriptionName            = $subscription.Name
            Name                        = $vNet.Name
            ResourceGroup               = $vNet.ResourceGroupName
            Location                    = $vNet.Location
            Subnets                     = @()
            Peerings                    = @()
        }

        # Get Subnets
        foreach ($subnet in $vNet.Subnets) {
            $subnetInfo = [PSCustomObject]@{
                Name                    = $subnet.Name
                NatGateway              = $null
                DefaultOutboundAccess   = if($null -eq $subnetConfig.DefaultOutboundAccess){ "Allowed" } else { "Not allowed" }
            }

            # Get NAT Gateway
            if ($subnet.NatGateway) {
                $subnet.NatGateway.Id -match "^\/subscriptions\/(.+?)\/resourceGroups\/(.+?)\/.*" | Out-Null
                $natGateway             = Get-AzNatGateway -ResourceGroupName $matches[2] -Name $subnet.NatGateway.Id.Split('/')[-1]
                $subnetInfo.NatGateway  = $natGateway.Name
            }

            $vNetInfo.Subnets += $subnetInfo
        }

        # Get Peerings
        foreach ($peering in $vNet.VirtualNetworkPeerings) {
            $peeringInfo = [PSCustomObject]@{
                Name                    = $peering.Name
                RemoteVirtualNetwork    = $peering.RemoteVirtualNetwork.Id
                PeeringState            = $peering.PeeringState
            }
            $vNetInfo.Peerings += $peeringInfo
        }

        # Add vNet info to the array
        $vNetDetails += $vNetInfo
    }

    # Add the VNET details to the subscription details hashtable
    $subscriptionDetails[$subscription.Name] = $vNetDetails
}

# Convert the array to JSON
$jsonOutput = $subscriptionDetails | ConvertTo-Json -Depth 10

# Output JSON to a file
$outputFile = "AllAzureVirtualNetworkDetails.json"
$jsonOutput | Out-File -FilePath $outputFile

Write-Output "JSON output saved to $outputFile"
