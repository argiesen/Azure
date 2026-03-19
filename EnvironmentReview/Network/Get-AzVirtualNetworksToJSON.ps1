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
            #SubscriptionId          = $subscription.Id
            #SubscriptionName        = $subscription.Name
            Name                    = $vNet.Name
            ResourceGroup           = $vNet.ResourceGroupName
            Location                = $vNet.Location
            AddressSpace            = $vNet.AddressSpace.AddressPrefixes -join ', '
            Subnets                 = @()
            Peerings                = @()
            DnsServers              = $vNet.DhcpOptions.DnsServers -join ', '
        }

        # Get Subnets
        foreach ($subnet in $vNet.Subnets) {
            $subnetInfo = [PSCustomObject]@{
                Name                = $subnet.Name
                AddressPrefix       = $subnet.AddressPrefix
                ConnectedDevices    = @()
                RouteTable          = $null
                NatGateway          = $null
                Delegations         = @()
            }
            
            # Get Connected Devices
            $networkInterfaces = Get-AzNetworkInterface | Where-Object { $_.IpConfigurations.Subnet.Id -eq $subnet.Id }
            foreach ($nic in $networkInterfaces) {
                $subnetInfo.ConnectedDevices += $nic.Name
            }

            # Get Route Table
            if ($subnet.RouteTable) {
                $subnet.RouteTable.Id -match "^\/subscriptions\/(.+?)\/resourceGroups\/(.+?)\/.*" | Out-Null
                $routeTable = Get-AzRouteTable -ResourceGroupName $matches[2] -Name $subnet.RouteTable.Id.Split('/')[-1]
                $subnetInfo.RouteTable = $routeTable.Name
            }

            # Get NAT Gateway
            if ($subnet.NatGateway) {
                $subnet.NatGateway.Id -match "^\/subscriptions\/(.+?)\/resourceGroups\/(.+?)\/.*" | Out-Null
                $natGateway = Get-AzNatGateway -ResourceGroupName $matches[2] -Name $subnet.NatGateway.Id.Split('/')[-1]
                $subnetInfo.NatGateway = $natGateway.Name
            }

            # Get Delegations
            foreach ($delegation in $subnet.Delegations) {
                $delegationInfo     = [PSCustomObject]@{
                    ServiceName     = $delegation.ServiceName
                    Actions         = $delegation.Actions -join ', '
                }
                $subnetInfo.Delegations += $delegationInfo
            }

            $vNetInfo.Subnets += $subnetInfo
        }

        # Get Peerings
        foreach ($peering in $vNet.VirtualNetworkPeerings) {
            $peeringInfo = [PSCustomObject]@{
                Name                 = $peering.Name
                RemoteVirtualNetwork = $peering.RemoteVirtualNetwork.Id
                PeeringState         = $peering.PeeringState
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
