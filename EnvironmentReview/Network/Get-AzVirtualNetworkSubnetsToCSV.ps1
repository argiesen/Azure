# Get all subscriptions
$subscriptions = Get-AzSubscription | Where-Object { $_.State -eq "Enabled" }

# Initialize an array to store subnet information
$subnetsInfo = @()

# Iterate over each subscription
foreach ($subscription in $subscriptions){
    Set-AzContext -Subscription $subscription.Id -ErrorAction SilentlyContinue

    # Get all resource groups in the current subscription
    $resourceGroups = Get-AzResourceGroup

    # Iterate over each resource group
    foreach ($resourceGroup in $resourceGroups){
        # Get all virtual networks in the current resource group
        $virtualNetworks = Get-AzVirtualNetwork -ResourceGroupName $resourceGroup.ResourceGroupName

        # Iterate over each virtual network
        foreach ($virtualNetwork in $virtualNetworks){
            # Iterate over each subnet in the virtual network
            foreach ($subnet in $virtualNetwork.Subnets){
                # Get route table, NAT gateway, NSGs, private endpoint network policies, and default outbound access
                $subnetConfig = Get-AzVirtualNetworkSubnetConfig -ResourceId $subnet.Id

                # Initialize DefaultRoute as "None"
                $defaultRoute = "None"

                # Get route table details if it exists
                if ($subnetConfig.RouteTable.Id) {
                    $subnetConfig.RouteTable.Id -match "^\/subscriptions\/(.+?)\/resourceGroups\/(.+?)\/.*" | Out-Null
                    $routeTable = Get-AzRouteTable -ResourceGroupName $matches[2] -Name $subnetConfig.RouteTable.Id.Split('/')[-1]
                    $routeTableName = $routeTable.Name

                    # Check for 0.0.0.0/0 route in the route table
                    $defaultRouteEntry = $routeTable.Routes | Where-Object { $_.AddressPrefix -eq "0.0.0.0/0" }
                    if ($defaultRouteEntry) {
                        $defaultRoute = $defaultRouteEntry.NextHopIpAddress
                    }
                } else {
                    $routeTableName = "None"
                }

                # Create an object with subnet information
                $subnetInfo = [PSCustomObject]@{
                    Subscription                = $subscription.Name
                    ResourceGroup               = $resourceGroup.ResourceGroupName
                    VirtualNetwork              = $virtualNetwork.Name
                    Subnet                      = $subnetConfig.Name
                    Region                      = $virtualNetwork.Location
                    AddressPrefix               = $subnetConfig.AddressPrefix -join ", "
                    IPAddressCount              = ($subnetConfig.IpConfigurations).Count
                    PrivateEndpointCount        = ($subnetConfig.PrivateEndpoints).Count
                    Delegation                  = if($subnetConfig.Delegations){ ($subnetConfig.Delegations).Name -join ", " } else { "None" }
                    NetworkSecurityGroup        = if($subnetConfig.networkSecurityGroup){ ($subnetConfig.networkSecurityGroup.Id).Split("/networkSecurityGroups/")[-1] } else { "None" }
                    RouteTable                  = $routeTableName
                    DefaultRoute                = if($routeTableName -eq "None"){ "N/A" } else { $defaultRoute }
                    NatGateway                  = if($subnetConfig.NatGateway){ ($subnetConfig.NatGateway.Id).Split("/natGateways/")[-1] } else { "None" }
                    PrivateEndpointPolicies     = $subnetConfig.privateEndpointNetworkPolicies
                    DefaultOutboundAccess       = if($null -eq $subnetConfig.DefaultOutboundAccess){ "Allowed" } else { "Not allowed" }
                    DDoSProtection              = if($virtualNetwork.enableDdosProtection){ "Enabled" } else { "Disabled" }
                }

                # Add the subnet information to the array
                $subnetsInfo += $subnetInfo
            }
        }
    }
}

# Export the array to a CSV file
$subnetOutputFile = "AzureSubnets.csv"
$subnetsInfo | Export-Csv -Path $subnetOutputFile -NoTypeInformation

Write-Output "CSV file has been created: $subnetOutputFile"
