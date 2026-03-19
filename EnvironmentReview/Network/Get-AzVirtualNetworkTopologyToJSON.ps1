# Output
$perSubscription = $true
$perRegion = $true

# Get all subscriptions
$subscriptions = Get-AzSubscription

# Initialize an array to hold all VNET details
$allVnetDetails = @()

# Initialize an array to hold all virtual hub details
$allVirtualHubDetails = @()

# Iterate through each subscription
foreach ($subscription in $subscriptions) {
    Set-AzContext -SubscriptionId $subscription.Id

    # Get all resource groups in the subscription
    $resourceGroups = Get-AzResourceGroup

    # Iterate through each resource group
    foreach ($resourceGroup in $resourceGroups) {
        # Get all VNETs in the resource group
        $vnets = Get-AzVirtualNetwork -ResourceGroupName $resourceGroup.ResourceGroupName

        # Iterate through each VNET
        foreach ($vnet in $vnets) {
            # Get the VNET peering details
            $vnetPeerings = Get-AzVirtualNetworkPeering -ResourceGroupName $resourceGroup.ResourceGroupName -VirtualNetworkName $vnet.Name

            # Get the subnet details
            $subnets = Get-AzVirtualNetworkSubnetConfig -VirtualNetwork $vnet

            # Get the route table details
            $routeTables = Get-AzRouteTable -ResourceGroupName $resourceGroup.ResourceGroupName

            # Get the virtual network gateway details
            $vnetGateways = Get-AzVirtualNetworkGateway -ResourceGroupName $resourceGroup.ResourceGroupName

            # Get the route server details
            $routeServers = Get-AzRouteServer -ResourceGroupName $resourceGroup.ResourceGroupName

            # Get the firewall details
            $firewalls = Get-AzFirewall -ResourceGroupName $resourceGroup.ResourceGroupName

            # Create a hashtable to hold the VNET details
            $vnetDetails = @{
                SubscriptionId                  = $subscription.Id
                SubscriptionName                = $subscription.Name
                ResourceGroupName               = $resourceGroup.ResourceGroupName
                VnetName                        = $vnet.Name
                Region                          = $vnet.Location
                AddressSpace                    = $vnet.AddressSpace.AddressPrefixes -join ", "
                DnsServers                      = if ($vnet.DhcpOptions.DnsServers){ $vnet.DhcpOptions.DnsServers -join ", " } else { "Azure Default (168.63.129.16)" }
                Subnets                         = @()
                Peerings                        = @()
                RouteTables                     = @()
                Firewalls                       = @()
                VirtualNetworkGateways          = @()
                RouteServers                    = @()
            }

            # Add subnet details to the VNET details
            foreach ($subnet in $subnets) {
                $subnetDetails = @{
                    SubnetName                  = $subnet.Name
                    AddressPrefix               = $subnet.AddressPrefix -join ", "
                    NetworkSecurityGroup        = $subnet.NetworkSecurityGroup.Id
                    RouteTable                  = $subnet.RouteTable.Id
                    NatGateway                  = if ($subnet.NatGateway.Id){ (Get-AzResource -ResourceId $subnet.NatGateway.Id -ErrorAction SilentlyContinue).Name } else { $null }
                    Delegations                 = $subnet.Delegations | Select-Object -ExpandProperty Name
                }

                # Get the NAT Gateway associated with the subnet, if any
                # if ($subnet.IpConfigurations) {
                #    foreach ($ipConfig in $subnet.IpConfigurations) {
                #        $natGateway = Get-AzNatGateway -ResourceGroupName $resourceGroup.ResourceGroupName -VirtualNetworkName $vnet.Name | Where-Object { $_.NatGatewayId -eq $ipConfig.NatGateway.Id }
                #        if ($natGateway) {
                #            $subnetDetails.NatGateway = $natGateway.Name
                #        }
                #    }
                #}

                $vnetDetails.Subnets += $subnetDetails
            }

            # Add VNET peering details to the VNET details
            foreach ($peering in $vnetPeerings) {
                $peeringDetails = @{
                    PeeringName                         = $peering.Name
                    RemoteVirtualNetwork                = $peering.RemoteVirtualNetwork.Id
                    AllowVirtualNetworkAccess           = $peering.AllowVirtualNetworkAccess
                    AllowForwardedTraffic               = $peering.AllowForwardedTraffic
                    AllowGatewayTransit                 = $peering.AllowGatewayTransit
                    UseRemoteGateways                   = $peering.UseRemoteGateways
                }
                $vnetDetails.Peerings += $peeringDetails
            }

            # Add route table details to the VNET details
            foreach ($routeTable in $routeTables) {
                $routeTableDetails = @{
                    RouteTableName                      = $routeTable.Name
                    Routes                              = $routeTable.Routes | Select-Object -Property Name, AddressPrefix, NextHopType, NextHopIpAddress
                }
                $vnetDetails.RouteTables += $routeTableDetails
            }

            # Add firewall details to the VNET details
            foreach ($firewall in $firewalls) {
                $firewallDetails = @{
                    FirewallName                        = $firewall.Name
                    Sku                                 = $firewall.Sku.Tier
                    Policy                              = $firewall.FirewallPolicy.Id -Split "/firewallPolicies/",-1
                    PrivateIp                           = $firewall.PrivateIpAddress
                    PublicIp                            = $firewall.PublicIpAddress.Id -Split "/azureFirewallIpConfigurations/",-1
                }
                $vnetDetails.Firewalls += $firewallDetails
            }

            # Add virtual network gateway details to the VNET details
            foreach ($gateway in $vnetGateways) {
                $gatewayDetails = @{
                    GatewayName                         = $gateway.Name
                    GatewayType                         = $gateway.GatewayType
                    VpnType                             = $gateway.VpnType
                    LocalNetworkGateways                = @()
                    ExpressRouteCircuits                = @()
                }

                # Get the connections of the virtual network gateway
                $connections = Get-AzVirtualNetworkGatewayConnection -ResourceGroupName $resourceGroup.ResourceGroupName -Name *

                # Filter the connections to include only VPN or ExpressRoute connections
                foreach ($connection in $connections) {
                    if ($connection.ConnectionType -eq "IPsec") {
                        Write-Host $connection.LocalNetworkGateway2.Id -ForegroundColor Green
                        
                        # Regex match subscription and resource group from peer ResourceId
                        $connection.LocalNetworkGateway2.Id -match "^\/subscriptions\/(.+?)\/resourceGroups\/(.+?)\/.*" | Out-Null
                        $localGateway = Get-AzLocalNetworkGateway -ResourceGroupName $matches[2] -Name $connection.LocalNetworkGateway2.Id.Split("/localNetworkGateways/")[-1]
                        $localGatewayDetails = @{
                            LocalNetworkGatewayName     = $localGateway.Name
                            GatewayIpAddress            = $localGateway.GatewayIpAddress
                            AddressPrefixes             = $localGateway.AddressSpace.AddressPrefixes -join ", "
                        }
                        $gatewayDetails.LocalNetworkGateways += $localGatewayDetails
                    }elseif ($connection.ConnectionType -eq "ExpressRoute") {
                        Write-Host $connection.Peer.Id -ForegroundColor Green

                        # Regex match subscription and resource group from peer ResourceId
                        $connection.Peer.Id -match "^\/subscriptions\/(.+?)\/resourceGroups\/(.+?)\/.*" | Out-Null
                        Set-AzContext -SubscriptionId $matches[1]
                        $expressRouteCircuit = Get-AzExpressRouteCircuit -ResourceGroupName $matches[2] -Name $connection.Peer.Id.Split("/expressRouteCircuits/")[-1]
                        Set-AzContext -SubscriptionId $subscription.Id

                        $expressRouteCircuitDetails = @{
                            ExpressRouteCircuitName     = $expressRouteCircuit.Name
                            Sku                         = $expressRouteCircuit.Sku.Name
                            Peerings                    = $expressRouteCircuit.Peerings -join ", "
                            ServiceProviderName         = $expressRouteCircuit.ServiceProviderProperties.ServiceProviderName
                            PeeringLocation             = $expressRouteCircuit.ServiceProviderProperties.PeeringLocation
                            BandwidthInMbps             = $expressRouteCircuit.ServiceProviderProperties.BandwidthInMbps
                        }
                        $gatewayDetails.ExpressRouteCircuits += $expressRouteCircuitDetails
                    }
                }

                $vnetDetails.VirtualNetworkGateways += $gatewayDetails
            }

            # Add route server details to the VNET details
            foreach ($routeServer in $routeServers) {
                $routeServerDetails = @{
                    RouteServerName                     = $routeServer.Name
                    HubIp                               = $routeServer.HubIpAddresses
                    RouteServerPeers                    = @()
                }

                # Get the route server peer details
                $routeServerPeers = $routeServers.Peerings

                foreach ($peer in $routeServerPeers) {
                    $peerDetails = @{
                        PeerName                        = $peer.Name
                        PeerIp                          = $peer.PeerIp
                        PeerAsn                         = $peer.PeerAsn
                    }
                    $routeServerDetails.RouteServerPeers += $peerDetails
                }

                $vnetDetails.RouteServers += $routeServerDetails
            }

            # Add the VNET details to the array
            $allVnetDetails += $vnetDetails
        }

        # Get all virtual hubs in the resource group
        $virtualHubs = Get-AzVirtualHub -ResourceGroupName $resourceGroup.ResourceGroupName

        # Iterate through each virtual hub
        foreach ($virtualHub in $virtualHubs) {
            # Get the virtual hub connections
            $hubConnections = Get-AzVirtualHubConnection -ResourceGroupName $resourceGroup.ResourceGroupName -ParentResourceName $virtualHub.Name

            # Create a hashtable to hold the virtual hub details
            $virtualHubDetails = @{
                SubscriptionId                      = $subscription.Id
                ResourceGroupName                   = $resourceGroup.ResourceGroupName
                VirtualHubName                      = $virtualHub.Name
                AddressPrefix                       = $virtualHub.AddressPrefix
                VirtualWan                          = $virtualHub.VirtualWan.Id
                HubConnections                      = @()
            }

            # Add hub connection details to the virtual hub details
            foreach ($connection in $hubConnections) {
                $connectionDetails = @{
                    ConnectionName                  = $connection.Name
                    RemoteVirtualNetwork            = $connection.RemoteVirtualNetwork.Id
                    AllowHubToRemoteVnetTransit     = $connection.AllowHubToRemoteVnetTransit
                    AllowRemoteVnetToHubTransit     = $connection.AllowRemoteVnetToHubTransit
                    EnableInternetSecurity          = $connection.EnableInternetSecurity
                }
                $virtualHubDetails.HubConnections += $connectionDetails
            }

            # Add the virtual hub details to the array
            $allVirtualHubDetails += $virtualHubDetails
        }
    }
}

# Convert the arrays to JSON
$allVnetJson = $allVnetDetails | ConvertTo-Json -Depth 10
$allVirtualHubJson = $allVirtualHubDetails | ConvertTo-Json -Depth 10

if ($perSubscription){
    foreach ($sub in $allVnetDetails.SubscriptionId | Sort-Object | Get-Unique){
        $subName = ($subscriptions | Where-Object {$_.SubscriptionId -eq $sub}).Name -replace " |/","_"
        $perSubVnetJson = $allVnetDetails | Where-Object {$_.SubscriptionId -eq $sub} | ConvertTo-Json -Depth 10
        $perSubVnetJson | Out-File -FilePath "AzureVnetTopology-$subName.json"
    }
}

if ($perRegion){
    foreach ($region in $allVnetDetails.Region | Sort-Object | Get-Unique){
        $perRegionVnetJson = $allVnetDetails | Where-Object {$_.Region -eq $region} | ConvertTo-Json -Depth 10
        $perRegionVnetJson | Out-File -FilePath "AzureVnetTopology-$region.json"
    }
}

# Output the JSON to files
$vnetOutputFile = "AzureVnetTopology-All.json"
$virtualHubOutputFile = "AzureVirtualHubTopology-All.json"
$allVnetJson | Out-File -FilePath $vnetOutputFile
$allVirtualHubJson | Out-File -FilePath $virtualHubOutputFile

Write-Host "VNET topology exported to $vnetOutputFile"
Write-Host "Virtual hub topology exported to $virtualHubOutputFile"
