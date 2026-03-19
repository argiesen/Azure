## TO DO
# VM NICs: Look upstream for NSG on NIC or subnet

# Initialize an array to store the extracted data for CSV
$publicIPDetails = @()

# Get all subscriptions
$subscriptions = Get-AzSubscription

# Iterate through each subscription
foreach ($subscription in $subscriptions) {
    # Set the current subscription context
    Set-AzContext -SubscriptionId $subscription.Id

    # Get all public IP addresses in the current subscription
    $publicIPs = Get-AzPublicIpAddress

    foreach ($publicIP in $publicIPs) {
        # Debug
        Write-Host $publicIP.Name -ForegroundColor Green

        $publicIPInfo = [PSCustomObject]@{
            SubscriptionId                          = $subscription.Id
            SubscriptionName                        = $subscription.Name
            Name                                    = $publicIP.Name
            ResourceGroup                           = $publicIP.ResourceGroupName
            Location                                = $publicIP.Location
            Sku                                     = $publicIP.Sku.Name
            Tier                                    = $publicIP.Sku.Tier
            IpAddress                               = $publicIP.IpAddress
            DnsName                                 = $publicIP.DnsSettings.Fqdn
            AssociatedWith                          = @()
        }

        # Determine what the public IP is associated with
        switch -regex ($publicIP.IpConfiguration.Id) {
            "virtualNetworkGateways" { $ipConfig = Get-AzResource -ResourceId $publicIP.IpConfiguration.Id.Split('/ipConfigurations/')[-2] }
            "applicationGateways" { $ipConfig = Get-AzResource -ResourceId $publicIP.IpConfiguration.Id.Split('/frontendIPConfigurations/')[-2] }
            "virtualHubs" { $ipConfig = Get-AzResource -ResourceId $publicIP.IpConfiguration.Id.Split('/ipConfigurations/')[-2] }
            "bastionHosts" { $ipConfig = Get-AzResource -ResourceId $publicIP.IpConfiguration.Id.Split('/bastionHostIpConfigurations/')[-2] }
            default {
                $natGatewayMatch = Get-AzNatGateway -ErrorAction SilentlyContinue | Where-Object { $_.PublicIpAddresses.Id -match $publicIP.Id }
                if ($natGatewayMatch){
                    $ipConfig = Get-AzResource -ResourceId $natGatewayMatch.Id
                }else{
                    try {
                        $ipConfig = Get-AzResource -ResourceId $publicIP.IpConfiguration.Id
                    } catch {
                        $ipConfig = $null
                    }
                }
            }
        }

        if ($ipConfig){
            $associatedResource = [PSCustomObject]@{
                Id                                  = if ($publicIP.IpConfiguration.Id) { $publicIP.IpConfiguration.Id } else { $ipConfig.ResourceId }
                Name                                = $ipConfig.Name
                Type                                = $ipConfig.ResourceType
                ResourceDetails                     = @{}
            }

            # Debug
            $ipConfig

            # Get additional details based on resource type
            switch ($ipConfig.ResourceType) {
                "Microsoft.Network/networkInterfaces/ipConfigurations" {
                    $nic = Get-AzNetworkInterface -ResourceGroupName $ipConfig.ResourceGroupName -Name $ipConfig.ParentResource.Split('/')[-1]
                    $associatedResource.ResourceDetails = @{
                        ResourceName                = if ($nic.VirtualMachine.Id) { "$($nic.VirtualMachine.Id.Split('/')[-1]) ($($nic.Name))" } else { "No VM associated ($($nic.Name))" }
                        PrivateIp                   = $nic.IpConfigurations.PrivateIpAddress
                        Network                     = $nic.NetworkSecurityGroup.Id
                        InterfaceName               = $nic.Name
                        Associated                  = if ($nic.VirtualMachine.Id) { $true } else { $false }
                    }
                }
                "Microsoft.Network/loadBalancers/frontendIPConfigurations" {
                    $lb = Get-AzLoadBalancer -ResourceGroupName $ipConfig.ResourceGroupName -Name $ipConfig.ParentResource.Split('/')[-1]
                    $associatedResource.ResourceDetails = @{
                        ResourceName                = $lb.Name
                        FrontendIpConfig            = $ipConfig.Name
                        Sku                         = $lb.Sku.Name
                        Tier                        = $lb.Sku.Tier
                    }
                }
                "Microsoft.Network/applicationGateways/frontendIPConfigurations" {
                    $ag = Get-AzApplicationGateway -ResourceGroupName $ipConfig.ResourceGroupName -Name $ipConfig.ParentResource.Split('/')[-1]
                    $associatedResource.ResourceDetails = @{
                        ResourceName                = $ag.Name
                        FrontendIpConfig            = $ipConfig.Name
                    }
                }
                "Microsoft.Network/bastionHosts" {
                    $bastion = Get-AzBastion -ResourceGroupName $ipConfig.ResourceGroupName -Name $ipConfig.ResourceId.Split('/')[-1]
                    $associatedResource.ResourceDetails = @{
                        ResourceName                = $bastion.Name
                    }
                }
                "Microsoft.Network/virtualNetworkGateways" {
                    $vng = Get-AzVirtualNetworkGateway -ResourceGroupName $ipConfig.ResourceGroupName -Name $ipConfig.Name
                    $associatedResource.ResourceDetails = @{
                        ResourceName                = $vng.Name
                        GatewayType                 = $vng.GatewayType
                        Generation                  = $vng.VpnGatewayGeneration
                        VpnType                     = $vng.VpnType
                        BGP                         = $vng.EnableBgp
                        ActiveActive                = $vng.ActiveActive
                    }
                }
                "Microsoft.Network/natGateways" {
                    $natGateway = Get-AzNatGateway -ResourceGroupName $ipConfig.ResourceGroupName -Name $ipConfig.Name
                    $associatedResource.ResourceDetails = @{
                        ResourceName                = $natGateway.Name
                        Sku                         = $natGateway.Sku
                    }
                }
                "Microsoft.Network/virtualHubs" {
                    $virtualHub = Get-AzVirtualHub -ResourceGroupName $publicIP.ResourceGroupName -ErrorAction SilentlyContinue | Where-Object { $_.PublicIpAddress -eq $publicIP.Id }
                    $routeServer = Get-AzRouteServer -ResourceGroupName $publicIP.ResourceGroupName -ErrorAction SilentlyContinue | Where-Object { $_.PublicIpAddress -eq $publicIP.Id }
                    if ($routeServer){
                        $associatedResource.ResourceDetails = @{
                            ResourceName            = $routeServer.Name
                            Sku                     = $routeServer.Sku
                            PrivateIp               = $routeServer.RouteServerIps -join ", "
                        }
                    } elseif($virtualHub) {
                        $associatedResource.ResourceDetails = @{
                            ResourceName            = $virtualHub.Name
                            Sku                     = $virtualHub.Sku
                            PrivateIp               = $virtualHub.RouteServerIps -join ", "
                        }
                    }
                }
            }

            $publicIPInfo.AssociatedWith += $associatedResource
        }

        # Add public IP info to the array for CSV export
        if ($publicIPInfo.AssociatedWith.Count -gt 0) {
            foreach ($associated in $publicIPInfo.AssociatedWith) {
                $obj = [PSCustomObject]@{
                    SubscriptionId                  = $publicIPInfo.SubscriptionId
                    SubscriptionName                = $publicIPInfo.SubscriptionName
                    Name                            = $publicIPInfo.Name
                    ResourceGroup                   = $publicIPInfo.ResourceGroup
                    Location                        = $publicIPInfo.Location
                    Sku                             = $publicIPInfo.Sku
                    Tier                            = $publicIPInfo.Tier
                    IpAddress                       = $publicIPInfo.IpAddress
                    PrivateIp                       = if ($associated.ResourceDetails.PrivateIp) { $associated.ResourceDetails.PrivateIp } else { $null }
                    DnsName                         = $publicIPInfo.DnsName
                    AssociatedWithName              = if ($associated.ResourceDetails.ResourceName){ "$($associated.ResourceDetails.ResourceName) ($($associated.Name))" } else { $associated.Name }
                    AssociatedWithType              = $associated.Type
                    AssociatedWithId                = $associated.Id
                    Notes                           = if ($publicIPInfo.Sku -eq "Basic") { "Recommend Standard SKU for production workloads" } else { $null }
                }
                $publicIPDetails += $obj
            }
        } else {
            $obj = [PSCustomObject]@{
                SubscriptionId                      = $publicIPInfo.SubscriptionId
                SubscriptionName                    = $publicIPInfo.SubscriptionName
                Name                                = $publicIPInfo.Name
                ResourceGroup                       = $publicIPInfo.ResourceGroup
                Location                            = $publicIPInfo.Location
                Sku                                 = $publicIPInfo.Sku
                Tier                                = $publicIPInfo.Tier
                IpAddress                           = $publicIPInfo.IpAddress
                PrivateIp                           = $null
                DnsName                             = $publicIPInfo.DnsName
                AssociatedWithName                  = $null
                AssociatedWithType                  = $null
                AssociatedWithId                    = "Unassociated"
                Notes                               = "Unassigned IP address"
            }
            $publicIPDetails += $obj
        }
    }
}

# Debug
$publicIPDetails

# Output to a CSV file
$outputFile = "AzurePublicIPs.csv"
$publicIPDetails | Export-Csv -Path $outputFile -NoTypeInformation

Write-Output "CSV output saved to $outputFile"
