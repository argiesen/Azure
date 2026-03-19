## TO DO
# Merge with CSV script
# Add notes column
# Eliminate InterfaceName, VmName, LoadBalancerName, FrontendIpConfig columns
# Put associated resource name into single column, possibly AssociatedWithName or new column
# VM NICs: Look upstream for NSG on NIC or subnet
# Resolve detection for AppGW, VNG, Bastion
# Set AssociatedWithId to "Unassociated" when null
# Set associated resource name to "Unassociated" when NIC not attached to VM


# Prepare a hashtable to hold the subscription details
$subscriptionDetails = @{}

# Get all subscriptions
$subscriptions = Get-AzSubscription

# Iterate through each subscription
foreach ($subscription in $subscriptions) {
    # Set the current subscription context
    Set-AzContext -SubscriptionId $subscription.Id

    # Initialize an array to hold the public IP details
    $publicIPDetails = @()

    # Get all public IP addresses in the current subscription
    $publicIPs = Get-AzPublicIpAddress

    foreach ($publicIP in $publicIPs) {
        $publicIPInfo = [PSCustomObject]@{
            SubscriptionId      = $subscription.Id
            SubscriptionName    = $subscription.Name
            Name                = $publicIP.Name
            ResourceGroup       = $publicIP.ResourceGroupName
            Location            = $publicIP.Location
            Sku                 = $publicIP.Sku.Name
            Tier                = $publicIP.Sku.Tier
            IpAddress           = $publicIP.IpAddress
            DnsName             = $publicIP.DnsSettings.Fqdn
            AssociatedWith      = @()
        }

        # Determine what the public IP is associated with
        if ($publicIP.IpConfiguration) {
            $ipConfig = Get-AzResource -ResourceId $publicIP.IpConfiguration.Id
            $associatedResource = [PSCustomObject]@{
                Id              = $publicIP.IpConfiguration.Id
                Name            = $ipConfig.Name
                Type            = $ipConfig.ResourceType
                ResourceDetails = @{}
            }

            # Get additional details based on resource type
            switch ($ipConfig.ResourceType) {
                "Microsoft.Network/networkInterfaces/ipConfigurations" {
                    $nic = Get-AzNetworkInterface -ResourceGroupName $ipConfig.ResourceGroupName -Name $ipConfig.ParentResource.Split('/')[-1]
                    $associatedResource.ResourceDetails = @{
                        VmName        = $nic.VirtualMachine.Id.Split('/')[-1]
                        PrivateIp     = $nic.IpConfigurations.PrivateIpAddress
                        Network       = $nic.NetworkSecurityGroup.Id
                        InterfaceName = $nic.Name
                    }
                }
                "Microsoft.Network/loadBalancers/frontendIPConfigurations" {
                    $lb = Get-AzLoadBalancer -ResourceGroupName $ipConfig.ResourceGroupName -Name $ipConfig.ParentResource.Split('/')[-1]
                    $associatedResource.ResourceDetails = @{
                        LoadBalancerName    = $lb.Name
                        FrontendIpConfig    = $ipConfig.Name
                        Sku                 = $lb.Sku.Name
                        Tier                = $lb.Sku.Tier
                    }
                }
                "Microsoft.Network/applicationGateways/frontendIPConfigurations" {
                    $ag = Get-AzApplicationGateway -ResourceGroupName $ipConfig.ResourceGroupName -Name $ipConfig.ParentResource.Split('/')[-1]
                    $associatedResource.ResourceDetails = @{
                        ApplicationGatewayName = $ag.Name
                        FrontendIpConfig       = $ipConfig.Name
                    }
                }
                "Microsoft.Network/bastionHosts" {
                    $bastion = Get-AzBastion -ResourceGroupName $ipConfig.ResourceGroupName -Name $ipConfig.ParentResource.Split('/')[-1]
                    $associatedResource.ResourceDetails = @{
                        BastionName = $bastion.Name
                    }
                }
                "Microsoft.Network/virtualNetworkGateways" {
                    $vng = Get-AzVirtualNetworkGateway -ResourceGroupName $ipConfig.ResourceGroupName -Name $ipConfig.ParentResource.Split('/')[-1]
                    $associatedResource.ResourceDetails = @{
                        VirtualNetworkGatewayName   = $vng.Name
                        GatewayType                 = $vng.GatewayType
                        Generation                  = $vng.VpnGatewayGeneration
                        VpnType                     = $vng.VpnType
                        BGP                         = $vng.EnableBgp
                        ActiveActive                = $vng.ActiveActive
                    }
                }
                "Microsoft.Network/natGateways" {
                    $natGateway = Get-AzNatGateway -ResourceGroupName $ipConfig.ResourceGroupName -Name $ipConfig.ParentResource.Split('/')[-1]
                    $associatedResource.ResourceDetails = @{
                        NatGatewayName = $natGateway.Name
                    }
                }
            }

            $publicIPInfo.AssociatedWith += $associatedResource
        }

        # Add public IP info to the array
        $publicIPDetails += $publicIPInfo
    }

    # Add the public IP details to the subscription details hashtable
    $subscriptionDetails[$subscription.Name] = $publicIPDetails
}

# Convert the array to JSON
$jsonOutput = $subscriptionDetails | ConvertTo-Json -Depth 10

# Output JSON to a file
$outputFile = "AllAzurePublicIPDetails.json"
$jsonOutput | Out-File -FilePath $outputFile

Write-Output "JSON output saved to $outputFile"
