# Requires Az Module
# Run Connect-AzAccount first

$subscriptions = Get-AzSubscription
$linkedResources = @()

foreach ($sub in $subscriptions) {
    Set-AzContext -SubscriptionId $sub.Id | Out-Null
    Write-Host "Processing subscription: $($sub.Name)" -ForegroundColor Cyan

    $resources = Get-AzResource

    foreach ($res in $resources) {
        $parentInfo = @{
            Name             = $res.Name
            ResourceId       = $res.ResourceId
            ResourceType     = $res.ResourceType
            SubscriptionId   = $sub.Id
            SubscriptionName = $sub.Name
            ResourceGroup    = $res.ResourceGroupName
            Location         = $res.Location
            ParentResource   = ""
            ParentType       = ""
        }

        switch -Wildcard ($res.ResourceType) {
            # NIC -> VM
            "Microsoft.Network/networkInterfaces" {
                $nic = Get-AzNetworkInterface -Name $res.Name -ResourceGroupName $res.ResourceGroupName -ErrorAction SilentlyContinue
                if ($nic.VirtualMachine) {
                    $parentInfo.ParentResource = $nic.VirtualMachine.Id
                    $parentInfo.ParentType = "Microsoft.Compute/virtualMachines"
                }
            }

            # Public IP -> NIC or Gateway or Bastion or NAT Gateway
            "Microsoft.Network/publicIPAddresses" {
                $pip = Get-AzPublicIpAddress -Name $res.Name -ResourceGroupName $res.ResourceGroupName -ErrorAction SilentlyContinue

                # 1. Try linking to NIC (VM)
                if ($pip.IpConfiguration.Id -match "/networkInterfaces/(.+?)/") {
                    $nicName = $matches[1]
                    $nic = Get-AzNetworkInterface -Name $nicName -ResourceGroupName $res.ResourceGroupName -ErrorAction SilentlyContinue
                    if ($nic.VirtualMachine.Id) {
                        $parentInfo.ParentResource = $nic.VirtualMachine.Id
                        $parentInfo.ParentType = "Microsoft.Compute/virtualMachines"
                    } else {
                        $parentInfo.ParentResource = $nic.Id
                        $parentInfo.ParentType = "Microsoft.Network/networkInterfaces"
                    }
                }
                else {
                    # 2. Try Virtual Network Gateways
                    $gateways = Get-AzVirtualNetworkGateway -ResourceGroupName $res.ResourceGroupName -ErrorAction SilentlyContinue
                    foreach ($gw in $gateways) {
                        foreach ($ipconf in $gw.IpConfigurations) {
                            if ($ipconf.PublicIpAddress.Id -eq $pip.Id) {
                                $parentInfo.ParentResource = $gw.Id
                                $parentInfo.ParentType = "Microsoft.Network/virtualNetworkGateways"
                                break
                            }
                        }
                    }

                    # 3. Try Bastion Hosts
                    if (-not $parentInfo.ParentResource) {
                        $bastions = Get-AzBastion -ResourceGroupName $res.ResourceGroupName -ErrorAction SilentlyContinue
                        foreach ($bastion in $bastions) {
                            foreach ($ipconf in $bastion.IpConfigurations) {
                                if ($ipconf.PublicIpAddress.Id -eq $pip.Id) {
                                    $parentInfo.ParentResource = $bastion.Id
                                    $parentInfo.ParentType = "Microsoft.Network/bastionHosts"
                                    break
                                }
                            }
                        }
                    }

                    # 4. Try NAT Gateway
                    if (-not $parentInfo.ParentResource) {
                        $nats = Get-AzNatGateway -ResourceGroupName $res.ResourceGroupName -ErrorAction SilentlyContinue
                        foreach ($nat in $nats) {
                            foreach ($pipRef in $nat.PublicIpAddresses) {
                                if ($pipRef.Id -eq $pip.Id) {
                                    $parentInfo.ParentResource = $nat.Id
                                    $parentInfo.ParentType = "Microsoft.Network/natGateways"
                                    break
                                }
                            }
                        }
                    }
                }
            }

            # Disk -> VM
            "Microsoft.Compute/disks" {
                $disk = Get-AzDisk -Name $res.Name -ResourceGroupName $res.ResourceGroupName -ErrorAction SilentlyContinue
                if ($disk.ManagedBy) {
                    $parentInfo.ParentResource = $disk.ManagedBy
                    $parentInfo.ParentType = "Microsoft.Compute/virtualMachines"
                }
            }

            # Restore Point Collection -> VM
            "Microsoft.Compute/restorePointCollections" {
                $rpc = Get-AzRestorePointCollection -ResourceGroupName $res.ResourceGroupName -Name $res.Name -ErrorAction SilentlyContinue
                
                foreach ($rp in $rpc.RestorePoints) {
                    if ($rp.SourceMetadata -and $rp.SourceMetadata.ResourceId) {
                        $parentInfo.ParentResource = $rp.SourceMetadata.ResourceId
                        $parentInfo.ParentType = "Microsoft.Compute/virtualMachines"
                        break
                    }
                }
            }

            # Web App -> App Service Plan
            "Microsoft.Web/sites" {
                $webApp = Get-AzWebApp -ResourceGroup $res.ResourceGroupName -Name $res.Name -ErrorAction SilentlyContinue
                if ($webApp.ServerFarmId) {
                    $parentInfo.ParentResource = $webApp.ServerFarmId
                    $parentInfo.ParentType = "Microsoft.Web/serverfarms"
                }

                # Function App Storage Account
                if ($webApp.Kind -like "*functionapp*") {
                    $settings = Get-AzWebApp -ResourceGroup $res.ResourceGroupName -Name $res.Name -ErrorAction SilentlyContinue
                    if ($settings.SiteConfig.AppSettings) {
                        foreach ($setting in $settings.SiteConfig.AppSettings) {
                            if ($setting.Value -like "*blob.core.windows.net*") {
                                $parentInfo.ParentType = "Microsoft.Storage/storageAccounts"
                                $parentInfo.ParentResource = $setting.Value
                                break
                            }
                        }
                    }
                }
            }

            # SQL DB -> SQL Server
            "Microsoft.Sql/servers/databases" {
                $parts = $res.ResourceId -split "/"
                $serverName = $parts[$parts.IndexOf("servers") + 1]
                $parentInfo.ParentResource = "/subscriptions/$($sub.Id)/resourceGroups/$($res.ResourceGroupName)/providers/Microsoft.Sql/servers/$serverName"
                $parentInfo.ParentType = "Microsoft.Sql/servers"
            }

            # Private Endpoint
            "Microsoft.Network/privateEndpoints" {
                $pe = Get-AzPrivateEndpoint -Name $res.Name -ResourceGroupName $res.ResourceGroupName -ErrorAction SilentlyContinue
                foreach ($conn in $pe.PrivateLinkServiceConnections) {
                    if ($conn.PrivateLinkServiceId) {
                        $parentInfo.ParentResource = $conn.PrivateLinkServiceId
                        $parentInfo.ParentType = ($conn.PrivateLinkServiceId -split "/providers/")[1] -replace "/.*", ""
                        break
                    }
                }
            }

            # AKS Agent Pool -> AKS Cluster
            "Microsoft.ContainerService/managedClusters/agentPools" {
                $parts = $res.ResourceId -split "/"
                $clusterName = $parts[$parts.IndexOf("managedClusters") + 1]
                $parentInfo.ParentResource = "/subscriptions/$($sub.Id)/resourceGroups/$($res.ResourceGroupName)/providers/Microsoft.ContainerService/managedClusters/$clusterName"
                $parentInfo.ParentType = "Microsoft.ContainerService/managedClusters"
            }

            # App Gateway Pool -> App Gateway
            "Microsoft.Network/applicationGateways/backendAddressPools" {
                $parts = $res.ResourceId -split "/"
                $appGwName = $parts[$parts.IndexOf("applicationGateways") + 1]
                $parentInfo.ParentResource = "/subscriptions/$($sub.Id)/resourceGroups/$($res.ResourceGroupName)/providers/Microsoft.Network/applicationGateways/$appGwName"
                $parentInfo.ParentType = "Microsoft.Network/applicationGateways"
            }

            # VM Extension -> VM
            "Microsoft.Compute/virtualMachines/extensions" {
                $parts = $res.ResourceId -split "/"
                $vmName = $parts[$parts.IndexOf("virtualMachines") + 1]
                $parentInfo.ParentResource = "/subscriptions/$($sub.Id)/resourceGroups/$($res.ResourceGroupName)/providers/Microsoft.Compute/virtualMachines/$vmName"
                $parentInfo.ParentType = "Microsoft.Compute/virtualMachines"
            }

            # VMSS Instance -> VMSS
            "Microsoft.Compute/virtualMachineScaleSets/virtualMachines" {
                $parts = $res.ResourceId -split "/"
                $vmssName = $parts[$parts.IndexOf("virtualMachineScaleSets") + 1]
                $parentInfo.ParentResource = "/subscriptions/$($sub.Id)/resourceGroups/$($res.ResourceGroupName)/providers/Microsoft.Compute/virtualMachineScaleSets/$vmssName"
                $parentInfo.ParentType = "Microsoft.Compute/virtualMachineScaleSets"
            }

            # Private DNS Zone Link -> Private DNS Zone
            "Microsoft.Network/privateDnsZones/virtualNetworkLinks" {
                $parts = $res.ResourceId -split "/"
                $zoneName = $parts[$parts.IndexOf("privateDnsZones") + 1]

                $parentInfo.ParentResource = "/subscriptions/$($sub.Id)/resourceGroups/$($res.ResourceGroupName)/providers/Microsoft.Network/privateDnsZones/$zoneName"
                $parentInfo.ParentType = "Microsoft.Network/privateDnsZones"
            }

            default {
                # Leave blank
            }
        }

        $linkedResources += New-Object PSObject -Property $parentInfo
    }
}

# Output to CSV
$csvPath = "LinkedAzureResources_$(Get-Date -Format "yyyyMMdd-HHmmss").csv"
$linkedResources | Export-Csv -Path $csvPath -NoTypeInformation
Write-Host "Linked resources exported to $csvPath" -ForegroundColor Green
