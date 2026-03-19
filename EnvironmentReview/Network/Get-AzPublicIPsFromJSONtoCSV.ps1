# Load the JSON file
$jsonContent = Get-Content -Path "BBSI-Legacy-AllAzurePublicIPDetails.json" -Raw | ConvertFrom-Json

# Initialize an array to store the extracted data
$dataArray = @()

# Loop through each subscription
foreach ($subscription in $jsonContent.PSObject.Properties) {
    $subscriptionName = $subscription.Name
    $resources = $subscription.Value

    # Check if the resources array is not empty
    if ($resources.Count -gt 0) {
        foreach ($resource in $resources) {
            # If there are associated items, process each one
            if ($resource.AssociatedWith.Count -gt 0) {
                foreach ($associated in $resource.AssociatedWith) {
                    $obj = [PSCustomObject]@{
                        SubscriptionId   = $resource.SubscriptionId
                        SubscriptionName = $resource.SubscriptionName
                        Name             = $resource.Name
                        ResourceGroup    = $resource.ResourceGroup
                        Location         = $resource.Location
                        Sku              = $resource.Sku
                        Tier             = $resource.Tier
                        IpAddress        = $resource.IpAddress
                        DnsName          = $resource.DnsName
                        AssociatedWithId = $associated.Id
                        AssociatedWithName = $associated.Name
                        AssociatedWithType = $associated.Type
                        PrivateIp        = if ($associated.ResourceDetails.PrivateIp) { $associated.ResourceDetails.PrivateIp } else { $null }
                        InterfaceName    = if ($associated.ResourceDetails.InterfaceName) { $associated.ResourceDetails.InterfaceName } else { $null }
                        VmName           = if ($associated.ResourceDetails.VmName) { $associated.ResourceDetails.VmName } else { $null }
                        LoadBalancerName = if ($associated.ResourceDetails.LoadBalancerName) { $associated.ResourceDetails.LoadBalancerName } else { $null }
                        FrontendIpConfig = if ($associated.ResourceDetails.FrontendIpConfig) { $associated.ResourceDetails.FrontendIpConfig } else { $null }
                    }
                    $dataArray += $obj
                }
            } else {
                # If there are no associated items, create an entry with null values for association fields
                $obj = [PSCustomObject]@{
                    SubscriptionId   = $resource.SubscriptionId
                    SubscriptionName = $resource.SubscriptionName
                    Name             = $resource.Name
                    ResourceGroup    = $resource.ResourceGroup
                    Location         = $resource.Location
                    Sku              = $resource.Sku
                    Tier             = $resource.Tier
                    IpAddress        = $resource.IpAddress
                    DnsName          = $resource.DnsName
                    AssociatedWithId = "Unassociated"
                    AssociatedWithName = $null
                    AssociatedWithType = $null
                    PrivateIp        = $null
                    InterfaceName    = $null
                    VmName           = $null
                    LoadBalancerName = $null
                    FrontendIpConfig = $null
                }
                $dataArray += $obj
            }
        }
    }
}

# Export the data to a CSV file
$dataArray | Export-Csv -Path "BBSI-Legacy-AllAzurePublicIPDetails.csv" -NoTypeInformation
