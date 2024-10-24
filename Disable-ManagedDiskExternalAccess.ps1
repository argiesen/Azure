$filterSubscriptions = Read-Host -Prompt "Enter subscription ID (optional): "
$filterResourceGroups = Read-Host -Prompt "Enter resource group name (optional): "

# Get subscriptions
$subscriptions = @()
if ($filterSubscriptions){
    foreach ($filterSubscription in $filterSubscriptions){
        $subscriptions += Get-AzSubscription -SubscriptionId $filterSubscription
    }
}else{
    $subscriptions = Get-AzSubscription
}

# Loop through each subscription
foreach ($subscription in $subscriptions) {
    # Set the current subscription
    Select-AzSubscription -SubscriptionId $subscription.Id
    Write-Host "Processing subscription: $($subscription.Name) ($($subscription.Id))"

    # Get resource groups
    $resourceGroups = @()
    if ($filterResourceGroups){
        foreach ($filterResourceGroup in $filterResourceGroups){
            $resourceGroups += Get-AzResourceGroup -Name $filterResourceGroup
        }
    }else{
        $resourceGroups = Get-AzResourceGroup
    }

    # Loop through each resource group
    foreach ($rg in $resourceGroups) {
        Write-Host "Processing resource group: $($rg.ResourceGroupName)"

        # Get all managed disks in the resource group
        $disks = Get-AzDisk -ResourceGroupName $rg.ResourceGroupName

        # Loop through each managed disk
        foreach ($disk in $disks) {
            Write-Host "Disabling public network access for disk ($($disk.Name)) in resource group ($($rg.ResourceGroupName))"

            # Disable public network access by setting the networkAccessPolicy to 'DenyAll'
            $disk.NetworkAccessPolicy = "DenyAll"

            # Update the disk settings
            Update-AzDisk -ResourceGroupName $rg.ResourceGroupName -DiskName $disk.Name -Disk $disk

            Write-Host "Public network access has been disabled for disk ($($disk.Name))"
        }
    }
}

Write-Host "Completed disabling public network access for all managed disks across all subscriptions."
