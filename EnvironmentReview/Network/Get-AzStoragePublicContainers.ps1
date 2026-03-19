# Get all subscriptions
$subscriptions = Get-AzSubscription

# Function to check blob containers for anonymous access in storage accounts with public network access enabled
function Get-AnonAccessBlobContainers {
    param (
        [Parameter(Mandatory=$true)]
        [string]$subscriptionId
    )

    # Set the subscription context
    Set-AzContext -SubscriptionId $subscriptionId | Out-Null

    # Get all storage accounts in the subscription
    $storageAccounts = Get-AzStorageAccount

    foreach ($storageAccount in $storageAccounts) {
        # Check if public network access is enabled and allow blob anonymous access is true
        $accountDetails = Get-AzStorageAccount -ResourceGroupName $storageAccount.ResourceGroupName -Name $storageAccount.StorageAccountName
        if ($accountDetails.PublicNetworkAccess -eq "Enabled" -and $accountDetails.AllowBlobPublicAccess -eq $true) {
            # Get the storage account context
            $context = $storageAccount.Context

            # Get all blob containers in the storage account
            $containers = Get-AzStorageContainer -Context $context

            foreach ($container in $containers) {
                if ($container.PublicAccess -ne "Off") {
                    [PSCustomObject]@{
                        SubscriptionId  = $subscriptionId
                        StorageAccount  = $storageAccount.StorageAccountName
                        ContainerName   = $container.Name
                        PublicAccess    = $container.PublicAccess
                    }
                }
            }
        }
    }
}

# Initialize an array to store results
$results = @()

# Loop through each subscription and get containers with anonymous access
foreach ($subscription in $subscriptions) {
    $anonContainers = Get-AnonAccessBlobContainers -subscriptionId $subscription.Id
    $results += $anonContainers
}

# Display the results
$results | Format-Table -AutoSize

# Optionally, export the results to a CSV file
$results | Export-Csv -Path "AnonAccessBlobContainers.csv" -NoTypeInformation
