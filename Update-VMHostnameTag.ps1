<#
.SYNOPSIS
    Tags all Azure VMs across all subscriptions with their hostname using Azure Automation.

    Requires Virtual Machine Contributor role on the VM and the ability to run scripts.
    az role assignment create --assignee <principalId> --role "Virtual Machine Contributor" --scope /subscriptions/<sub-id>
#>

# Authenticate using the system-assigned managed identity
Connect-AzAccount -Identity

# Get all subscriptions the identity has access to
$subscriptions = Get-AzSubscription

foreach ($sub in $subscriptions) {
    Write-Output "Switching to subscription: $($sub.Name)"
    Set-AzContext -SubscriptionId $sub.Id | Out-Null

    try {
        $vms = Get-AzVM -Status
    } catch {
        Write-Warning "Unable to get VMs for subscription $($sub.Name): $_"
        continue
    }

    foreach ($vm in $vms) {
        $vmName = $vm.Name
        $resourceGroup = $vm.ResourceGroupName

        Write-Output "Processing VM: $vmName in $resourceGroup"

        try {
            $result = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroup -Name $vmName `
                        -CommandId 'RunPowerShellScript' -Script 'hostname' -ErrorAction Stop

            $hostname = ($result.Value | Where-Object { $_.Name -eq 'stdout' }).Message.Trim()

            if (-not [string]::IsNullOrWhiteSpace($hostname)) {
                $tags = $vm.Tags
                if (-not $tags) { $tags = @{} }
                $tags["Hostname"] = $hostname

                # Update tag
                Set-AzResource -ResourceId $vm.Id -Tag $tags -Force

                Write-Output "[$vmName] Tagged with Hostname: $hostname"
            } else {
                Write-Warning "[$vmName] Hostname was empty"
            }

        } catch {
            Write-Warning "[$vmName] ERROR: $_"
        }
    }
}

Write-Output "Completed tagging all VMs."
