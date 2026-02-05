<#
.SYNOPSIS
    Tags all Azure VMs across all subscriptions with their hostname using Azure Automation.

    Requires Virtual Machine Contributor role on the VM.
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
        Write-Output "Found $($vms.Count) VMs in subscription $($sub.Name)"
    } catch {
        Write-Warning "Unable to get VMs for subscription $($sub.Name): $_"
        continue
    }

    foreach ($vm in $vms) {
        $vmName = $vm.Name
        $resourceGroup = $vm.ResourceGroupName

        Write-Output "[$vmName] Processing VM (RG: $resourceGroup)"

        try {
            if ($vm.PowerState -ne "VM running") {
                Write-Warning "[$vmName] VM is not running. Skipping."
                continue
            }

            if ($vm.StorageProfile.Osdisk.OsType -eq "Windows") {
                $result = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroup -Name $vmName `
                    -CommandId 'RunPowerShellScript' -ScriptString 'hostname' -ErrorAction Stop

                $hostname = ($result.Value | Where-Object { $_.Code -match 'stdout' }).Message.Trim()
            } elseif ($vm.StorageProfile.Osdisk.OsType -eq "Linux") {
                $result = Invoke-AzVMRunCommand -ResourceGroupName $resourceGroup -Name $vmName `
                    -CommandId 'RunShellScript' -ScriptString 'hostname' -ErrorAction Stop

                $regex = '\[stdout\](.+)\[stderr\]'
                $options = [System.Text.RegularExpressions.RegexOptions]::Singleline
                $hostname = ([RegEx]::Matches($result.Value.Message,$regex,$options)).Groups[1].Value.Trim()
            }
            
            if (-not [string]::IsNullOrWhiteSpace($hostname)) {
                $tags = $vm.Tags
                if (-not $tags) { $tags = @{} }
                $tags["Hostname"] = $hostname

                # Update tag
                Set-AzResource -ResourceId $vm.Id -Tag $tags -Force | Out-Null

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
