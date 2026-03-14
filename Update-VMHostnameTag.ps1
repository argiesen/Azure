<#
  .SYNOPSIS
    Tags all Azure VMs across all subscriptions with their hostname using Azure Automation.

    Requires 'Tag Contributor' and 'Virtual Machine Contributor' roles on VMs to update tags.
    Alternatively to the 'Virtual Machine Contributor' role, a custom role with the following permissions are required to execute the run commands:
        "Microsoft.Compute/virtualMachines/runCommand/action",
        "Microsoft.Compute/virtualMachines/runCommands/read",
        "Microsoft.Compute/virtualMachines/runCommands/write",
        "Microsoft.Compute/locations/runCommands/read",
        "Microsoft.Compute/virtualMachines/read"

  .DESCRIPTION
    This script connects to Azure using the system-assigned managed identity, iterates through all accessible subscriptions, retrieves all VMs, executes a command to get the hostname, and updates the VM's tags with the hostname.

  .PARAMETER TagName
    The name of the tag to use for storing the hostname.

  .NOTES
    Name: Update-VMHostnameTag.ps1
    DateCreated: 2026-03-11
    Author: Andy Giesen (agiesen@compunet.biz)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$TagName
)

# Authenticate using the system-assigned managed identity
Connect-AzAccount -Identity | Out-Null

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
                $tags[$TagName] = $hostname

                # Update tag
                Update-AzTag -ResourceId $vm.Id -Tag $tags -Operation Merge | Out-Null

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
