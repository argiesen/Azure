$sentinel_laws_id = "/subscriptions/697ec65f-7ce2-41a0-baae-f0b68fe16ee6/resourcegroups/290-corp-sentinel-prod-central/providers/microsoft.operationalinsights/workspaces/290-corp-sentinel-loganalytics"
$DryRun = $true

if($DryRun) {
  Write-Warning "DRY RUN ENABLED."
} else {
  Write-Warning "DRY RUN NOT ENABLED!"
}

Get-AzSubscription -TenantId 30911934-7663-410b-b282-10e95eda882c | ForEach-Object {
  Set-AzContext $_.id | Out-Null
  Write-Output "Subscription: $($_.Name)"
  
  # Storage Accounts
  $StorageAccountSubResources = @(
    "" # For the storage account itself (without subresource IDs appended)
    "/blobServices/default"
    "/fileServices/default"
    "/queueServices/default"
    "/tableServices/default"
  )
  Get-AzStorageAccount | `
  ForEach-Object {
    ForEach($SubResource in $StorageAccountSubResources) {
      Get-AzDiagnosticSetting -ResourceId ($_.id + $SubResource) | `
      Where-Object WorkspaceId -eq $sentinel_laws_id | `
      Select-Object Name,@{n="ResourceUri";e={$_.Id -replace "(?=/providers/microsoft.insights).*"}} | `
      ForEach-Object {
        if($DryRun) {
          Write-Output "DRY RUN: Removing Diagnostic Setting '$($_.Name)' from '$($_.ResourceUri)'"
        } else {
          Write-Output "Removing Diagnostic Setting '$($_.Name)' from '$($_.ResourceUri)'"
          Remove-AzDiagnosticSetting -Name $_.Name -ResourceId $_.ResourceUri
        }
      }
    }
  }
  
  # Network Security Groups
  Get-AzNetworkSecurityGroup | `
  ForEach-Object {
    Get-AzDiagnosticSetting -resourceId $_.id | `
    Where-Object WorkspaceId -eq $sentinel_laws_id | `
    Select-Object Name,@{n="ResourceUri";e={$_.Id -replace "(?=/providers/microsoft.insights).*"}} | `
    ForEach-Object {
      if($DryRun) {
        Write-Output "DRY RUN: Removing Diagnostic Setting '$($_.Name)' from '$($_.ResourceUri)'"
      } else {
        Write-Output "Removing Diagnostic Setting '$($_.Name)' from '$($_.ResourceUri)'"
        Remove-AzDiagnosticSetting -Name $_.Name -ResourceId $_.ResourceUri
      }
  }
  }

  # Azure Key Vaults
  Get-AzKeyVault | `
  ForEach-Object {
    Get-AzDiagnosticSetting -resourceId $_.ResourceId | `
    Where-Object WorkspaceId -eq $sentinel_laws_id | `
    Select-Object Name,@{n="ResourceUri";e={$_.Id -replace "(?=/providers/microsoft.insights).*"}} | `
    ForEach-Object {
      if($DryRun) {
        Write-Output "DRY RUN: Removing Diagnostic Setting '$($_.Name)' from '$($_.ResourceUri)'"
      } else {
        Write-Output "Removing Diagnostic Setting '$($_.Name)' from '$($_.ResourceUri)'"
        Remove-AzDiagnosticSetting -Name $_.Name -ResourceId $_.ResourceUri
      }
    }
  }
}