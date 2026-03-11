$managementGroupName = "azdojo-intermediate-mg"
$policyFolder = "C:\GitHub\EME\policy\requiredTags"

$policyDefinitions = @()
$policySetDefinitions = @()
$tmp = [System.IO.Path]::GetTempPath()
$jsonFiles = Get-ChildItem $policyFolder -Filter *.json

# Classify the JSON files into policy definitions and policy set definitions based on the "type" property
foreach ($file in $jsonFiles) {
	$json = Get-Content $file | ConvertFrom-Json

	if ($json.type -match "policySetDefinitions") {
		$policySetDefinitions += $file
	} elseif ($json.type -match "policyDefinitions") {
		$policyDefinitions += $file
	}
}

# Deploy policy definitions
foreach ($file in $policyDefinitions) {
	$json = Get-Content $file | ConvertFrom-Json

	# Extract metadata, parameters, and policy rule into separate JSON files for the New-AzPolicyDefinition cmdlet
	jq .properties.metadata $file > "$tmp\azurepolicy-metadata.json"
	jq .properties.parameters $file > "$tmp\azurepolicy-parameters.json"
	jq .properties.policyRule $file > "$tmp\azurepolicy-policyDefinitions.json"

	Start-Sleep -Milliseconds 150

	New-AzPolicyDefinition -Name $json.name `
		-DisplayName $json.properties.displayName `
		-Description $json.properties.description `
		-Mode $json.properties.mode `
		-Metadata "$tmp\azurepolicy-metadata.json" `
		-Parameter "$tmp\azurepolicy-parameters.json" `
		-Policy "$tmp\azurepolicy-policyDefinitions.json" `
		-ManagementGroupName $managementGroupName

	Start-Sleep -Milliseconds 150
}

# Deploy policy set definitions
foreach ($file in $policySetDefinitions) {
	$json = Get-Content $file | ConvertFrom-Json

	# Extract metadata, parameters, and policy definitions into separate JSON files for the New-AzPolicySetDefinition cmdlet
	jq .properties.metadata $file > "$tmp\azurepolicy-metadata.json"
	jq .properties.parameters $file > "$tmp\azurepolicy-parameters.json"
	jq .properties.policyDefinitions $file > "$tmp\azurepolicy-policyDefinitions.json"

	Start-Sleep -Milliseconds 150

	# Get-Content "$tmp\azurepolicy-policyDefinitions.json" -Replace "contoso",$managementGroupName
	(Get-Content -Path "$tmp\azurepolicy-policyDefinitions.json").Replace("contoso", $managementGroupName) | Set-Content -Path "$tmp\azurepolicy-policyDefinitions.json"

	Start-Sleep -Milliseconds 150

	New-AzPolicySetDefinition -Name $json.name `
		-DisplayName $json.properties.displayName `
		-Description $json.properties.description `
		-Metadata "$tmp\azurepolicy-metadata.json" `
		-Parameter "$tmp\azurepolicy-parameters.json" `
		-PolicyDefinition "$tmp\azurepolicy-policyDefinitions.json" `
		-ManagementGroupName $managementGroupName `
		-apiVersion "2025-03-01"

	Start-Sleep -Milliseconds 150
}
