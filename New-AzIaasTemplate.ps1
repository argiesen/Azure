$AzRegion = "eastus2"
$RFC1918 = "10.0.0.0/8","172.16.0.0/20","192.168.0.0/16"
$VnetAddressSpace = "10.254.0.0/16"
$VnetGatewaySubnet = "10.254.0.0/28"
$VnetAsgSubnet = "10.254.0.16/28"
$VnetServer01Subnet = "10.254.10.0/24"
$VnetDmz01Subnet = "10.254.20.0/24"

#Create network RG
New-AzResourceGroup -Name rg-net01-prd-$AzRegion -Location $AzRegion

#Create VPN gateway subnet
$vpnSubnet = New-AzVirtualNetworkSubnetConfig -Name snet-gateway01-prd-$AzRegion -AddressPrefix $VnetGatewaySubnet

#Create ASG subnet
$asgSubnet = New-AzVirtualNetworkSubnetConfig -Name snet-asg01-prd-$AzRegion -AddressPrefix $VnetAsgSubnet

#Create server subnet and NSG
$serverRule1 = New-AzNetworkSecurityRuleConfig -Name rdp-rule -Description "Allow RDP from internal" `
	-Direction Inbound `
	-Priority 100 `
	-Access Allow `
	-Protocol Tcp `
	-SourceAddressPrefix $RFC1918 `
	-SourcePortRange 0 `
	-DestinationAddressPrefix * `
	-DestinationPortRange 3389
$serverRule2 = New-AzNetworkSecurityRuleConfig -Name ssh-rule -Description "Allow SSH from internal" `
	-Direction Inbound `
	-Priority 110 `
	-Access Allow `
	-Protocol Tcp `
	-SourceAddressPrefix $RFC1918 `
	-SourcePortRange 0 `
	-DestinationAddressPrefix * `
	-DestinationPortRange 22
$nsgServer = New-AzNetworkSecurityGroup -Name nsg-server01-prd-$AzRegion -Location $AzRegion -ResourceGroupName rg-net01-prd-$AzRegion -SecurityRules $serverRule1,$serverRule2
$snetServerId = (Get-AzNetworkSecurityGroup -Name nsg-server01-prd-$AzRegion -ResourceGroupName rg-net01-prd-eastus2).Id

$srvSubnet = New-AzVirtualNetworkSubnetConfig -Name snet-server01-prd-$AzRegion -AddressPrefix $VnetServer01Subnet -NetworkSecurityGroupId $snetServerId

#Create DMZ subnet and NSG
$dmzRule1 = New-AzNetworkSecurityRuleConfig -Name rdp-rule -Description "Allow RDP from internal" `
	-Direction Inbound `
	-Priority 100 `
	-Access Allow `
	-Protocol Tcp `
	-SourceAddressPrefix $RFC1918 `
	-SourcePortRange 0 `
	-DestinationAddressPrefix * `
	-DestinationPortRange 3389
$dmzRule2 = New-AzNetworkSecurityRuleConfig -Name ssh-rule -Description "Allow SSH from internal" `
	-Direction Inbound `
	-Priority 110 `
	-Access Allow `
	-Protocol Tcp `
	-SourceAddressPrefix $RFC1918 `
	-SourcePortRange 0 `
	-DestinationAddressPrefix * `
	-DestinationPortRange 22
$dmzRule3 = New-AzNetworkSecurityRuleConfig -Name web-rule -Description "Allow HTTP/HTTPS from Internet" `
	-Direction Inbound `
	-Priority 120 `
	-Access Allow `
	-Protocol Tcp `
	-SourceAddressPrefix Internet `
	-SourcePortRange 0 `
	-DestinationAddressPrefix * `
	-DestinationPortRange 80,443
New-AzNetworkSecurityGroup -Name nsg-dmz01-prd-$AzRegion -Location $AzRegion -ResourceGroupName rg-net01-prd-$AzRegion -SecurityRules $dmzRule1,$dmzRule2,$dmzRule3
$snetDmzId = (Get-AzNetworkSecurityGroup -Name nsg-dmz01-prd-eastus2 -ResourceGroupName rg-net01-prd-eastus2).Id

$dmzSubnet = New-AzVirtualNetworkSubnetConfig -Name snet-dmz01-prd-$AzRegion -AddressPrefix $VnetDmz01Subnet -NetworkSecurityGroupId $snetDmzId

#Create virtual network with subnets
New-AzVirtualNetwork -Name vnet-prd-$AzRegion -Location $AzRegion -ResourceGroupName rg-net01-prd-$AzRegion -AddressPrefix $VnetAddressSpace -Subnet $vpnSubnet,$asgSubnet,$srvSubnet,$dmzSubnet

#Create storage RG
New-AzResourceGroup -Name rg-storage01-prd-$AzRegion -Location $AzRegion
#diag storage account
#key vault

#Create VM RG
New-AzResourceGroup -Name rg-vm01-prd-$AzRegion -Location $AzRegion

