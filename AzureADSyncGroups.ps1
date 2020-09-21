$proxyAddreses = @{l='ProxyAddresses';e={($_.ProxyAddresses -join ';')}}
Get-AzureADGroup | select DisplayName,Mail,Description,$proxyAddreses,OnPremisesSecurityIdentifier,ObjectId,ObjectType,DirSyncEnabled
