<#
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. 
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING 
BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. We grant You a nonexclusive, 
royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that 
You agree: (i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; 
(ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and 
(iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, 
that arise or result from the use or distribution of the Sample Code.
This posting is provided "AS IS" with no warranties, and confers no rights. 
Use of included script samples are subject to the terms specified at http://www.microsoft.com/info/cpyright.htm.
#>

param([int]$daysPast = 7)

############################
Function DotNetPing
{
        param($computername)
	$Reachable = "FALSE"
	$Reply = $Null
	$ReplyStatus= $Null
	$ping = new-object System.Net.NetworkInformation.Ping
        Trap {continue}
	$Reply = $ping.send($computername)
	$ReplyStatus = $Reply.status
	If($ReplyStatus -eq "Success") {$Reachable ="TRUE"}
	else {$Reachable="FALSE"}
	$Reachable 
}              
############################
### DCDiscovery - All DCs in the Forest
Function EnumerateDCs
{
	$arrServers =@()
	$rootdse=new-object directoryservices.directoryentry("LDAP://rootdse")
	$Configpath=$rootdse.configurationNamingContext
	$adsientry=new-object directoryservices.directoryentry("LDAP://cn=Sites,$Configpath")
	$adsisearcher=new-object directoryservices.directorysearcher($adsientry)
	$adsisearcher.pagesize=1000
	$adsisearcher.searchscope="subtree"
	$strfilter="(ObjectClass=Server)"
	$adsisearcher.filter=$strfilter
	$colAttributeList = "cn","dNSHostName","ServerReference","distinguishedname"

	Foreach ($c in $colAttributeList)
	{
		[void]$adsiSearcher.PropertiesToLoad.Add($c)
	}
	$objServers=$adsisearcher.findall()
               		
	forEach ($objServer in $objServers)
        {
		$serverDN = $objServer.properties.item("distinguishedname")
		$ntdsDN = "CN=NTDS Settings,$serverDN"
		if ([adsi]::Exists("LDAP://$ntdsDN"))
		{
			$serverdNSHostname = $objServer.properties.item("dNSHostname")
			$arrServers += "$serverDNSHostname"
		}
		$serverdNSHostname=""
	}
        $arrServers
}
############################
#### Function Read Netlogon.log file for specifice DC for specified Time Period.
Function readNetlogon
{
	param([string]$DCName, [string]$netLogonPAth, [dateTime]$dateinPast)
	$continue = 1
	$i = 0
	$colOfRecords = @()
	Try {$myFile = (Get-Content $NetLogonPath)[-1..-500]}
	Catch {$continue=0}

	While ($continue -eq 1)
	{
		Try 
		{
			$line = $myFile[$i]
			$date = $line.substring(0,5)
			$date = [datetime]$date
			IF ($date -gt $dateinPast)
			{
				If ($line -like "*NO_CLIENT_SITE*")
				{
					$splitline = $line.split(" ")	
					$client = $splitline[-2]
					$IP = $splitline[-1]
					$record = ""|select-object Client,IP
					$record.client = $client
					$record.IP = $IP
					$colofRecords += $record
				}
				$i= $i+1
				If ($i -eq 500){$continue=0}
			}
			Else {$continue = 0}
		}
		Catch {$continue=0}
	}
	$colofRecords	

}
############################
### Collect the FQDN of all DCs in the Forest
$allDCsinForest = EnumerateDCs
$numberofDCs = $allDCsinForest.length
$today = Get-Date
$minusdays = -$dayspast
$dateinPast = $today.AddDays($minusdays)
$combinedNetLogon = @()
$count = 1

## Walk through list of DCs and collect Netlogon.
ForEach ($DC in $allDCsinForest)
{
	Write-Host "Collecting logs from $DC : $count of $numberofDCs DCs" -foregroundcolor green
	$NetlogonPath = "\\$DC\c$\Windows\Debug\netlogon.log"
	If (Test-path $NetLogonPath) 
	{
		$RoamingList = readNetlogon $DC	$NetLogonPath $dateinPast
		$combinedNetLogon += $RoamingList
	}
	Else {write-host "Can't connect to Netlogon.log for $DC.  $err[0]" -foregroundcolor red}
	$count++
}

$listofRoamingClients = $combinedNetLogon | sort-object -property IP -unique

### Comment out the line below, to not display results on screen
$listofRoamingClients

### Dump list to a file
If ($listofRoamingClients){$listofRoamingClients | export-csv .\listofroamingclients.txt}
Else {Write-Host "No Roaming Clients found in last $daysPast day(s)"}



