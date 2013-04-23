## requires -version 2
##
## Triage-TokenSize
##
## version reflected in $ScriptVersion variable below
##
## mreyn@microsoft.com

## This Sample Code is provided for the purpose of illustration only 
## and is not intended to be used in a production environment.  
## THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" 
## WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING 
## BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
## FITNESS FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive, 
## royalty-free right to use and modify the Sample Code and to reproduce 
## and distribute the object code form of the Sample Code, provided 
## that You agree: (i) to not use Our name, logo, or trademarks to 
## market Your software product in which the Sample Code is embedded; 
## (ii) to include a valid copyright notice on Your software product 
## in which the Sample Code is embedded; and (iii) to indemnify, hold 
## harmless, and defend Us and Our suppliers from and against any claims 
## or lawsuits, including attorneys� fees, that arise or result from 
## the use or distribution of the Sample Code.

param(
	[String[]]$Domains,
	[string]$outputFolder = (Split-Path -Parent -Path ((& {$myinvocation}).scriptname)),
	[Int32]$topNPrincipals = 1000,
	[switch]$createAllUsersCSV,
	[string]$xmlfilename = "Triage-TokenSize__RESULTS.xml",
	[switch]$suppressHTMLOutput,
	[string]$scriptfolderoverride = "notset",
	[int32]$AbortThresholdSkippedPrincipals = 100,
	[switch]$RAPIntegrationMode,
	[switch]$SkipClearCacheOnExit,
	[switch]$SaveUserMemberOfTable,
	[int]$cacheRowsAllowed = 100000,
    [string]$TempFolder = $env:temp
)

$ScriptVersion = "1.2000"

trap{
	Write-Host "ERROR: Overall failure"
	Write-Host "See Triage-TokenSize__ERRORLOG.xml"
	Write-Host "be4e805b-ba43-4c9b-a57c-ea15cea5dc58"
	Start-Sleep -Seconds 5
	Write-Host ""

	$TelemetryItemElement = $telemetryUmbrellaElement.appendchild( $xdoc.createelement( 'TelemetryItem' ) )
	$TelemetryItemElement.SetAttribute( "Name", 'ToolCompletedAcceptably' )
	$TelemetryItemElement.SetAttribute( "Value", 'False' )
	##TODO: FUTURE: Set up safe defaults in the XML so rules don't fire if we have failed to here
	$xdoc.Save( (Join-Path $outputFolder $xmlfilename) ); 
	Export-Clixml -InputObject $error -Path (Join-Path $outputfolder Triage-TokenSize__ERRORLOG.xml)
	$errorObject = New-Object System.Management.Automation.ErrorRecord  ( 
		$_.exception, 
		"be4e805b-ba43-4c9b-a57c-ea15cea5dc58", 
		"NotSpecified", 
		"NotSpecified"
	)
	throw $errorObject
}

Set-PSDebug -strict
$Error.Clear()
$MaximumErrorCount = 1024
$ErrorActionPreference = "Continue"

Function Main{

	Write-Host "------------------------------"
	Write-Host "   Triage-TokenSize           "
	Write-Host "      Version $ScriptVersion  "
	Write-Host "------------------------------"
	Write-Host ""
	Write-Host "### Starting"
	
	##
	## create XML doc
	##
	
	$xdoc = New-Object system.Xml.XmlDocument
	
	$outerTokenSizeElement = $xdoc.appendchild( $xdoc.CreateElement("TokenSize") )
	
	$thresholdsUmbrellaElement = $outerTokenSizeElement.appendchild( $xdoc.CreateElement("Thresholds") )
	$telemetryUmbrellaElement = $outerTokenSizeElement.appendchild( $xdoc.CreateElement("Telemetry") )
	$biggesttokenusersElement = $outerTokenSizeElement.appendchild( $xdoc.CreateElement("BiggestTokenUsers") )
	$contributingGroupsElement = $outerTokenSizeElement.appendchild( $xdoc.CreateElement("ContributingGroups") )
	
	
	
	.{
		## get script location in order to reliably call the second script
		IF( $scriptfolderoverride -eq "notset" ){
			$scriptFolder = Split-Path -Parent -Path ((& {$myinvocation}).scriptname)
		}
		ELSE{
			$scriptfolder = $scriptfolderoverride
		}
		$scriptPath = Join-Path $scriptfolder "triage-tokensize__CORE.ps1"
		
		IF(-not (Test-Path -Path $scriptpath)){
			throw (
				New-Object System.Management.Automation.ErrorRecord  ( 
					"Failed to obtain script path", 
					"0ed5e4f5-3447-4303-bd73-d473cabd9203", 
					"NotSpecified", 
					(Get-ScriptStack)
				)
			)
		}
		
		##
		## go do the real work and store the results
		##
        $instanceTimeStampFileFriendly = (Get-Date -Format "yyyyMMdd-HHMMss")
        
		$masterResults = & $scriptpath `
			-accountDomains $Domains `
			-resourceDomains $Domains `
			-createAllUsersCSV:$createAllUsersCSV `
			-csvOutputFolder $outputFolder `
			-TopNPrincipals $topNPrincipals `
			-AbortThresholdSkippedPrincipals $AbortThresholdSkippedPrincipals `
			-RAPIntegrationMode:$RAPIntegrationMode `
			-SkipClearCacheOnExit:$SkipClearCacheOnExit `
			-SaveUserMemberOfTable:$SaveUserMemberOfTable `
			-CacheRowsAllowed $cacheRowsAllowed `
            -CacheRootPath $(
                Join-Path -Path $TempFolder -ChildPath "TTSZTemp__$instanceTimeStampFileFriendly"
            )
	}
	
	Write-Host "----------------------------"
	Write-Host "   Validating Core Results"
	Write-Host "   to generate output files"
	Write-Host "----------------------------"

	##
	## Check if there was a catastrophic failure
	##
	if( $masterresults -eq $null ){
		throw (
			New-Object System.Management.Automation.ErrorRecord  ( 
				"MasterResults was Null", 
				"3741c297-df11-460e-a279-d91f47c88d1d", 
				"NotSpecified", 
				(Get-ScriptStack)
			)
		)
	}
	elseif($masterresults -isnot [System.Management.Automation.PSObject]){
		Write-Debug "$($masterresults.gettype().fullname)"
		throw (
			New-Object System.Management.Automation.ErrorRecord  ( 
				"MasterResults was not a PSObject", 
				"7f1038e9-a861-4a68-90e4-f979aaa01bc3", 
				"NotSpecified", 
				(Get-ScriptStack)
			)
		)
	}
	elseif( $masterResults.Telemetry.ToolCompletedAcceptably -eq $false ){
		throw (
			New-Object System.Management.Automation.ErrorRecord  ( 
				"A terminating error occured inside the core script", 
				"d398bb41-0098-4fe3-9d73-a329094c361f", 
				"NotSpecified", 
				(Get-ScriptStack)
			)
		)
	}

	##
	## Populate XML with finished data
	##
	. Populate-XDOC 
	
	
	## save XML
	$xdoc.Save( (Join-Path $outputFolder $xmlfilename) );
	
	
	##
	## Generate HTML views of the data for ad-hoc usage
	##
	If( $RAPIntegrationMode -or $suppressHTMLOutput){
		##do nothing
	}
	Else{
		$masterresults.telemetry.getenumerator() | 
			Select-Object @{name='name';expression={$_.key}},@{name='value';expression={$_.value}} | 
				Sort-object Name | 
					ConvertTo-Html > (Join-Path $scriptFolder Triage-TokenSize__RESULTSATAGLANCE__telemetry.html)
		$masterresults.thresholds.getenumerator() | 
			Select-Object @{name='thresholdname';expression={$_.key}},@{name='warnCount';expression={$_.value.warnCount}},@{name='failCount';expression={$_.value.failCount}} | 
				SOrt-Object thresholdname | 
					ConvertTo-Html > (Join-Path $scriptFolder Triage-TokenSize__RESULTSATAGLANCE__thresholds.html)
		$masterresults.biggesttokenusers | 
			Sort-Object -property AccTkn_SIDCount -descending | 
				ConvertTo-Html > (Join-Path $scriptFolder Triage-TokenSize__RESULTSATAGLANCE__biggesttokenusers.html)
		$masterresults.contributinggroups | 
			Select-Object distinguishedName,expansionfactor | 
				Sort-Object -property @{expression={$_.expansionfactor -as [int]}} -descending | 
					ConvertTo-Html > (Join-Path $scriptFolder Triage-TokenSize__RESULTSATAGLANCE__contributinggroups.html)
	}
	
	Export-Clixml -InputObject $error -Path (Join-Path $outputfolder Triage-TokenSize__ERRORLOG.xml)
	
	Write-Host "------------------------------"
	Write-Host "   Triage-TokenSize           "
	Write-Host "    Version $ScriptVersion    "
	Write-Host "------------------------------"
	
	Write-Host "### Finished"
	
	IF ($RAPIntegrationMode){
		## Begin: Added by Naresh
		[string]$parentPath = (Get-ItemProperty "HKCU:\Software\Microsoft").TokenSizeProcessID
		
		if($parentPath -ne ""){
			Remove-ItemProperty -Path HKCU:\Software\Microsoft -Name TokenSizeProcessID
		}
		## End: Added by Naresh
	}
}


#########################           ##########
######################### Functions ##########
#########################           ##########


#############################

Function Populate-XDOC{

#############################

	param(
		[switch]$failureMode
	)
	
	trap{
	$errorObject = New-Object System.Management.Automation.ErrorRecord ( 
		$_.exception, 
		"2eaf8af0-e074-42b0-8051-2ce5c6278792", 
		"NotSpecified", 
		(GetScriptStack)
	)
	throw $errorObject
	}

	## create thresholds data
	foreach ($threshold in ( $masterresults.thresholds.getenumerator() | Sort-Object -Property Key ))
	{
		$ThresholdElement = $thresholdsUmbrellaElement.appendchild( $xdoc.createelement( 'Threshold' ) )
		$thresholdElement.SetAttribute( 'Name' , $threshold.key )
		$thresholdElement.SetAttribute( 'WarnThreshold' , $threshold.value.WarnThreshold )
		$thresholdElement.SetAttribute( 'FailThreshold' , $threshold.value.FailThreshold )
		$thresholdElement.SetAttribute( 'WarnCount' , $threshold.value.Warncount )
		$thresholdElement.SetAttribute( 'FailCount' , $threshold.value.Failcount )
	}
	## create telemetry data
	foreach ($telemetryItem in $masterresults.telemetry.getenumerator() | Sort-Object -Property Key )
	{
		$TelemetryItemElement = $telemetryUmbrellaElement.AppendChild( $xdoc.CreateElement("TelemetryItem") )
		$TelemetryItemElement.SetAttribute( "Name", $telemetryItem.Key )
		IF( ($telemetryitem.Key -eq "SkippedDomains") -or ($telemetryitem.Key -eq "TriagedDomains")){
			#[string]$tempMergedString = $telemetryItem.value.keys
			$TelemetryItemElement.SetAttribute( "Value", [string]$telemetryItem.value.keys )
		}
		ELSE{
			$TelemetryItemElement.SetAttribute( "Value", $telemetryItem.value )
		}
	}
	## create biggesttokenusers data
	foreach ($user in $masterresults.BiggestTokenUsers)
	{
		$userElement = $biggesttokenusersElement.appendchild( $xdoc.CreateElement( "BigTokenUser" ) )
		$user.psobject.properties |
			Foreach-Object{
				$userElement.SetAttribute( $_.name , $_.value )		
			}
	
	}
	## create contributing groups data
	foreach ($group in $masterresults.contributinggroups)
	{
		$groupElement = $contributingGroupsElement.appendchild( $xdoc.CreateElement("ContributingGroup") )
		$group |
			Select-Object DistinguishedName,ExpansionFactor |
				ForEach-Object{ $_.psobject.properties} |
					Foreach-Object{ $groupElement.SetAttribute($_.name , $_.value )}
	}
}


##################################

function Get-ScriptStack{

##################################
	param(
		[Int32]$StartingDepth = 2,
		[Int32]$EndingDepth = 10
	)
	trap{
		$error.RemoveAt(0);
		continue
	}
	[String[]]$stringArray = @()
	$stringArray += $Error[0] | out-string
	foreach( $n IN $StartingDepth..$EndingDepth ){ 
		$stringArray += (get-variable -ErrorAction 'SilentlyContinue' -scope $n myinvocation).value.positionmessage -replace "`n" 
	}
	$stringArray
}



. Main


#signature="0FBEE5C80279A4BB"