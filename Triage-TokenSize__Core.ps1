## requires -version 2

##
## Triage-TokenSize__Core
##
## version 1.200
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


##TODO: FUTURE: Introduce a correlation feature to identify group SIDs that have a high likelihood of being present in
##		the same users' tokens. THis could help to identify opportunities for group consolidation

##TODO: FUTURE: change nttoken to be measured in bytes instead of SIDs (though sid count should still be reported)

##TODO: FUTURE: add another property on users for the estimated http version of their kerb ticket (in bytes). This will help in lining up with IIS thresholds.

#TODO: future: TGSExpansionCache appears to be goign to disk pre-maturely

#todo: future: update comments and general cleanup

##todo: improve storage speed

##todo: future: add appropriate parallelism

##todo: review cache management

 param(
 	[string[]]$accountDomains = $(throw "must specify at least one account domain"),
	[string[]]$resourceDomains = $(throw "must specify at least one resource domain") ,
	[switch]$skipClearCacheOnStart,
	[switch]$skipClearCacheOnExit,
	$statusVerbosityLevel = 0,
	$statusLogFile = "",
	[switch]$RAPIDInProcMonitorMode,
	$cacheRootPath = "$($env:temp)\TTSZ1",
	$LDAPTimeoutLow = 12,
	$LDAPTimeoutHigh = 120,
	$estimatedSpecialSIDsForTicket = 0,
	$estimatedSpecialSIDsForToken = 4,
	[switch]$saveUserMemberOfTable,
	[switch]$createAllUsersCSV,
	$CSVOutputFolder = $env:temp,
	$cacheRowsAllowed = 100000,
	$topNPrincipals = 1000,
	$AbortThresholdSkippedPrincipals = 100,
	[switch]$RAPIntegrationMode,
	[string]$preferredForestGC = $null
 )

#perfwp#@#@# -t TTSZOverall -w Begin
Set-PSDebug -strict

##load s.ds.p for ldap functions
[reflection.assembly]::Load( "System.DirectoryServices.Protocols, Version=2.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" ) > $null

#define main function. This is executed at the end of the script file
#######################################                ##########
#######################################     MAIN       ##########
#######################################                ##########


########################

Function MainCore {

########################

	trap {
		## total bail out
		Write-Host "Exception reached top level trap in MainCore. Exiting"
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"MainCore__Trap-A", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $errorObject
		$Error.Insert( 0 , $errorrecord )
		
		IF( $RAPIntegrationMode){
			$script:masterResults.Telemetry.ToolCompletedAccepably = $false
			$script:masterResults
			break
		}
		ELSE{
			Throw $ErrorRecord
		}
	}
	

	
	$overallStartTime = Get-Date
	
	Write-Host "### Starting CORE"
	
	Prepare-PerfwayPointTables
	
	##@#@#perfwp $myinvocation.mycommand.name -d
    
	. Invoke-MiscInitializationAndCleanup
	
	Write-Host "### Analyzing each domain for best available GCs"
    
	Triage-DomainList $accountDomains -account
	
	Triage-DomainList $resourceDomains -resource
	
	IF( $masterResults.Telemetry.triagedDomains.count -lt 1 ){
		Write-Host "Script aborted. No domains remained to be analyzed after suitability tests"
		throw "Script aborted. No domains remained to be analyzed after suitability tests"
	}
    
    ##@#@#perfwp $myinvocation.mycommand.name -d
	
	Write-Host "### Domains to be analyzed:"
	Write-Host "###  Account Domains:"
	Write-Host "###    $( $script:masterresults.Telemetry.TriagedDomains.Values | where {$_.useAsAccountDomain -eq $true} | % { $_.DNSDomainName })"
	Write-Host "###  Resource Domains:"
	Write-Host "###    $( $script:masterresults.Telemetry.TriagedDomains.Values | where {$_.useAsResourceDomain -eq $true} | % { $_.DNSDomainName })"
	Write-Host "###  Domains that had to be skipped (if any):"
	Write-Host "###    $($script:masterResults.Telemetry.SkippedDomains.Keys)"
	
	Start-Sleep -Seconds 3
    
	## roll through each resource group type across each resource domain
	foreach ($currentBasePrincipalType IN @("DLG","FSP")){
		#emit a list of domain objects
		$script:masterResults.Telemetry.TriagedDomains.Values |
		 	#from the list of resource domains
			Where-Object { $_.useAsResourceDomain -eq $true } |
		  		#for each resource domain analyze the relevant principals
				Foreach-Object{
					##@#@#perfwp $myinvocation.mycommand.name ;
					$currentBaseScope = $_
					Get-PrincipalsFromDomain |
						Write-DotEveryNTimes -n 5 | 
							Write-CountEveryNTimes -n 400 |
								Get-BasePrincipalObjectforPrincipal | 
									Get-EffectiveMemberOfForBasePrincipal | 
										Invoke-ExtraBasePrincipalProcessingForGroups | 
											Write-BasePrincipalToDiskCacheGroupsOnly
				##@#@#perfwp $myinvocation.mycommand.name -d
				}
	}


	## handle universal groups
	foreach ($currentBasePrincipalType IN @("UG")){
		## emit list of account domain objects
		$script:masterResults.Telemetry.TriagedDomains.Values |
			Where-Object { $_.useAsAccountDomain -eq $true } |
				Select -First 1 |
					Foreach-Object{
						##@#@#perfwp $myinvocation.mycommand.name ;
						$currentBaseScope = $_ 
						Get-PrincipalsFromDomain |
							Write-DotEveryNTimes -n 5 |
								Write-COuntEveryNTimes -n 400 |
									Get-BasePrincipalObjectforPrincipal |
										Get-EffectiveMemberOfForBasePrincipal |
											Invoke-ExtraBasePrincipalProcessingForGroups |
												Write-BasePrincipalToDiskCacheGroupsOnly
            ##@#@#perfwp $myinvocation.mycommand.name -d
					}
	}
		
		
	## roll through each account group type (now just global groups) across each account domain
	foreach ($currentBasePrincipalType IN @("GG")){
		## emit list of account domain objects
		$script:masterResults.Telemetry.TriagedDomains.Values |
			Where-Object { $_.useAsAccountDomain -eq $true } |
		  	## for each domain do the typical round of processing
		  		Foreach-Object{
            		##@#@#perfwp $myinvocation.mycommand.name ;
		 			$currentBaseScope = $_ 
					Get-PrincipalsFromDomain |
						Write-DotEveryNTimes -n 5 |
							Write-COuntEveryNTimes -n 400 |
								Get-BasePrincipalObjectforPrincipal |
									Get-EffectiveMemberOfForBasePrincipal | 
										Invoke-ExtraBasePrincipalProcessingForGroups | 
											Write-BasePrincipalToDiskCacheGroupsOnly
            ##@#@#perfwp $myinvocation.mycommand.name -d
		}
	}
		
	## repeat similar process for users
	$currentBasePrincipalType = "USER"
	## roll through account domains
	$script:masterResults.Telemetry.TriagedDomains.Values |
		Where-Object { $_.useAsAccountDomain -eq $true } | 
			Foreach-Object{
				##@#@#perfwp $myinvocation.mycommand.name ;
				$currentBaseScope = $_
				Get-PrincipalsFromDomain |
					Write-DotEveryNTimes -n 5 |
						Write-CountEveryNTimes -n 400 |
							Get-BasePrincipalObjectforPrincipal |
								Get-EffectiveMemberOfForBasePrincipal |
									Invoke-ExtraBasePrincipalProcessingForUsers |
										Write-BasePrincipalToDiskCacheUsersOnly
        ##@#@#perfwp $myinvocation.mycommand.name
	}
		
	## At this point all of the group and user data exists in the Trie structures in
	## the on disk cache (or in $groupsRAMCache). The following functions go through that data to find objects
	## of interest
	
	Write-Host "### Finished online analysis of users and groups"
	Write-Host "### Beginning post-processing phase"
	
	Start-Sleep -Seconds 3
    
    ##@#@#perfwp $myinvocation.mycommand.name
	
	Invoke-StatisticsPostProcessingForGroups

	Invoke-StatisticsPostProcessingForUsers
    
    ##@#@#perfwp $myinvocation.mycommand.name -d
	
	Write-Host "## Core script approaching completion"
	Write-Host "## Emitting master results to wrapper for final processing"
	
	#emit the masterResults object to the calling wrapper script
	#the calling wrapper script will render it as RAPID friendly XML or as standalone html
	Write-Output $script:masterResults
	
	## clear temporary structures on disk
#	IF (-not $skipClearCacheOnExit){
#		Remove-Item $cacheRootPath\* -force -Recurse
#	}
    #Write-Host "Attempting to schedule async deletion of temp files via task scheduler"
    Write-Host "Creating out of band cmd.exe instance to delete temp files asynchronously"
    #$soonTimeString = "{0:HH:mm}" -f ((Get-Date).AddMinutes(2))
    #$schTaskUniquifier = Split-Path -Leaf $cacheRootPath
    try{
        ## creating different versions of cmdline depending on OS to account for KB
#        [string]$schtaskscmdline = $(
#            $win32OS = Get-WMIObject -query "select version from Win32_OperatingSystem"
#            IF( $win32OS.version -like "5.*" ){
#                "schtasks /create /SC ONCE /ST $soonTimeString /TN TokenSizeTempCleanup$schTaskUniquifier /RU SYSTEM /Z /TR 'cmd /C rd $cacheRootPath /S /Q'"
#            }
#            ELSE{
#                "schtasks /create /SC ONCE /ST $soonTimeString /TN TokenSizeTempCleanup$schTaskUniquifier /RU SYSTEM /Z /V1 /TR 'cmd /C rd $cacheRootPath /S /Q'"
#            }
#        )
#        invoke-expression $schtaskscmdline  > $null

        Start-Process -FilePath cmd.exe -ArgumentList "/C rd $cacheRootPath /S /Q" -WindowStyle Hidden -ErrorAction Stop
 #       IF ($LASTEXITCODE -ne 0 ){
 #           throw "failed to schedule deletion"
 #       }
    }
    catch{
        Write-Host "Temp files deletion failed"
        Write-Host "Files at $cacheRootPath can be manually deleted to recover disk space"
        continue
    }
    finally{
    
    	Dispose-sDSPSearchKeptConnections -all
    	
    	##@#@#perfwp $myinvocation.mycommand.name
    	
    	$overallEndTime = Get-Date
    	$script:masterResults.Telemetry.TotalRunTime = $overallEndTime - $overallStartTime
    	$script:masterResults.Telemetry.ToolCompletedAcceptably = $true
    	IF($error.count -eq 0){ $script:masterResults.Telemetry.ToolCompletedErrorFree = $true }
    }
	
}










#######################################                ##########
#######################################  FUNCTIONS     ##########
#######################################                ##########


########################

function Invoke-MiscInitializationAndCleanup{

#########################

	trap{
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"Invoke-MiscInitializationAndCleanup__TRAP-A", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $errorRecord
		$Error.Insert( 0 , $errorRecord )
	}

	##@#@#perfwp $myinvocation.mycommand.name -d
	
	IF( (Get-WmiObject -Class Win32_ComputerSystem).domainrole -ge 4 ){
		Write-Host "This tool consumes significant CPU cycles. It should not be run directly on a production domain controller"
		Write-Host "Instead it should be run on a member server in the domain or forest of interest"
		Write-Host ""
		IF (-not $RAPIntegrationMode){
			Read-Host -Prompt "Press control+C to exit, or 'Enter' to proceed" > $null
		}
	}

	## clear temp disk structures
	IF (-not $skipClearCacheOnStart -and (Test-Path $cacheRootPath)){
		Remove-Item $cacheRootPath\* -force -Recurse
		Remove-Item $cacheRootPath -force -Recurse
	}
	
	## create cache dir and first level structures
	New-Item -ItemType Directory -Path $( split-path -Parent $cacheRootPath) -Name $( Split-Path -Leaf $cacheRootPath) > $null
	New-Item -ItemType Directory -Path $cacheRootPath -Name ExpansionFactor > $null
	New-Item -ItemType Directory -Path $cacheRootPath -Name Groups > $null
	New-Item -ItemType Directory -Path $cacheRootPath -Name Users > $null
	New-Item -ItemType Directory -Path $cacheRootPath -Name UserTicketBytesIndex > $null
	New-Item -ItemType Directory -Path $cacheRootPath -Name UserTokenSIDCountIndex > $null
	New-Item -ItemType Directory -Path $cacherootPath -Name TGSExpansion > $null
	
	##@#@#perfwp $myinvocation.mycommand.name

	#define master results object which will collect many things and be returned
	#for the wrapper layer to parse/display
	$script:masterResults = New-Object psobject
	Add-Member -InputObject $script:masterResults -MemberType NoteProperty -Name Thresholds -Value @{}
	Add-Member -InputObject $script:masterResults -MemberType NoteProperty -Name Telemetry -Value @{}
	Add-Member -InputObject $script:masterResults -MemberType NoteProperty -Name biggesttokenusers -Value @()
	Add-Member -InputObject $script:masterResults -MemberType NoteProperty -Name ContributingGroups -Value @()

	$script:masterResults.Thresholds.AccTkn_PoolAlloc44KB = @{ 
		FailThreshold = [int]921 ;
		WarnThreshold = [int]916 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}
	$script:masterResults.Thresholds.AccTkn_PoolAlloc40KB = @{ 
		FailThreshold = [int]828 ;
		WarnThreshold = [int]823 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}
	$script:masterResults.Thresholds.AccTkn_PoolAlloc36KB = @{ 
		FailThreshold = [int]735 ;
		WarnThreshold = [int]730 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}
	$script:masterResults.Thresholds.AccTkn_PoolAlloc32KB = @{ 
		FailThreshold = [int]642 ;
		WarnThreshold = [int]637 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}
	$script:masterResults.Thresholds.AccTkn_PoolAlloc28KB = @{ 
		FailThreshold = [int]549 ;
		WarnThreshold = [int]544 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}	
	$script:masterResults.Thresholds.AccTkn_PoolAlloc24KB = @{ 
		FailThreshold = [int]456 ;
		WarnThreshold = [int]451 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}	
	$script:masterResults.Thresholds.AccTkn_PoolAlloc20KB = @{ 
		FailThreshold = [int]363 ;
		WarnThreshold = [int]358 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}	
	$script:masterResults.Thresholds.AccTkn_PoolAlloc16KB = @{ 
		FailThreshold = [int]270 ;
		WarnThreshold = [int]265 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}	
	$script:masterResults.Thresholds.AccTkn_PoolAlloc12KB = @{ 
		FailThreshold = [int]177 ;
		WarnThreshold = [int]172 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}	
	$script:masterResults.Thresholds.AccTkn_PoolAlloc08KB = @{ 
		FailThreshold = [int]84 ;
		WarnThreshold = [int]79 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}
	$script:masterResults.Thresholds.AccTkn_AbsoluteSIDLimit = @{ 
		FailThreshold = [int]1015 ;
		WarnThreshold = [int]950 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}	
	$script:masterResults.Thresholds.KrbTkt_IIS5Default = @{ 
		FailThreshold = [int]10000 ;
		WarnThreshold = [int]9600 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}	
	$script:masterResults.Thresholds.KrbTkt_IIS67Default = @{ 
		FailThreshold = [int]10000 ;
		WarnThreshold = [int]9600 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}	
	$script:masterResults.Thresholds.KrbTkt_OSMaxTokenSizeDefault = @{ 
		FailThreshold = [int]12000 ;
		WarnThreshold = [int]10000 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}	
	$script:masterResults.Thresholds.KrbTkt_OSMaxTokenSizeMaxConfig = @{ 
		FailThreshold = [int]64000 ;
		WarnThreshold = [int]62000 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;		
	}
# Deprecating this threshold for now
# The idea was to create a discussion around MaxPacketSize and UDP/TCP,
# but fr moa threshold standpoint it wasn't very useful.
#	$script:masterResults.Thresholds.OSUDPSafeLimit = @{ 
#		FailThreshold = [int]1000 ;
#		WarnThreshold = [int]900 ;
#		FailCount = [int]0 ;
#		WarnCount = [int]0 ;	
#	}	
	$script:masterResults.Thresholds.UsersWithSIDHistory = @{ 
		#note that this is a simple count (using the Warncount
		#field, but fon the sake of schema consistency I have
		#retained the extra fields.
		FailThreshold = [int]0 ;
		WarnThreshold = [int]0 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;	
	}
	$script:masterResults.Thresholds.GroupsWithSIDHistory = @{ 
		FailThreshold = [int]0 ;
		WarnThreshold = [int]0 ;
		FailCount = [int]0 ;
		WarnCount = [int]0 ;	
	}	
	
	$script:masterResults.Telemetry.FullyExpandedCacheHits = [int]0
	$script:masterResults.Telemetry.FullyExpandedCacheMisses = [int]0
	$script:masterResults.Telemetry.TGSExpansionHits = [int]0
	$script:masterResults.Telemetry.TGSExpansionMisses = [int]0
	$script:masterResults.Telemetry.SkippedPrincipalCount = [int]0
	$script:masterResults.Telemetry.SkippedDomains = @{}
	$script:masterResults.Telemetry.TriagedDomains = @{}
	$script:masterResults.Telemetry.UsersEvaluated = [int]0
	$script:masterResults.Telemetry.GroupsEvaluated = [int]0
	$script:masterResults.Telemetry.AuthPathsEvaluated = [int]0
	$script:masterResults.Telemetry.GroupsRAMCacheRowsUsed = [int]0
	$script:masterResults.Telemetry.GroupsDiskCacheRowsUsed = [int]0
	$script:masterResults.Telemetry.TGSExpansionRAMCacheRowsUsed = [int]0
	$script:masterResults.Telemetry.GroupsRAMCacheRowsAllowed = $cacheRowsAllowed
	$script:masterResults.Telemetry.TGSExpansionRAMCacheRowsAllowed = $cacheRowsAllowed
	$script:masterResults.Telemetry.AbortThresholdSkippedPrincipals = $AbortThresholdSkippedPrincipals
	
	$script:masterResults.Telemetry.ToolCompletedAcceptably = $false
	$script:masterResults.Telemetry.ToolCompletedErrorFree = $false
	
	$script:masterResults.Telemetry.TotalRunTime = [TimeSpan]0

	$script:TGSExpansionRAMCache = @{}
	$script:GroupsRAMCache = @{}
	
	##create header for optional all users csv file
	IF( $createAllUsersCSV){
		"DistinguishedName`tKrbTkt_TicketBytes`tAccTkn_SIDCount`tAccTkn_PoolAllocKB`tAccTkn_PoolAllocGreaterThanDefault`tAccTkn_PoolAllocNextJumpWarning`tAccTkn_AbsoluteSIDLimit`tKrbTkt_IIS5Default`tKrbTkt_IIS67Default`tKrbTkt_OSMaxTokenSizeDefault`tKrbTkt_OSMaxTokenSizeMaxConfig`tLargestTokenResourceDomain" > (join-path $csvoutputfolder AllUsersCSV.csv)
	}
	
	IF( $preferredForestGC.length -eq 0 ){
		Write-Host "### Auto-detecting forest reference GC"
		$preferredForestGC = $(
			Get-DCNameEx2 `
				-Domain "*" `
				-gc `
				-expensiveLatencySort `
				-excludeNonResponsive `
				-scopeLevel 2 `
				-singleResultOnly
		)
	}
	$preferredForestGC += ":3268"
	
	Write-Host "###     $preferredForestGC"

	##@#@#perfwp $myinvocation.mycommand.name
}



#######################################

function Get-PrincipalsFromDomain {

#######################################

	trap {
		Write-Host "Failed in Get-PrincipalsFromDomain"
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"Get-PrincipalsFromDomain__TrapA", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $ErrorRecord -ErrorAction SilentlyContinue
		$Error.Insert( 0 , $errorRecord )
	
		throw $errorRecord
	}

	##@#@#perfwp $myinvocation.mycommand.name -d
	

	
	
	SWITCH($currentBasePrincipalType){
		{$_ -ne "UG"}{
			Write-Host "### Analyzing $currentBasePrincipalType objects from $($currentBaseScope.DNSDomainName)"
			Write-Host "###     Initially using $($currentBaseScope.preferredDC)"
			break
		}
		{ $_ -eq "UG" }{
			Write-Host "### Analyzing $currentBasePrincipalType objects from forest"
			Write-Host "###     Initially using $preferredForestGC"
			break
		}
	}
	
	##	Set up up mechanism to watch for whether everyone and authUsers fsps have been spotted in current domain.
	IF ($script:currentBasePrincipalType -eq "FSP"){
		[bool]$script:everyoneFSPSeenInDomain = $false
		[bool]$script:AUthUsersFSPSeenInDomain = $false
	}

	#get and emit principals
	## the pipeline will move to subsequent filters whenever this is emitting
    
    ##@#@#perfwp $myinvocation.mycommand.name
    
	[string]$tempFilter = Get-PrincipalTypeLDAPFilter $script:currentBasePrincipalType
	
	##TODO: FUTURE: Re-think for which cases we can use a GC
	
	invoke-sdspsearch `
		-computername $( IF ($currentBasePrincipalType -eq "UG" ){ $preferredForestGC }ELSE{ $currentBaseScope.preferredDC } ) `
		-baseDN $( IF( $currentBasePrincipalType -eq "UG" ){ $null }ELSE{ $currentBaseScope.distinguishedName } ) `
		-Scope "SubTree" `
		-filter $tempFilter `
		-attributes distinguishedName,objectsid,sidhistory,primarygroupid,objectClass,groupType,samaccountname `
		-Warnings $false `
		-timeout $LDAPTimeoutHigh `
		-retry 3 `
		-controls "P","DS" `
		-pagesize 400 `
		-connectionKeeping $true `
		-rethrow
        
    ##@#@#perfwp $myinvocation.mycommand.name -d
	
	## Mechanism to create synthetic AUthUsers and Everyone FSPs if needed.
	IF ($script:currentBasePrincipalType -eq "FSP"){
		IF($script:everyoneFSPSeenInDomain -eq $false){

			Invoke-SpecialSyntheticFSPShortCut -specialFSP "Everyone"

		}
		IF($script:AuthUsersFSPSeenInDomain -eq $false){

			Invoke-SpecialSyntheticFSPShortCut -specialFSP "AuthUsers"

		}
	}
	
	##@#@#perfwp $myinvocation.mycommand.name
}


##########################

Filter Get-BasePrincipalObjectforPrincipal{

###########################

	trap{
		## skip current principal for whatever reason
		Write-Host "s" -NoNewline
		$script:masterResults.Telemetry.SkippedPrincipalCount++
		
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"Get-BasePrincipalObjectforPrincipal__TrapA", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $ErrorRecord -ErrorAction SilentlyContinue
		$Error.Insert( 0 , $errorRecord )

	
		IF( $script:masterResults.Telemetry.SkippedPrincipalCount -ge $script:masterResults.Telemetry.AbortThresholdSkippedPrincipals ){
			Write-Host "The number of users or groups that have been skipped"
			Write-Host "due to data gathering errors has exceeded the allowed"
			Write-Host "limit (configured as -AbortThresholdSkippedPrincipals)"
			Write-Host "Exiting"
			Write-Error "AbortThresholdSkippedPrincipals exceeded"
			throw $errorRecord
		}
		ELSE{
			Continue
		}
	}
	

	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	
#	## check if pipeline input is expected type
#	IF ($_ -isnot [system.directoryservices.protocols.searchresultentry]) {
#		Throw ( 
#			New-CustomErrorObject `
#				-intention "Abort due to AbortThresholdSkippedPrincipals" `
#				-uniqueID "090f9d04-6434-44bc-a1e6-36b39bfb4168" 
#		)
#	}
	
	## Wrapping function content in false DO/WHILE in order
	## to allow "skipping" of failed pipeline objects
	## Note that in powershell v2 this construct can be replaced wit hthe use
	## of 'Return' in the trap
	DO{
	
		## assign pipeline input to mroe useful variable name
		$ldapSearchEntry = $_
		
	
		##@#@#perfwp $myinvocation.mycommand.name
		
		$protoBasePrincipal = New-BasePrincipal -ldapObject $ldapSearchEntry
		
		##@#@#perfwp $myinvocation.mycommand.name -d
		
		##
		## check if current principal is everyone or authenticated users, in order
		## to update the watcher objects which determine if we need to create
		## synthetic everyone or authenticated users
		##
		IF ($script:currentBasePrincipalType -eq "FSP"){
			IF(-not (Compare-Object ([byte[]](1,1,0,0,0,0,0,5,11,0,0,0)) (($ldapsearchentry.attributes.objectsid.getvalues([byte[]]))[0]))){
				$script:AuthUsersFSPSeenInDomain = $true
			}
			IF(-not (Compare-Object ([byte[]](1,1,0,0,0,0,0,1,0,0,0,0)) (($ldapsearchentry.attributes.objectsid.getvalues([byte[]]))[0]))){
				$script:EveryoneFSPSeenInDomain = $true
			}
		}
		
		##@#@#perfwp $myinvocation.mycommand.name
		
		Write-Output $protoBasePrincipal
		
		##@#@#perfwp $myinvocation.mycommand.name -d
		
		##@#@#perfwp $myinvocation.invocationname
	}`
	WHILE($false)
}


##########################################

Function New-BasePrincipal {

##########################################

	##
	## When a group is seen in the first level enumeration of groups, and the group is being fully expanded
	## that group is called a "base" group. The goal when dealing with a base group is to fully expand 
	## its effective memberOf, and then serialize the results to the on-disk cache for later use
	##
	## This function creates and emits a blank object meant to be used to collect information learned
	## about the group during processing.
	##
	## An sdsp result object can be passed in, and will be assigned to the property "ldapObject"
	##
	param(
		$ldapObject
	)
	
	trap{
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"New-BasePrincipal__TrapA", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $ErrorRecord -ErrorAction SilentlyContinue
		$Error.Insert( 0 , $errorRecord )
		continue
	}
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	DO{
		
		##
		## Build up base principal object
		##
		$protoBasePrincipal = New-Object psobject
		Add-Member `
			-inputObject $protoBasePrincipal `
			-MemberType NoteProperty `
			-Name ldapObject `
			-Value $ldapObject
		Add-Member `
			-inputObject $protoBasePrincipal `
			-MemberType NoteProperty `
			-Name DistinguishedName `
			-Value ($protoBasePrincipal.ldapobject.distinguishedName)
		IF ($currentBasePrincipalType -ne "FSP"){ 
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name SAMAccountName `
				-Value ($protoBasePrincipal.ldapobject.attributes.samaccountname.getvalues([string])[0])
		}
		Add-Member `
			-inputObject $protoBasePrincipal `
			-MemberType NoteProperty `
			-Name SIDKey `
			-Value (
				New-SIDKey -sidBytes $protoBasePrincipal.ldapobject.attributes.objectsid.getvalues([byte[]])[0] -DNSDomainName $currentBaseScope.DNSDomainName 
			)
		Add-Member `
			-inputObject $protoBasePrincipal `
			-MemberType NoteProperty `
			-Name pendingMemberOfQueueReadOnly `
			-Value @()
		Add-Member `
			-inputObject $protoBasePrincipal `
			-MemberType NoteProperty `
			-Name pendingMemberOfQueueWritable `
			-Value @{}
		Add-Member `
			-inputObject $protoBasePrincipal `
			-MemberType NoteProperty `
			-Name effectiveMemberOfTable `
			-Value @{}
		Add-Member `
			-inputObject $protoBasePrincipal `
			-MemberType NoteProperty `
			-Name DNSDomainName `
			-Value $currentBaseScope.DNSDomainName
		Add-Member `
			-inputObject $protoBasePrincipal `
			-MemberType NoteProperty `
			-Name principalType `
			-Value $script:currentBasePrincipalType
		Add-Member `
			-inputObject $protoBasePrincipal `
			-MemberType NoteProperty `
			-Name SIDKeyTrie2Path `
			-Value $(
				##@#@#perfwp $myinvocation.mycommand.name
				New-Trie2PathString `
					-rootPath $(
						IF($protoBasePrincipal.principalType -eq "USER"){ 
							Join-Path $cacherootpath Users 
						}
						ELSE{
							Join-Path $cacheRootPath Groups
						}
					)`
					-keyName $protoBasePrincipal.SIDKey `
					-prefixTokenLengths 2,2 `
					-prefixTokenStartingOffset 48
				##@#@#perfwp $myinvocation.mycommand.name -d	
			)
		## followng properties only used for groups
		## since there isn't an easy way to do formal classes and inheirtance in powerhsell v1
		## I'll just selectively add properties here.
		IF( $protobasePrincipal.principalType -ne "USER"){
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name ExpansionFactor `
				-Value ([int]0)
		}
		#following properties only used for users
		IF( $protoBasePrincipal.principalType -eq "USER"){
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name domainSID `
				-Value ""
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name primaryGroupRIDKey `
				-Value ""
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name primaryGroupSIDKey `
				-Value ""
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name protoTicketTGT40ByteSIDs `
				-Value ([int]0)
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name protoTicketTGT8ByteSIDs `
				-Value ([int]0)
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name protoTokenTGTSIDCount `
				-Value ([int]0)
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name highestTicketBytesAnyResourceDomain `
				-Value ([int]0)
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name highestTokenSIDCountAnyResourceDomain `
				-Value ([int]0)
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name BiggestTicketAndTokenResourceDomain `
				-Value ([string]"")
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name estimatedTicketBytesPerResourceDomain `
				-Value @{}
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name estimatedTokenSIDCountPerResourceDomain `
				-Value @{}
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name AccTkn_AbsoluteSIDLimit `
				-Value "Pass"
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name AccTkn_PoolAllocKB `
				-Value 4
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name AccTkn_PoolAllocGreaterThanDefault `
				-Value "Pass"
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name AccTkn_PoolAllocNextJumpWarning `
				-Value "Pass"
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name KrbTkt_IIS5Default `
				-Value "Pass"
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name KrbTkt_IIS67Default `
				-Value "Pass"
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name KrbTkt_OSMaxTokenSizeDefault `
				-Value "Pass"
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType NoteProperty `
				-Name KrbTkt_OSMaxTokenSizeMaxConfig `
				-Value "Pass"
			#Deprecated
			#Add-Member -inputObject $protoBasePrincipal -MemberType NoteProperty -Name OSUDPSafeLimit -Value "Pass"
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType AliasProperty `
				-Name AccTkn_SIDCount `
				-Value highestTokenSIDCountAnyResourceDomain
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType AliasProperty `
				-Name KrbTkt_TicketBytes `
				-Value highestTicketBytesAnyResourceDomain
			Add-Member `
				-inputObject $protoBasePrincipal `
				-MemberType AliasProperty `
				-Name LargestTokenResourceDomain `
				-Value biggestTicketAndTokenResourceDomain
		}
		## adding methods (for both users and groups)
		Add-Member `
			-inputObject $protoBasePrincipal `
			-MemberType ScriptMethod `
			-Name mergeEffectiveMemberOfFromCache `
			-Value {
				##
				## reads a serialized effective member of object from RAM or on disk cache (representing a 
				## group which has previously been fully expanded), and merges the data
				## with an in memory effective member of structure which is being built up for a new user or group.
				##
				##
				## arguments are positional and are:
				## 0 : $SIDKey (always required)
				## 1 : $indexName (defaults to "groups")
				## 2 : $skipCacheCheck (defaults to $false)
				##@#@#perfwp "mergeEffectiveMemberOfFromCache" -d
				
				## todo: future: I think this always operates in "groups" mode, so I can probably get rid of the second argument,
				## though that changes the signature since it is positional so I will ahve to update callers
			
				Switch($args.count){
					0{ 	
						Throw ( 
							New-Object System.Management.Automation.ErrorRecord ( 
								"bad number of args passed to mergeEffectiveMemberOfFromCache method", 
								"6478cbb4-3e9c-4c11-901d-41f238c16502", 
								"NotSpecified", 
								(Get-ScriptStack)
							)
						) 
					}
					1{ $SIDKey = $args[0] ; [string]$indexName = "groups" ; $skipcachecheck=$false ; break }
					2{ $SIDKey = $args[0] ; [string]$indexName = $args[1] ; $skipcachecheck=$false ; break }
					3{ $SIDKey = $args[0] ; [string]$indexName = $args[1] ; $skipcachecheck=$args[2] ; break }
				}
				
				##@#@#perfwp "mergeEffectiveMemberOfFromCache"
				
				IF ($skipcachecheck -or (Test-Caches -mode "GROUPS" -sIDKey $SIDKey)){
					##@#@#perfwp "mergeEffectiveMemberOfFromCache"
					#TODO: Future: This section (call to get-deserialized baseprincipal) seems extremely slow.
					# Attempted workaround ineffective. Research further in the future.
					$deSerializedBasePrincipal = Get-DeserializedBasePrincipal -sidKey $sidKey
					
					##@#@#perfwp "mergeEffectiveMemberOfFromCache"
					
					foreach( $value IN $deSerializedBasePrincipal.effectiveMemberOfTable.Values){
						IF (-not $this.effectiveMemberOfTable.ContainsKey( $value.DistinguishedName ) ){
							##@#@#perfwp "mergeEffectiveMemberOfFromCache"
							$this.effectiveMemberOfTable.Add( $value.DistinguishedName , $value )
							##@#@#perfwp "mergeEffectiveMemberOfFromCache"
						}
					}
				}
				
				##@#@#perfwp "mergeEffectiveMemberOfFromCache"
			}
	
		##@#@#perfwp $myinvocation.mycommand.name
		Write-Output $protoBasePrincipal
		##@#@#perfwp $myinvocation.mycommand.name -d
		$protoBasePrincipal =$null
		
		##@#@#perfwp $myinvocation.mycommand.name
		
	}WHILE($false)
}




################################################

Filter Get-EffectiveMemberOfForBasePrincipal{

###############################################
	trap{
		## skip current principal for whatever reason
		Write-Host "s" -NoNewline
		$script:masterResults.Telemetry.SkippedPrincipalCount++
		
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"Get-EffectiveMemberOfForBasePrincipal__TrapA", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $ErrorRecord -ErrorAction SilentlyContinue
		$Error.Insert(0,$errorRecord)

	
		IF( $script:masterResults.Telemetry.SkippedPrincipalCount -ge $script:masterResults.Telemetry.AbortThresholdSkippedPrincipals ){
			Write-Host "The number of users or groups that have been skipped"
			Write-Host "due to data gathering errors has exceeded the allowed"
			Write-Host "limit (configured as -AbortThresholdSkippedPrincipals)"
			Write-Host "Exiting"
			Write-Error "AbortThresholdSkippedPrincipals exceeded"
			throw $errorRecord
		}
		ELSE{
			Continue
		}
	}

	DO{
		##@#@#perfwp $myinvocation.mycommand.name -d
	
		$currentBasePrincipal = $_
		
		##
		## Add base principal self to own effective MemberOf, expect when processing an FSP
		##
		
		## add self to effectiveMemberOf as long as it is not an FSP (with the exception of everyone and AU, which should be added)
		IF( `
			($currentBasePrincipal.principalType -eq "USER") -or `
			($currentBasePrincipal.principalType -eq "DLG") -or `
			($currentBasePrincipal.principalType -eq "UG") -or `
			($currentBasePrincipal.principalType -eq "GG") -or `
			(-not (Compare-Object ([byte[]](1,1,0,0,0,0,0,5,11,0,0,0)) ($currentBasePrincipal.ldapObject.attributes.objectsid.getvalues([byte[]])[0]))) -or `
			(-not (Compare-Object ([byte[]](1,1,0,0,0,0,0,1,0,0,0,0)) ($currentBasePrincipal.ldapObject.attributes.objectsid.getvalues([byte[]]))[0]))
		){
			##@#@#perfwp $myinvocation.mycommand.name -d
			$tempEffectivememberOfEntry = New-EffectiveMemberOfEntry -ldapObject $currentBasePrincipal.ldapobject
			##@#@#perfwp $myinvocation.mycommand.name -d
			$currentBasePrincipal.effectiveMemberOfTable.add($currentBasePrincipal.distinguishedname , $tempEffectivememberOfEntry )
			##@#@#perfwp $myinvocation.mycommand.name
		}
		
		##@#@#perfwp $myinvocation.mycommand.name
		
		##
		## Add sidHistory to self. At first add directly, regardless of potential expansion
		##
		
		## add sid history to effective member of, regardless of potential expansion
		IF ( $currentBasePrincipal.ldapobject.attributes.contains( "sidhistory" ) ){
			#Write-Status 2 2 "Handling sid history"
			IF ( "GG","UG","DLG" -eq $currentBasePrincipalType){
				$script:masterResults.Thresholds.GroupsWithSIDHistory.Warncount++
			}
			ELSEIF( "USER" -eq $currentBasePrincipalType ){
				$script:masterResults.Thresholds.UsersWithSIDHistory.Warncount++
			}
			## create an effectivememberOf object from SIDHistory SID(s), and add to effectiveMemberOf collection
			foreach ($sIDHistorySID IN $currentBasePrincipal.ldapobject.attributes.sidhistory.getvalues([byte[]]) ){
				$effectiveMemberOfEntry = New-EffectiveMemberOfEntry -ldapObject $currentBasePrincipal.ldapobject -sIDHistoryMode -sIDHistorySID $sIDHistorySID
				IF (-not $currentBasePrincipal.effectiveMemberOfTable.ContainsKey( $effectiveMemberOfEntry.distinguishedName ) ){
					$currentBasePrincipal.effectiveMemberOfTable.add( $effectiveMemberOfEntry.distinguishedname , $effectiveMemberOfEntry ) 
				}
			}
		}
		##@#@#perfwp $myinvocation.mycommand.name
		
		
		##
		## For users, add primary group. This should always come from cache, similar to sid history above
		##
		
		IF ($currentBasePrincipal.principalType -eq "USER") {
		
			$currentBasePrincipal.domainSID = $currentBasePrincipal.SIDKey.substring( 0 , 48 )
			$currentBasePrincipal.primaryGroupRIDKey = $(
				[int]$primaryGroupIDAsInt = ( $currentbasePrincipal.ldapobject.Attributes.primarygroupid.getvalues([string]))[0] ;
				[byte[]]$primaryGroupIDAsByteArray = [bitconverter]::GetBytes( $primaryGroupIDAsInt ) ;
				##@#@#perfwp $myinvocation.mycommand.name
				Format-ByteArrayAsHexString -byteArray $primaryGroupIDAsByteArray
				##@#@#perfwp $myinvocation.mycommand.name -d
				$primaryGroupIDAsInt = $null
				$primaryGroupIDAsByteArray = $null
			)
			
			[string]$currentBasePrincipal.primaryGroupSIDKey = $currentBasePrincipal.domainSID + $currentBasePrincipal.primaryGroupRIDKey
		
			IF ( Test-Caches -sIDKey $currentBasePrincipal.primaryGroupSIDKey -mode "groups"){
				##@#@#perfwp $myinvocation.mycommand.name
				$currentBasePrincipal.mergeEffectiveMemberOfFromCache( $currentBasePrincipal.primaryGroupSIDKey )
				##@#@#perfwp $myinvocation.mycommand.name -d
				$script:masterResults.Telemetry.FullyExpandedCacheHits++
			}
			ELSE{
				Write-Host "User's primary group not found in cache, this is unexpected"
				Throw ( 
					New-Object System.Management.Automation.ErrorRecord ( 
						"Primary group lookup failed, throw to skip user", 
						"86b0d31d-c816-4490-a740-e4bf8c5692ad", 
						"NotSpecified", 
						(Get-ScriptStack)
					)
				)
				$script:masterResults.Telemetry.FullyExpandedCacheMisses++
			}		
		}
		##@#@#perfwp $myinvocation.mycommand.name
		
		##
		## For users, add all relevent Everone and AUthenticated Users concepts to effective memberof
		## THis will allow for effectively simulating E and AU behavior later
		##
		IF ($currentBasePrincipal.principalType -eq "USER"){
			##TODO: Future: It seems wasteful to do all these assignments and false sid key creations for every user. 
			## We could create all the values once at the beginning, and then just assign as needed for the user.
			[byte[]]$AuthUsersSIDBytes = (1,1,0,0,0,0,0,5,11,0,0,0)
			[byte[]]$EveryoneSIDBytes = (1,1,0,0,0,0,0,1,0,0,0,0)
			
			## loop through resource domain names
			## for each one, guess what authenticated users and everyone FSPs (and synthetic FSPs) would look like.
			## then retrieve memberships from cache.
			
			foreach($resourceDomain2 IN $resourceDomains){
				$tempEveryoneSIDKey = new-SIDKey $everyoneSIDbytes $resourcedomain2
				$tempAUthUsersSIDKey = new-SIDKey $authUsersSIDbytes $resourcedomain2
				$currentBasePrincipal.mergeEffectiveMemberOfFromCache( $tempEveryoneSIDKey )
				$currentBasePrincipal.mergeEffectiveMemberOfFromCache( $tempAUthUsersSIDKey )
				
				$tempEveryoneSIDKey = $null
				$tempAUthUsersSIDKey = $null
			}
			
			$AuthUsersSIDBytes = $null
			$EveryoneSIDBytes = $null
		}
		##@#@#perfwp $myinvocation.mycommand.name
		
		
		##
		## Get Principal's memberOf.
		##
		## For FSPs and DLGs include Security DLGs. For portable principals (USER, UG, GG) only get 
		## security GGs and UGs. The reason DLGs are skipped here is that DLGs are not properly represented in
		## memberOf (unless you are willing to query for the same base principal against a GC in every resource domain)
		## so we will do what SAM does which is to ignore DLGs at first, and expand on DLGs and FSPs based
		## on SID matching later on
		##
		## for each memberOf entry which would be included in a TGT, there will either already be a fully expanded item in cache (which we merge)
		##	or we will fully recurse on an uncached item.
		##
		## This results in a fully expanded version of the current base principal, but expanded versions of other groups seen
		## along the way are not stored.
		##
		##
		
		##@#@#perfwp $myinvocation.mycommand.name
		##TODO: Future: This is surprisingly slow, and it appears to be only partially the fault of "get-principaltypeLDAPfilter"
		## consider replacing all this dynamically generated stuff with a big precalculated table that we just pull from
		## using a conditional
		
		$tempFilter2 = $(
			IF ( `
				($currentBasePrincipal.principalType -eq "USER") `
				-or ($currentBasePrincipal.principalType -eq "GG") `
				-or ($currentBasePrincipal.principalType -eq "UG") `
			){
				Write-Output "(|$(Get-PrincipalTypeLDAPFIlter 'UG')$(Get-PrincipalTypeLDAPFIlter 'GG'))"
			}
			ELSEIF(`
				($currentBasePrincipal.principalType -eq "FSP") `
				-or ($currentBasePrincipal.principalType -eq "DLG") `
			){
				Write-Output "$(Get-PrincipalTypeLDAPFIlter 'DLG')"
			}
		)
		
		##@#@#perfwp $myinvocation.mycommand.name
		. Get-AndTriageDirectMemberOf `
		-dynamicBaseDistinguishedName $currentBasePrincipal.distinguishedName `
		-customFilter $tempFilter2
		##@#@#perfwp $myinvocation.mycommand.name -d
		
		WHILE ($currentBasePrincipal.pendingMemberOfQueueWritable.Count -gt 0){
			$currentBasePrincipal.pendingMemberOfQueueReadOnly = @($currentBasePrincipal.pendingMemberOfQueueWritable.keys.getenumerator())
			foreach ($DN IN $currentBasePrincipal.pendingMemberOfQueueReadOnly){
				$currentBasePrincipal.effectiveMemberOfTable.$DN = $currentBasePrincipal.pendingMemberOfQueueWritable.$DN
				$currentBasePrincipal.pendingMemberOfQueueWritable.remove($DN)
				##@#@#perfwp $myinvocation.mycommand.name
				. Get-AndTriageDirectMemberOf $DN $tempFilter2
				##@#@#perfwp $myinvocation.mycommand.name -d
			}
		}
		##@#@#perfwp $myinvocation.mycommand.name
		
		$tempFilter2 = $null
		
		
		##
		## Get missing DLG and FSP memberships
		##
		## Because we skipped getting DLG memberOf info earlier (because it would be too expensive to do it properly over the network, so
		## we choose to do it locally here), we now need to compare the current base principal (if it is a portable principal)
		## against the TGS expansion lookup index and merge where needed.
		##
		IF( `
			($currentBasePrincipal.principalType -eq "USER") `
			-or ($currentBasePrincipal.principalType -eq "GG") `
			-or ($currentBasePrincipal.principalType -eq "UG") `
		){
			##@#@#perfwp $myinvocation.mycommand.name -d
			#Write-Status 2 2 "Handling TGS Expansion Lookup"
			##@#@#perfwp $myinvocation.mycommand.name
			$TGTPrincipalsToExpandUpon = @(
				IF ($currentBasePrincipal.principalType -eq "USER"){
	
					$currentbasePrincipal.effectiveMemberOfTable.Values | Where-Object { $_.principalType -eq "USER" }
	
				}
				ELSE{
	
					$currentbasePrincipal.effectiveMemberOfTable.Values.getenumerator()
				}
			)
			##@#@#perfwp $myinvocation.mycommand.name
			
			
			foreach($effectiveMemberOfEntry IN $TGTPrincipalsToExpandUpon){
				##@#@#perfwp $myinvocation.mycommand.name -d
				$DLGSIDKeysToLoopThrough = @()
				##@#@#perfwp $myinvocation.mycommand.name
				$tempFlagCachePresence = test-caches -mode "TGSExpansion" -sidKey $effectiveMemberOfEntry.SIDKey
				##@#@#perfwp $myinvocation.mycommand.name
				IF( $tempFlagCachePresence ){
					##@#@#perfwp $myinvocation.mycommand.name -d
					$DLGSIDKeysToLoopThrough = @(
						Get-TGSExpansionCacheContent -sidkey $effectiveMemberOfEntry.SIDKey
					)
					##@#@#perfwp $myinvocation.mycommand.name
					Foreach ($DLGSIDKey IN $DLGSIDKeysToLoopThrough){
						##TODO: This is probably very slow
						$currentBasePrincipal.MergeEffectiveMemberofFromCache( $DLGSIDKey )
					}
					##@#@#perfwp $myinvocation.mycommand.name
				}
				$DLGSIDKeysToLoopThrough = $null
			}
			$TGTPrincipalsToExpandUpon = $null
			##@#@#perfwp $myinvocation.mycommand.name
		}
		
		
		##
		## EMit the populated basePrincipal object
		##
		##@#@#perfwp $myinvocation.mycommand.name
		Write-Output $currentBasePrincipal
		##@#@#perfwp $myinvocation.mycommand.name -d
		
		$currentBasePrincipal.distinguishedName = $null
		$currentBasePrincipal.ldapobject = $null
		$currentBasePrincipal = $null
		
		##@#@#perfwp $myinvocation.mycommand.name
	}WHILE($false)
}



################################################

Filter Invoke-ExtraBasePrincipalProcessingForGroups{

################################################

	trap{
		## skip current principal for whatever reason
		Write-Host "s" -NoNewline
		$script:masterResults.Telemetry.SkippedPrincipalCount++
		
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"Invoke-ExtraBasePrincipalProcessingForGroups__TrapA", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $ErrorRecord -ErrorAction SilentlyContinue
		$Error.Insert(0,$errorRecord)

	
		IF( $script:masterResults.Telemetry.SkippedPrincipalCount -ge $script:masterResults.Telemetry.AbortThresholdSkippedPrincipals ){
			Write-Host "The number of users or groups that have been skipped"
			Write-Host "due to data gathering errors has exceeded the allowed"
			Write-Host "limit (configured as -AbortThresholdSkippedPrincipals)"
			Write-Host "Exiting"
			Write-Error "AbortThresholdSkippedPrincipals exceeded"
			throw $errorRecord
		}
		ELSE{
			Continue
		}
	}
	
	DO{
		##@#@#perfwp $myinvocation.mycommand.name -d
	
		$currentbasePrincipal = $_
		
		##@#@#perfwp $myinvocation.mycommand.name
		##@#@#perfwp $myinvocation.mycommand.name
		
		##
		## Get and index DLGs members, this facilitates proper TGS expansion later on
		##
		IF ($currentBasePrincipal.principalType -eq "DLG"){
			##
			## Get the DLG's direct "member"s and for each one derive a sidkey and
			## write to an index that point back to this DLG's sidkey.
			##
			## This allows us to find DLG relationships later which would be expensive to get from LDAP
			##
			##
			
			## Get currentDLG's direct "member"s
			##@#@#perfwp $myinvocation.mycommand.name
			$filterForPortableSecurityPrincipals = `
			"(|$(Get-PrincipalTypeLDAPFIlter 'UG')$(Get-PrincipalTypeLDAPFIlter 'GG')$(Get-PrincipalTypeLDAPFIlter 'USER'))"
			##@#@#perfwp $myinvocation.mycommand.name
			
			$currentDLGDirectMembers = @(
				##@#@#perfwp $myinvocation.mycommand.name
				invoke-sdspsearch `
					-computerName $currentBaseScope.preferredGC `
					-baseDN $currentBasePrincipal.distinguishedName `
					-scope Base `
					-filter $filterForPortableSecurityPrincipals `
					-attributes objectsid `
					-controls "P","A","DS" `
					-pagesize 400 `
					-asqattribute "member" `
					-Warnings $false `
					-connectionKeeping $true `
					-timeout $LDAPTimeoutLow `
					-rethrow
				##@#@#perfwp $myinvocation.mycommand.name -d
			)
			
			$filterForPortableSecurityPrincipals = $null
			
			IF ($currentDLGDirectMembers.count -gt 0){
				Foreach($directMemberLDAPObject in $currentDLGDirectMembers){
					##generate sid key for member object
					##@#@#perfwp $myinvocation.mycommand.name
					$tempMemberSIDKey = New-SIDKey -sidBytes $directMemberLDAPObject.attributes.objectsid.getvalues([byte[]])[0]
					##@#@#perfwp $myinvocation.mycommand.name -d
					##If the TGSExpansionRAMCache has not been exceeded, add or merge into the RAM cache which has the "member" sidkey as a key (to facilitate later tgs expansion), and had the base principal as a pointer
					IF(-not $script:masterresults.Telemetry.TGSExpansionRAMCacheRowsUsed -le $script:masterresults.Telemetry.TGSExpansionRAMCacheRowsAllowed){
						## we know the cache is still good, so now we need to either add new or merge. The following line does either
						$script:TGSExpansionRAMCache.$tempMemberSIDKey += @( $currentBasePrincipal.sIDKey )
						## incremet the cache utilization counter so we know when to start going to disk
						$script:masterResults.Telemetry.TGSExpansionRAMCacheRowsUsed++
					}
					ELSE{
						## the RAM cache has been exceeded, so go to disk cache
						##generate a trie2 path for the member object
						##@#@#perfwp $myinvocation.mycommand.name
						$tempMemberTGSExpansionTriePath = New-Trie2PathString -rootPath (join-path $cacheRootPath "TGSExpansion") -keyName $tempMemberSIDKey -prefixtokenLengths 2,2 -prefixtokenstartingoffset 48
						##@#@#perfwp $myinvocation.mycommand.name -d
						
						##
						## Inside of the sidkey named directory (corresponds to the current portable principal which is 
						## found in the member attribute of the current base DLG), we will see if the current
						## base DLG is already refernced by sidkey. If it is, do nothing and move on. If it is not
						## Then create a reference and move on.
						##
					
						IF (Test-Path (Join-Path $tempMemberTGSExpansionTriePath $($currentbasePrincipal.sidkey))){
							##reference already exists, move on
						}
						ELSE{
							[void]$(New-Item -ItemType Directory -Name $currentBasePrincipal.sidKey -Path $tempMemberTGSExpansionTriePath)
						}
					}
	
					$tempMemberSIDKey=$null
					$tempMemberTGSExpansionTriePath = $null
				}
			}
			$currentDLGDirectMembers = $null
		}
		
		##
		## Add FSPs to TGS expansion lookup index
		##
		IF ($script:currentBasePrincipalType -eq "FSP"){
			## we only care about FSPs with some kind of member of, otherwise it is a dead FSP and not worth matching
			IF ($currentBasePrincipal.effectiveMemberOfTable.count -gt 0){
	
				##
				## In this case the value is the same as the key, as we are telling the TGS expansion
				## logic "yes, there is an interesting match here, just go look up the sid directly
				## in the effective member of cache"
				##
				## TODO: these paths are getting really long, is this okay?
				## create TGSExpansion version of trie2 path for current principal
				$tempTGSExpansionVersionBasePrincipalTrie2Path = $(
					##@#@#perfwp $myinvocation.mycommand.name
					New-Trie2PathString `
						-rootPath $(Join-Path $cacherootpath "TGSExpansion")`
						-keyName $currentBasePrincipal.SIDKey `
						-prefixTokenLengths 2,2 `
						-prefixTokenStartingOffset 48
					##@#@#perfwp $myinvocation.mycommand.name -d
				)
				
				##@#@#perfwp $myinvocation.mycommand.name
				Ensure-Trie2Path -Trie2Path $tempTGSExpansionVersionBasePrincipalTrie2Path -extraChildPath $currentBasePrincipal.SIDKey -itemType "Directory"
				##@#@#perfwp $myinvocation.mycommand.name -d
			}
		}
	
		##
		##build expansion factor index for groups
		##
		
		$currentBasePrincipal.ExpansionFactor = $currentBasePrincipal.effectiveMemberOfTable.count
	
		##@#@#perfwp $myinvocation.mycommand.name
		Write-Output $currentBasePrincipal
		##@#@#perfwp $myinvocation.mycommand.name -d
		
		$currentbasePrincipal = $null
		
		##@#@#perfwp $myinvocation.invocationname
	}WHILE($false)
}


################################

FIlter Invoke-ExtraBasePrincipalProcessingForUsers{

#################################

	trap{
		## skip current principal for whatever reason
		Write-Host "s" -NoNewline
		$script:masterResults.Telemetry.SkippedPrincipalCount++
		
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"Invoke-ExtraBasePrincipalProcessingForUsers__TrapA", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $ErrorRecord -ErrorAction SilentlyContinue
		$Error.Insert(0,$errorRecord)

	
		IF( $script:masterResults.Telemetry.SkippedPrincipalCount -ge $script:masterResults.Telemetry.AbortThresholdSkippedPrincipals ){
			Write-Host "The number of users or groups that have been skipped"
			Write-Host "due to data gathering errors has exceeded the allowed"
			Write-Host "limit (configured as -AbortThresholdSkippedPrincipals)"
			Write-Host "Exiting"
			Write-Error "AbortThresholdSkippedPrincipals exceeded"
			throw $errorRecord
		}
		ELSE{
			Continue
		}
	}
	
	DO{
	
		##@#@#perfwp $myinvocation.invocationname -d
	
		$currentBasePrincipal = $_
		
		#############
		#Generate per user TGT level proto ticket and token stats
		foreach ($effectiveMemberOfEntry IN $currentBasePrincipal.effectiveMemberOfTable.Values){
			SWITCH( $effectiveMemberOfEntry ){
				#condition to find 8 byte TGT sids
				{ 
					($_.principalType -like "GG" -and $_.isSIDHistory -eq $false) -or `
					($_.principalType -like "UG" -and $_.DNSDomainName -like $currentBasePrincipal.DNSDomainName -and $_.isSIDHistory -eq $false )
				}{
					$currentBasePrincipal.protoTicketTGT8ByteSIDs++
					break
				}
				#condition to skip FSPs and DLGs for now
				{ 
					($_.principalType -like "FSP") -or
					($_.principalType -like "DLG") -or
					($_.principalType -like "DLGS")
				}{
					break
				}
				#condition to find 40 byte TGT sids
				{ 
					( ($_.principalType -like "UG") -and ($_.DNDomainName -notlike $currentBasePrincipal.DNSDomainName) ) -or
					($_.isSIDHistory -eq $true) -or
					($_.principalType -like "USER")
				}{
					$currentBasePrincipal.protoTicketTGT40ByteSIDs++
					break
				}
				Default{
					Write-Host "Unexpected bdd69908-cdfa-4a73-ab39-b8d67dc97ade"
				}
			}
			
		}
		
		$currentBasePrincipal.protoTicketTGT8ByteSIDs+=$estimatedSpecialSIDsForTicket
		$currentBasePrincipal.protoTokenTGTSIDCount = $currentBasePrincipal.protoTicketTGT40ByteSIDs + $currentBasePrincipal.protoTicketTGT8ByteSIDs
		
		##
		## Generate per user per resource domain finished token and ticket sizes
		##
		Foreach ($resourcedomain3 IN $resourcedomains){
			##@#@#perfwp $myinvocation.mycommand.name -d
			$protoTicketTGSAdditional40ByteSIDsFromCurrentResourceDomain = [int]0
			$protoTokenDLGSTokenOnlySIDCount = [int]0
			
			foreach ($effectiveMemberOfEntry IN $($currentBasePrincipal.effectiveMemberOfTable.Values | Where-Object { $_.DNSDomainName -eq $resourcedomain3})){
				SWITCH( $effectiveMemberOfEntry.principalType ){
					"GG"{
						break
					}
					"UG"{
						break
					}
					"USER"{
						break
					}
					"DLG"{
						$protoTicketTGSAdditional40ByteSIDsFromCurrentResourceDomain++
						break
					}
					"DLGS"{
						$protoTokenDLGSTokenOnlySIDCount++
						break
					}
					"FSP"{
						$protoTicketTGSAdditional40ByteSIDsFromCurrentResourceDomain++
						break
					}
					Default
					{
						Write-Host "Unexpected 9963afee-07b8-444f-8ea9-4c505b6c46eb"
					}
					
				}
				#dbg off
					
			}
			
			$currentUserInCurrentResourceDomainTicketBytes = 0
			$currentUserInCurrentResourceDomainTicketBytes = & {
				Estimate-TicketSizeKB327825 -known8byteSIDs ($currentBasePrincipal.protoTicketTGT8ByteSIDs)`
											-known40ByteSIDs ($currentBasePrincipal.protoTicketTGT40ByteSIDs + $protoTicketTGSAdditional40ByteSIDsFromCurrentResourceDomain) `
											-delegation `
											-overhead 1140
											## Note that the KB327825 value for "overhead" is really a guessing game. I depends on some variable length things that are included
											##in differnt parts of the ticket, inside and outside of the PAC. KB327825 mentions lenght of domain name, which goes into the ticket,
											##but now that the PAC specification is public we see that all kinds of surprising things like logon hours and other user properties go into this.
											##We could calculate a better overhead figure for each user, but that would require pulling down several additonal attributes per user which would make
											##execution slower and more expensive than it already is. As for the value of the extra accuracy, it would be nice to nail down that  factor
											##particularly considering the lenghts to which we go in other regards for the sake of accuracy. For now, however, this just is not worth it
											## because the few to few hundred bytes that it can sway may seem significant on the low end, but we don't care about users on the low end. We
											## care about users with big tickets from lots of groups, and for these users the variable amount of KB327825 overhead is proportionally far less significant.
											## Also, the extra byte are in a certain range of bytes and do not scale, so by skipping this we can still never be off by more than a certain amount.
											## By contrast if you miss expanding on a single sid somewhere else you have the potential to miss massive nesting. Therefore priority in terms of
											## cost versus accuracy has been given to all forms of group expansion and not to this category of overhead
			}
			
			$currentBasePrincipal.estimatedTicketBytesPerResourceDomain.add( $resourceDomain3 , $currentUserInCurrentResourceDomainTicketBytes )
			
			$currentUserInCurrentResourceDomainTokenSIDsCount = 0
			$currentUserInCurrentResourceDomainTokenSIDsCount = $(
				$currentBasePrincipal.protoTicketTGT8ByteSIDs + `
				$currentBasePrincipal.protoTicketTGT40ByteSIDs + `
				$protoTicketTGSAdditional40ByteSIDsFromCurrentResourceDomain + `
				$protoTokenDLGSTokenOnlySIDCount + `
				$estimatedSpecialSIDsForToken
			)
		
			$currentBasePrincipal.estimatedTokenSIDCOuntPerResourceDomain.add( $resourceDomain3 , $currentUserInCurrentResourceDomainTokenSIDsCount )
			
			$script:masterResults.Telemetry.AuthPathsEvaluated++
			
			$protoTicketTGSAdditional40ByteSIDsFromCurrentResourceDomain =$null
			$currentUserInCurrentResourceDomainTicketBytes = $null
			$currentUserInCurrentResourceDomainTokenSIDsCount = $null
		} # end of per resource domain loop, user tracker is now mostly populated, including per domain structure.
		
		## get highest ticketSize and tokensize for this user
		$currentBasePrincipal.estimatedTicketBytesPerResourceDomain.getEnumerator() | `
		Sort-Object Value -Descending | `
		Select-Object -First 1 | `
		ForEach-Object { 
			$currentBasePrincipal.highestTicketBytesAnyResourceDomain = [int] $_.Value
			$currentBasePrincipal.biggestTicketAndTokenResourceDomain = [string] $_.Key
			
		}
		
		$currentBasePrincipal.estimatedTokenSIDCountPerResourceDomain.getEnumerator() | `
		Sort-Object Value -Descending | `
		Select-Object -First 1 | `
		ForEach-Object { $currentBasePrincipal.highestTokenSIDCountAnyResourceDomain = [int] $_.Value  }		
	
		##@#@#perfwp $myinvocation.mycommand.name
		##tick rule counters for this user
		
		## token size rules
		Switch( $currentBasePrincipal.highestTokenSIDCountAnyResourceDomain ){
			{$_ -ge $script:masterResults.Thresholds.AccTkn_AbsoluteSIDLimit.FailThreshold}{
				$script:masterResults.Thresholds.AccTkn_AbsoluteSIDLimit.FailCount++ ;
				$currentBasePrincipal.AccTkn_AbsoluteSIDLimit = "Fail"
			}
			{($_ -ge $script:masterResults.Thresholds.AccTkn_AbsoluteSIDLimit.WarnThreshold) -and ($_ -lt $script:masterResults.Thresholds.AccTkn_AbsoluteSIDLimit.FailThreshold)}{
				$script:masterResults.Thresholds.AccTkn_AbsoluteSIDLimit.WarnCount++
				$currentBasePrincipal.AccTkn_AbsoluteSIDLimit = "Warn"
			}
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc44KB.FailThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc44KB.FailCount++ ; 
				$currentBasePrincipal.AccTkn_PoolAllocKB = 44;
				$currentBasePrincipal.AccTkn_PoolAllocGreaterThanDefault = "Fail"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc44KB.WarnThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc44KB.WarnCount++ ;
				$currentBasePrincipal.AccTkn_PoolAllocNextJumpWarning = "Warn";
			}		
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc40KB.FailThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc40KB.FailCount++ ; 
				$currentBasePrincipal.AccTkn_PoolAllocKB = 40;
				$currentBasePrincipal.AccTkn_PoolAllocGreaterThanDefault = "Fail"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc40KB.WarnThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc40KB.WarnCount++
				$currentBasePrincipal.AccTkn_PoolAllocNextJumpWarning = "Warn";
			}	
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc36KB.FailThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc36KB.FailCount++ ; 
				$currentBasePrincipal.AccTkn_PoolAllocKB = 36;
				$currentBasePrincipal.AccTkn_PoolAllocGreaterThanDefault = "Fail"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc36KB.WarnThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc36KB.WarnCount++
				$currentBasePrincipal.AccTkn_PoolAllocNextJumpWarning = "Warn";
			}			
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc32KB.FailThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc32KB.FailCount++ ; 
				$currentBasePrincipal.AccTkn_PoolAllocKB = 32;
				$currentBasePrincipal.AccTkn_PoolAllocGreaterThanDefault = "Fail"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc32KB.WarnThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc32KB.WarnCount++;
				$currentBasePrincipal.AccTkn_PoolAllocNextJumpWarning = "Warn";
			}	
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc28KB.FailThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc28KB.FailCount++ ; 
				$currentBasePrincipal.AccTkn_PoolAllocKB = 28;
				$currentBasePrincipal.AccTkn_PoolAllocGreaterThanDefault = "Fail"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc28KB.WarnThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc28KB.WarnCount++;
				$currentBasePrincipal.AccTkn_PoolAllocNextJumpWarning = "Warn";
			}			
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc24KB.FailThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc24KB.FailCount++ ; 
				$currentBasePrincipal.AccTkn_PoolAllocKB = 24;
				$currentBasePrincipal.AccTkn_PoolAllocGreaterThanDefault = "Fail"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc24KB.WarnThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc24KB.WarnCount++;
				$currentBasePrincipal.AccTkn_PoolAllocNextJumpWarning = "Warn";
			}			
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc20KB.FailThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc20KB.FailCount++ ; 
				$currentBasePrincipal.AccTkn_PoolAllocKB = 20;
				$currentBasePrincipal.AccTkn_PoolAllocGreaterThanDefault = "Fail"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc20KB.WarnThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc20KB.WarnCount++;
				$currentBasePrincipal.AccTkn_PoolAllocNextJumpWarning = "Warn";
			}			
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc16KB.FailThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc16KB.FailCount++ ; 
				$currentBasePrincipal.AccTkn_PoolAllocKB = 16;
				$currentBasePrincipal.AccTkn_PoolAllocGreaterThanDefault = "Fail"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc16KB.WarnThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc16KB.WarnCount++;
				$currentBasePrincipal.AccTkn_PoolAllocNextJumpWarning = "Warn";
			}	
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc12KB.FailThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc12KB.FailCount++ ; 
				$currentBasePrincipal.AccTkn_PoolAllocKB = 12;
				$currentBasePrincipal.AccTkn_PoolAllocGreaterThanDefault = "Warn"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc12KB.WarnThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc12KB.WarnCount++;
				$currentBasePrincipal.AccTkn_PoolAllocNextJumpWarning = "Warn";
			}			
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc08KB.FailThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc08KB.FailCount++ ; 
				$currentBasePrincipal.AccTkn_PoolAllocKB = 8;
				$currentBasePrincipal.AccTkn_PoolAllocGreaterThanDefault = "Warn"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.AccTkn_PoolAlloc08KB.WarnThreshold}{
				$script:masterResults.Thresholds.AccTkn_PoolAlloc08KB.WarnCount++
				$currentBasePrincipal.AccTkn_PoolAllocNextJumpWarning = "Warn";
			}	
		}	
		##@#@#perfwp $myinvocation.mycommand.name
		#ticket size rules	
		Switch( $currentBasePrincipal.highestTicketBytesAnyResourceDomain ){
			{$_ -ge $script:masterResults.Thresholds.KrbTkt_IIS5Default.FailThreshold}{
				$script:masterResults.Thresholds.KrbTkt_IIS5Default.FailCount++
				$currentBasePrincipal.KrbTkt_IIS5Default = "Fail"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.KrbTkt_IIS5Default.WarnThreshold}{
				$script:masterResults.Thresholds.KrbTkt_IIS5Default.WarnCount++
				$currentBasePrincipal.KrbTkt_IIS5Default = "Warn"
			}	
		}
		Switch( $currentBasePrincipal.highestTicketBytesAnyResourceDomain ){
			{$_ -ge $script:masterResults.Thresholds.KrbTkt_IIS67Default.FailThreshold}{
				$script:masterResults.Thresholds.KrbTkt_IIS67Default.FailCount++
				$currentBasePrincipal.KrbTkt_IIS67Default = "Fail"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.KrbTkt_IIS67Default.WarnThreshold}{
				$script:masterResults.Thresholds.KrbTkt_IIS67Default.WarnCount++
				$currentBasePrincipal.KrbTkt_IIS5Default = "Warn"
			}	
		}
		Switch( $currentBasePrincipal.highestTicketBytesAnyResourceDomain ){
			{$_ -ge $script:masterResults.Thresholds.KrbTkt_OSMaxTokenSizeDefault.FailThreshold}{
				$script:masterResults.Thresholds.KrbTkt_OSMaxTokenSizeDefault.FailCount++ 
				$currentBasePrincipal.KrbTkt_OSMaxTokenSizeDefault = "Fail"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.KrbTkt_OSMaxTokenSizeDefault.WarnThreshold}{
				$script:masterResults.Thresholds.KrbTkt_OSMaxTokenSizeDefault.WarnCount++
				$currentBasePrincipal.KrbTkt_OSMaxTokenSizeDefault = "Warn"
			}	
		}
		Switch( $currentBasePrincipal.highestTicketBytesAnyResourceDomain ){
			{$_ -ge $script:masterResults.Thresholds.KrbTkt_OSMaxTokenSizeMaxConfig.FailThreshold}{
				$script:masterResults.Thresholds.KrbTkt_OSMaxTokenSizeMaxConfig.FailCount++
				$currentBasePrincipal.KrbTkt_OSMaxTokenSizeMaxConfig = "Fail"
				break
			}
			{$_ -ge $script:masterResults.Thresholds.KrbTkt_OSMaxTokenSizeMaxConfig.WarnThreshold}{
				$script:masterResults.Thresholds.KrbTkt_OSMaxTokenSizeMaxConfig.WarnCount++
				$currentBasePrincipal.KrbTkt_OSMaxTokenSizeMaxConfig = "Warn"
			}	
		}
	#	Switch( $currentBasePrincipal.highestTicketBytesAnyResourceDomain ){
	#		{$_ -ge $script:masterResults.Thresholds.OSUDPSafeLimit.FailThreshold}{
	#			$script:masterResults.Thresholds.OSUDPSafeLimit.FailCount++
	#			$currentBasePrincipal.OSUDPSafeLimit = "Fail"
	#			break
	#		}
	#		{$_ -ge $script:masterResults.Thresholds.OSUDPSafeLimit.WarnThreshold}{
	#			$script:masterResults.Thresholds.OSUDPSafeLimit.WarnCount++
	#			$currentBasePrincipal.OSUDPSafeLimit = "Warn"
	#		}	
	#	}
		
		##@#@#perfwp $myinvocation.mycommand.name
		Write-Output $currentBasePrincipal
		##@#@#perfwp $myinvocation.mycommand.name -d
		
		$currentBasePrincipal=$null
		
		##@#@#perfwp $myinvocation.mycommand.name
	}WHILE($false)
}



####################################

Filter Write-BasePrincipalToDiskCacheGroupsOnly {

######################################

	trap{
		## skip current principal for whatever reason
		Write-Host "s" -NoNewline
		$script:masterResults.Telemetry.SkippedPrincipalCount++
		
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"Write-BasePrincipalToDiskCacheGroupsOnly__TrapA", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $ErrorRecord -ErrorAction SilentlyContinue
		$Error.Insert(0,$errorRecord)

	
		IF( $script:masterResults.Telemetry.SkippedPrincipalCount -ge $script:masterResults.Telemetry.AbortThresholdSkippedPrincipals ){
			Write-Host "The number of users or groups that have been skipped"
			Write-Host "due to data gathering errors has exceeded the allowed"
			Write-Host "limit (configured as -AbortThresholdSkippedPrincipals)"
			Write-Host "Exiting"
			Write-Error "AbortThresholdSkippedPrincipals exceeded"
			throw $errorRecord
		}
		ELSE{
			Continue
		}
	}
	
	DO{
		##@#@#perfwp $myinvocation.mycommand.name -d
		
		$currentBasePrincipal = $_
		
		$currentBasePrincipalSlimForSerialize = $currentBasePrincipal | Select-Object distinguishedName,ExpansionFactor,effectiveMemberOfTable
		
		##@#@#perfwp $myinvocation.mycommand.name
		## If groupsRAMCache has not hit its cap, store the croup there and increment counters,
		## otherwise, store on disk.
		IF( $script:masterresults.Telemetry.GroupsRAMCacheRowsUsed -lt $script:masterresults.Telemetry.GroupsRAMCacheRowsAllowed){
			##cache is still okay, record the group's effective member of table here
			$script:GroupsRAMCache.add( $currentBasePrincipal.sIDKey , $currentBasePrincipalSlimForSerialize )
			$script:masterresults.Telemetry.GroupsRAMCacheRowsUsed += $currentBasePrincipalSlimForSerialize.effectiveMemberOfTable.count
		}
		ELSE{
			$script:masterresults.Telemetry.GroupsDiskCacheRowsUsed += $currentBasePrincipalSlimForSerialize.effectiveMemberOfTable.count
			ensure-trie2path $currentBasePrincipal.sidkeytrie2path
			##new mechanism, serialize effective member of
			Export-CliXML -InputObject $currentBasePrincipalSlimForSerialize -Path (Join-Path $currentBasePrincipal.sidkeytrie2path "self2.xml") -Depth 100
		}
		
		##create expansion factor index on disk
		##for each expansionfactor, there is a text file containing the SID Keys of the groups with that expansion factor.
		##Here we append the current group sid key to the appropriate file
		##TODO: see about integrating this with the groupsramcache behavior for perf boost
		##@#@#perfwp $myinvocation.mycommand.name
		##TODO: THis follow append operation is slow.
		$currentBasePrincipal.sIDKey >> "$cacheRootPath\ExpansionFactor\$($currentBasePrincipal.expansionFactor)"
		##@#@#perfwp $myinvocation.mycommand.name
	
		$script:masterResults.Telemetry.GroupsEvaluated++
	
		$currentbaseprincipal.distinguishedName = $null
		$currentBasePrincipal.ldapObject = $null
		$currentBasePrincipal = $null
		
		##@#@#perfwp $myinvocation.mycommand.name
	}WHILE($false)
}

 

############################

Filter Write-BasePrincipalToDiskCacheUsersOnly{

###########################

	trap{
		## skip current principal for whatever reason
		Write-Host "s" -NoNewline
		$script:masterResults.Telemetry.SkippedPrincipalCount++
		
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"Write-BasePrincipalToDiskCacheUsersOnly__TrapA", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $ErrorRecord -ErrorAction SilentlyContinue
		$Error.Insert(0,$errorRecord)

	
		IF( $script:masterResults.Telemetry.SkippedPrincipalCount -ge $script:masterResults.Telemetry.AbortThresholdSkippedPrincipals ){
			Write-Host "The number of users or groups that have been skipped"
			Write-Host "due to data gathering errors has exceeded the allowed"
			Write-Host "limit (configured as -AbortThresholdSkippedPrincipals)"
			Write-Host "Exiting"
			Write-Error "AbortThresholdSkippedPrincipals exceeded"
			throw $errorRecord
		}
		ELSE{
			Continue
		}
	}
	
	DO{
		##@#@#perfwp $myinvocation.mycommand.name -d
	
		$currentBasePrincipal = $_
		
		## Serialize and create indexes
		
		##@#@#perfwp $myinvocation.mycommand.name
		Ensure-Trie2Path $currentBasePrincipal.SIDKeyTrie2Path
		##@#@#perfwp $myinvocation.mycommand.name -d
			
		## create and populate ticket bytes index
		
		$currentBasePrincipal.sIDKey >> "$cacheRootPath\UserTicketBytesIndex\$($currentBasePrincipal.highestTicketBytesAnyResourceDomain)"
	
		## create and populate token sid count index
		
		$currentBasePrincipal.sIDKey >> "$cacheRootPath\UserTokenSIDCountIndex\$($currentBasePrincipal.highestTokenSIDCountAnyResourceDomain)"	
		
		##write self object for retrieval later
		#ensure-trie2path $currentBasePrincipal.sidkeytrie2path
		
		## write self object
	
		Export-CliXML `
		-InputObject $($currentBasePrincipal | 
			Select-Object DNSDomainName,SAMAccountName,DistinguishedName,KrbTkt_TicketBytes,AccTkn_SIDCount,AccTkn_PoolAllocKB,AccTkn_PoolAllocGreaterThanDefault,AccTkn_PoolAllocNextJumpWarning,AccTkn_AbsoluteSIDLimit,KrbTkt_IIS5Default,KrbTkt_IIS67Default,KrbTkt_OSMaxTokenSizeDefault,KrbTkt_OSMaxTokenSizeMaxConfig,LargestTokenResourceDomain `
		) `
		-Path $(Join-Path $currentBasePrincipal.sidkeytrie2path "self2.xml")`
		-Depth 100
		
		## option to record each users stats to a csv file. This is meant to be used if a user wants to see all the other user stats
		## instead of the top n users as the tool reports on typically. Another alternative to this need to to increate the "topn" cutoff.
		## In some cases there may be so many users that a tool (such as rapidclient.exe) would not want to consume all users stats. For such
		## situations this option exists to log all user stats to a CSV that an administrator can deal with as they see fit.
		
		IF($createAllUsersCSV){
			"$($currentBasePrincipal.DistinguishedName)`t$($currentBasePrincipal.KrbTkt_TicketBytes)`t$($currentBasePrincipal.AccTkn_SIDCount)`t$($currentBasePrincipal.AccTkn_PoolAllocKB)`t$($currentBasePrincipal.AccTkn_PoolAllocGreaterThanDefault)`t$($currentBasePrincipal.AccTkn_PoolAllocNextJumpWarning)`t$($currentBasePrincipal.AccTkn_AbsoluteSIDLimit)`t$($currentBasePrincipal.KrbTkt_IIS5Default)`t$($currentBasePrincipal.KrbTkt_IIS67Default)`t$($currentBasePrincipal.KrbTkt_OSMaxTokenSizeDefault)`t$($currentBasePrincipal.KrbTkt_OSMaxTokenSizeMaxConfig)`t$($currentBasePrincipal.LargestTokenResourceDomain)" >> (join-path $csvoutputfolder AllUsersCSV.csv)
		}
		
		## option to save user effectiveMemberOfTable, expensive for disk IO and disabled by default
		IF($saveUserMemberOfTable){
			Export-CliXML -Path (Join-Path $currentBasePrincipal.SIDKeyTrie2Path "effectiveMemberOf.xml") -InputObject $currentBasePrincipal.EffectiveMemberOfTable -Depth 100
		}
		
		$script:masterResults.Telemetry.UsersEvaluated++
		
		##@#@#perfwp $myinvocation.mycommand.name
	}WHILE($false)
}


#############################

Function Format-SIDByteArrayAsDistinguishedName {

##############################

	## Takes a SID byte array (from S.DS.P) and formats it as a bind-able DN
	## such as <SID=\12\23\56...etc> which can, in turn, be used to look up information about the principal
	param(
		$sidByteArray
	)
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	"<SID=$(Format-ByteArrayAsHexString -byteArray $sidByteArray)>"

	$sIDByteArray=$null
	
	##@#@#perfwp $myinvocation.mycommand.name
}

###############################

Function Invoke-StatisticsPostProcessingForGroups{ 

##############################

	trap {
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"cbfaaf6e-4316-4863-be8f-b3d2adb6c1d5", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $ErrorRecord -ErrorAction SilentlyContinue
		$Error.Insert(0,$errorRecord)
		throw $_
	}
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	Write-Host "### Performing post-processing of groups"
	
	Start-Sleep -Seconds 2
	
	$script:masterResults.ContributingGroups = @(
        ##@#@#perfwp $myinvocation.mycommand.name ;
		Get-TopNIndexPointers -path "$cacheRootPath\ExpansionFactor" |
		Get-DeSerializedSelfObjectsFromIndexPointers -path "$cacheRootPath\Groups" -mode "Groups" ;
        ##@#@#perfwp $myinvocation.mycommand.name -
	)
	
	#$TopNGroupExpansionCollection =$null
	
	##@#@#perfwp $myinvocation.mycommand.name
}


############################

Function Invoke-StatisticsPostProcessingForUsers{

##############################

	trap {
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"0642a1b4-2293-4b55-b8ca-16eac1cb1822", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $ErrorRecord -ErrorAction SilentlyContinue
		$Error.Insert(0,$errorRecord)
		throw $_
	}
	
	Write-Host "### Performing post processing for users"
    
  	##@#@#perfwp $myinvocation.mycommand.name -d
  
    $TopNUserTicketAndTokenCollection = @{}
   
	##
	## Get users with highest ticket and token sizes, remove duplicates, and add them to masterResults
	##
	$TopNUserTicketBytesCollection = @(
        ##@#@#perfwp $myinvocation.mycommand.name
		Get-TopNIndexPointers -path (join-path $cacheRootPath UserTicketBytesIndex) |
		Get-DeSerializedSelfObjectsFromIndexPointers -path (join-path $cacheRootPath Users)
        ##@#@#perfwp $myinvocation.mycommand.name -d
	)
	
	$TopNUserTokenSIDCountCollection = @(
        ##@#@#perfwp $myinvocation.mycommand.name
		Get-TopNIndexPointers -path (join-path $cacheRootPath UserTokenSIDCountIndex) |
		Get-DeSerializedSelfObjectsFromIndexPointers -path (join-path $cacheRootPath Users)
        ##@#@#perfwp $myinvocation.mycommand.name -d
	)
	
	##$script:masterResults.biggesttokenusers.add( "TopNUserTicketAndTokenCollection" , @{} )
    
	foreach ( $user IN ($TopNUserTicketBytesCollection + $TopNUserTokenSIDCountCollection)){
		IF (-not $TopNUserTicketAndTokenCollection.contains( $user.distinGuishedName )){
			$TopNUserTicketAndTokenCollection.add( $user.distinGuishedName , $user )
		}
	}
	
	$script:masterResults.biggesttokenusers += @( $TopNUserTicketAndTokenCollection.Values )
	## todo: sort this list and trim it back to the topn number. Otherwise the unpredictable number post merge seems confusing and wrong
	
	$TopNUserTicketAndTokenCollection = $null
	$TopNUserTicketBytesCollection = $null
	$TopNUserTokenSIDCountCollection = $null
	
	##@#@#perfwp $myinvocation.mycommand.name
}




######################

Function Get-PrincipalTypeLdapFilter {

######################
	param(
		$recievedPrincipalType = $script:currentBasePrincipalType
	)

	##@#@#perfwp $myinvocation.mycommand.name -d
	
	# Define group scope enum values
	$groupTypesNumerical = @{}
	$groupTypesNumerical.universalGroupScope = [int32]0x80000008
	$groupTypesNumerical.universalGroupScopeSystemCreated = $groupTypesNumerical.universalGroupScope -bor 1
	$groupTypesNumerical.globalGroupScope = [int32]0x80000002
	$groupTypesNumerical.globalGroupScopeSystemCreated = $groupTypesNumerical.globalGroupScope -bor 1
	$groupTypesNumerical.domainLocalGroupScope = [int32]0x80000004
	$groupTypesNumerical.domainLocalGroupScopeSystemCreated = $groupTypesNumerical.domainLocalGroupScope -bor 1
	
	$protofilter = $null
	
	SWITCH($recievedPrincipalType){
		"DLG" { $protoFilter = "(|(groupType=$($groupTypesNumerical.domainLocalGroupScope))(groupType=$($groupTypesNumerical.domainLocalGroupScopeSystemCreated)))" ; break }
		"FSP" { $protoFilter = "(objectCategory=ForeignSecurityPrincipal)" ; break }
		"UG" { $protoFilter = "(|(groupType=$($groupTypesNumerical.universalGroupScope))(groupType=$($groupTypesNumerical.universalGroupScopeSystemCreated)))" ; break }
		"GG" { $protoFilter = "(|(groupType=$($groupTypesNumerical.globalGroupScope))(groupType=$($groupTypesNumerical.globalGroupScopeSystemCreated)))" ; break }
		"USER" { $protoFilter = "(&(objectCategory=Person)(objectSID=*))" ; break }
		Default { 
			Write-Host "Unexpected code path 5ff4dd80-537f-4ecf-878a-b3edbe8feb8d"
			Throw "UNEXPECTED 5ff4dd80-537f-4ecf-878a-b3edbe8feb8d"
		}
	}
	
	IF ($protofilter){
	Write-Output $protoFilter
	}
	ELSE{
		Write-Host "Unexpected code path 7e7afb91-f4a0-40a5-a66a-544b977204c3"
		Throw "UNEXPECTED 7e7afb91-f4a0-40a5-a66a-544b977204c3"
	}
	
	#clean up
	$protoFilter = $null
	$groupTypesNumerical = $null
	$recievedPrincipalType = $null
	
	##@#@#perfwp $myinvocation.mycommand.name
}

#####################

Function Get-AndTriageDirectMemberOf {

######################

	param(
		$dynamicBaseDistinguishedName = {throw "dynamicBaseDistinguishedName REQUIRED"},
		$customFilter = "(groupType:1.2.840.113556.1.4.803:=2147483648)"
	)
	
	trap{
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"Get-AndTriageDirectMemberOf__TrapA", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $ErrorRecord -ErrorAction SilentlyContinue
		$Error.Insert( 0 , $errorRecord )
		throw $_
	}
	
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	#Write-Status 2 2 "Get First Level MemberOf for $dynamicBaseDistinguishedName" ##############
	
	## TODO: FUTURE: Can this be changed to just use $preferredForestGC
	## Need to evaluate all of the calling situations
	$tempCOmputerName = $(
		IF(($script:currentBasePrincipalType -eq "FSP") -or ($script:currentBasePrincipalType -eq "DLG")){ 
			Write-Output $currentBaseScope.preferredDC
		}
		ELSE{
			Write-Output $currentBaseScope.preferredGC
		}
	)
    ##@#@#perfwp $myinvocation.mycommand.name
	invoke-sdspsearch `
		-comp $tempComputerName `
		-base $dynamicBaseDistinguishedName `
		-controls "P","A","DS" `
		-pagesize 400 `
		-asq memberOf `
		-filter $customFilter `
		-attributes objectSID,objectclass,groupType `
		-Warnings $false `
		-connectionKeeping $true `
		-timeout $LDAPTimeoutLow `
		-rethrow | `
		Foreach-Object{
			##@#@#perfwp $myinvocation.mycommand.name -d ;
			$directMemberOfLDAPObject = $_
			## If the current memberOf item is already in the finished structure, ignore it
			IF ($currentBasePrincipal.effectiveMemberOfTable.containsKey( $directMemberOfLDAPObject.distinguishedName )){
			}
			## if it is already in the queue for further handling, ignore it
			ELSEIF ($currentBasePrincipal.pendingMemberOfQueueWritable.containsKey( $directMemberOfLDAPObject.distinguishedName )){
			}
			## the two remaining cases are that it is a new unseen group (add it to the chasing queue), or
			## it is a group that has been seen before and fully chased, in which case we'll merge it from cache
			ELSE{
				##@#@#perfwp $myinvocation.mycommand.name -d
				## for some reason this call to new-sidkey seems to take forever, since we only need a subset of that functinoality here, trying
				## to optimize with the below
				
				# old
				#$tempSIDKey = New-SIDKey -sidBytes $directMemberOfLDAPObject.attributes.objectsid.getvalues([Byte[]])[0] -DNSDomainName $null
	
				#new experiment
				$tempsidkey = $(
					IF( $directMemberOfLDAPObject.attributes.objectsid.getvalues([Byte[]])[0].length -eq 28){
					##TODO: FUTURE: It might be faster to store this big string in a var instead of redefining
					## it all the time.
					'{0:X2}{1:X2}{2:X2}{3:X2}{4:X2}{5:X2}{6:X2}{7:X2}{8:X2}{9:X2}{10:X2}{11:X2}{12:X2}{13:X2}{14:X2}{15:X2}{16:X2}{17:X2}{18:X2}{19:X2}{20:X2}{21:X2}{22:X2}{23:X2}{24:X2}{25:X2}{26:X2}{27:X2}' -f $directMemberOfLDAPObject.attributes.objectsid.getvalues([Byte[]])[0][0..27]
					}
					ELSE{
						##TODO: FUTURE: If the number of bytes was small, don't we need to pass in the
						##domin name for padding?
						New-SIDKey $directMemberOfLDAPObject.attributes.objectsid.getvalues([Byte[]])[0]
					}
				)
				##@#@#perfwp $myinvocation.mycommand.name
				
				IF ( Test-Caches -sIDKey $tempsidkey -mode "groups") {
					##@#@#perfwp $myinvocation.mycommand.name -d
					$script:masterResults.Telemetry.FullyExpandedCacheHits++
					##@#@#perfwp $myinvocation.mycommand.name
					$currentBasePrincipal.mergeEffectiveMemberOfFromCache( $tempsidkey , "groups" , $true )
					##@#@#perfwp $myinvocation.mycommand.name -d
				}
				## the group is totally new to us, add it to the queue
				ELSE {
					$memberOfEntry = New-EffectiveMemberOfEntry $directMemberOfLDAPObject
					$script:masterResults.Telemetry.FullyExpandedCacheMisses++
					$currentBasePrincipal.pendingMemberOfQueueWritable.add( $memberOfEntry.distinguishedName , $memberOfEntry )
					$memberOfEntry = $null
					##@#@#perfwp $myinvocation.mycommand.name
				}
				$tempsidkey=$null
				##@#@#perfwp $myinvocation.mycommand.name
			}
			#clean up
			$directMemberOfLDAPObject = $null
			$memberOfEntry = $null
		}
	
	#clean up
	$dynamicBaseDistinguishedName = $null
	$customFilter = $null
	$tempcomputername = $null
	
	##@#@#perfwp $myinvocation.mycommand.name
}

##################

Function New-EffectiveMemberOfEntry{

##################

	##
	## instantiates and returns a populated object used to describe a single memberOf entry within
	## an effective memberOf table
	##
	## takes as input an S.DS.P ldap result object representing a group
	##
	## TODO: describe sidhistory mode

	param(
		$ldapObject,
		[switch]$sIDHistoryMode,
		$sIDHistorySID
	)
	
	trap{
		$errorRecord = New-Object System.Management.Automation.ErrorRecord ( 
			$_.exception, 
			"New-EffectiveMemberOfEntry__TrapA", 
			"NotSpecified", 
			(Get-ScriptStack)
		)
		#Write-Error -ErrorRecord $ErrorRecord -ErrorAction SilentlyContinue
		$Error.Insert(0,$errorRecord)
		throw $_
	
	}
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	$protoEffectiveMemberOfEntry = New-Object psobject | Select-Object distinguishedName,sIDKey,principalType,DNSDomainName,isSidHistory
	$protoEffectiveMemberOfEntry.isSidHistory = $false
	
	##@#@#perfwp $myinvocation.mycommand.name
	
	IF ($sidHistoryMode){
        ##@#@#perfwp $myinvocation.mycommand.name -d
		$protoEffectiveMemberOfEntry.distinguishedName = Format-SIDByteArrayAsDistinguishedName -sIDByteArray $sIDHistorySID
		$protoEffectiveMemberOfEntry.isSIDHistory = $true
		$protoEffectiveMemberOfEntry.sIDKey = New-SIDKey $sIDHistorySID
        ##@#@#perfwp $myinvocation.mycommand.name
	}
	ELSE{
		##@#@#perfwp $myinvocation.mycommand.name -d
		$protoEffectiveMemberOfEntry.distinguishedName = $ldapObject.distinguishedName
		$tempByteArray = $ldapObject.attributes.objectsid.getvalues([byte[]])[0]
		##@#@#perfwp $myinvocation.mycommand.name
		$tempSIDKey = New-SIDKey $tempByteArray
		##@#@#perfwp $myinvocation.mycommand.name -d
		$protoEffectiveMemberOfEntry.sIDKey = $tempSIDKey
        ##@#@#perfwp $myinvocation.mycommand.name
	}
	
	##@#@#perfwp $myinvocation.mycommand.name
	
	##todo: the following is extremely slow, not sure why, trying some changes
	
	$protoEffectiveMemberOfEntry.principalType = $(
		##@#@#perfwp $myinvocation.mycommand.name
		$ldapObjectClasses = @($ldapobject.attributes.objectclass.getvalues([string]))
		IF ( $ldapObjectCLasses -contains "foreignSecurityPrincipal" ) {
			"FSP"
		}
		ELSEIF ($ldapObjectCLasses -contains "person" ) {
			"USER"
		}
		ELSEIF ($ldapObjectCLasses -contains "group" ) {
			##Now I have to distinguish between group types
			##@#@#perfwp $myinvocation.mycommand.name -d
			[int]$tempGroupType = ($ldapObject.attributes.grouptype.getvalues([string]))[0]
			SWITCH( $tempGroupType ){
				{$_ -band 0x00000002 }{
					"GG" ; break
				}
				{$_ -band 0x00000004 }{
					IF( $_ -band 0x1){
						"DLGS"
					}
					ELSE{
						"DLG"
					}
					break
				}			
				{$_ -band 0x00000008 }{
					"UG" ; break
				}
			}
			##@#@#perfwp $myinvocation.mycommand.name
		}
		ELSE{
			Write-Host "Unexpected code path d3761614-a783-4fd8-8c3f-d1e342abdecb"
			Throw "Unexpected code path d3761614-a783-4fd8-8c3f-d1e342abdecb"
		}
		##@#@#perfwp $myinvocation.mycommand.name
	)
	##@#@#perfwp $myinvocation.mycommand.name
	
	##TODO: when I am calling this for a base principal, I can just assign this to the "currentdomain"
	## when I am calling it for memberOf entries, however, how would I know what domain the group is in?
	## I think this is important because we use this later on in generating TGT/TGS distinctions.
	## I guess I could parse the DN, but that seems a bit barbaric.
	##using DN for now
	$protoEffectiveMemberOfEntry.DNSDomainName = Guess-DNSDomainNameFromDistinguishedName $ldapobject.distinguishedName

    ##@#@#perfwp $myinvocation.mycommand.name
	Write-Output $protoEffectiveMemberOfEntry
    ##@#@#perfwp $myinvocation.mycommand.name -d
    
	$protoEffectiveMemberOfEntry = $null
	
	##@#@#perfwp $myinvocation.mycommand.name
}

###################

Function New-SIDKey{

####################

	param(
		$sidBytes,
		$DNSDomainName = $currentBaseScope.DNSDomainName
	)
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	IF( $sidbytes.length -lt 28){
		$sidbytesoriginal = $sidbytes
		$paddingneeded = 28 - $sidbytes.length
		[Byte[]]$domainnamepaddingavailable = [Byte[]][Char[]]$DNSDomainName
		while( $domainnamepaddingavailable.length -lt $paddingneeded){
			$domainnamepaddingavailable+=0
		}
		[Byte[]]$sidbytes = $domainnamepaddingavailable[0..($paddingneeded - 1)]
		$sidbytes+=$sidbytesoriginal
		If( $sidbytes.length -ne 28 ){
			Throw "6011f001-8e25-48f5-bca4-9ec37ad8a635"
		}
	}
	
	IF( $sidbytes.length -gt 28){
		throw "f0f1e9d2-f191-4dff-aa2c-006b471b873b"
	}
	
	'{0:X2}{1:X2}{2:X2}{3:X2}{4:X2}{5:X2}{6:X2}{7:X2}{8:X2}{9:X2}{10:X2}{11:X2}{12:X2}{13:X2}{14:X2}{15:X2}{16:X2}{17:X2}{18:X2}{19:X2}{20:X2}{21:X2}{22:X2}{23:X2}{24:X2}{25:X2}{26:X2}{27:X2}' -f $sidbytes[0..27]
    ##@#@#perfwp $myinvocation.mycommand.name

}

###################

function Estimate-TicketSizeKB327825{

##################

	###
	### Calculate-KB327825
	###
	## Returns estimated bytes for "token"/PAC/session ticket per KB327825

	param(
		[int]$Known8ByteSIDs = 0,
		[int]$Known40ByteSIDs = 0,
		[int]$overhead = 1200,
		[switch]$delegation `
	)
	
	##@#@#perfwp $myinvocation.mycommand.name -d

	$formulastring = "($overhead + (($Known40ByteSIDs +1) * 40) + ($Known8ByteSIDs * 8))"
	[int]$result = 0
	$result = ($overhead + (($Known40ByteSIDs +1) * 40) + ($Known8ByteSIDs * 8))
	
	IF ($delegation){
		$result = $result * 2
	}
	
	##
	## Emit/return the result
	##
    ##@#@#perfwp $myinvocation.mycommand.name
	Write-Output $result
    ##@#@#perfwp $myinvocation.mycommand.name -d
#	$formulatString = $null
#	$result = $null
	
	##@#@#perfwp $myinvocation.mycommand.name
}

######################

function Triage-DomainList{

######################

	## input: a string array of dns domain names
	##
	## output: no direct output, adds triaged domain infor to $masterResults.Telemetry

	param(
		[String[]]$domainList,
		[switch]$account,
		[switch]$resource
	)
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	foreach( $DNSDomainName IN $domainList){
		IF( $script:masterResults.Telemetry.SkippedDomains.containsKey( $DNSDomainName )){
			continue
		}
		ELSEIF( $script:masterResults.Telemetry.TriagedDomains.containsKey( $DNSDomainName )){
			IF($account){
				$script:masterResults.Telemetry.TriagedDomains.$DNSDomainName.useAsAccountDomain = $true
			}
			IF($resource){
				$script:masterResults.Telemetry.TriagedDomains.$DNSDomainName.useAsResourceDomain = $true
			}
		}
		ELSE{
			## domain is new, if it seems suitable, create a domain object and add it to the table
			## else add it to the skipped list
			
			## try to find optimal GC/DC
			$protoPreferredGC = $null ;
			$protoPreferredGC = $(
                ##@#@#perfwp $myinvocation.mycommand.name ;
				
				##TODO: FUTURE: Note that if there is a single DC in a domain and it is unavailable
				## the call below to Get-DOmainNCName will fail with retrys and warnings
				## before the rest of this fails.
				Get-DCNameEx2 `
					-output "dNSHostName" `
					-domainNC (Get-DOmainNCName $DNSDomainName) `
					-minimumBehaviorVersion 2 `
					-GC `
					-scopeLevel 2 `
					-expensiveLatencySort `
					-excludeNonResponsive `
					-singleResultOnly
                ##@#@#perfwp $myinvocation.mycommand.name -d
			)
			IF($protoPreferredGC -ne $null){ 
				$protoCurrentDomain = New-Object psobject ;
				Add-Member -InputObject $protoCurrentDomain -MemberType NoteProperty -Name DNSDomainName -Value $DNSDomainName ;
                ##@#@#perfwp $myinvocation.mycommand.name ;
				Add-Member -InputObject $protoCurrentDomain -MemberType NoteProperty -Name DistinguishedName -Value (Get-DomainNCName $DNSDomainName) ;
                ##@#@#perfwp $myinvocation.mycommand.name -d ;
				Add-Member -InputObject $protoCurrentDomain -MemberType NoteProperty -Name preferredDC -Value $DNSDomainName ;
				Add-Member -InputObject $protoCurrentDomain -MemberType NoteProperty -Name preferredGC -Value "$($DNSDomainName):3268" ;
				Add-Member -InputObject $protoCurrentDomain -MemberType NoteProperty -Name useAsAccountDomain -Value $false ;
				Add-Member -InputObject $protoCurrentDomain -MemberType NoteProperty -Name useAsResourceDomain -Value $false ;
				$protocurrentdomain.preferredGC = "$($protoPreferredGC):3268"
				$protoCurrentDomain.preferredDC = $protoPreferredGC
				
				$script:masterResults.Telemetry.triagedDOmains.$DNSDomainName = $protoCurrentDomain
				
				IF($account){
					$script:masterResults.Telemetry.TriagedDomains.$DNSDomainName.useAsAccountDomain = $true
				}
				IF($resource){
					$script:masterResults.Telemetry.TriagedDomains.$DNSDomainName.useAsResourceDomain = $true
				}
				
				$protoCurrentDOmain = $null
			}
			ELSE{
				$script:masterResults.Telemetry.SkippedDomains.$DNSDomainName = 1
			}
		}
	}
	
	##@#@#perfwp $myinvocation.mycommand.name
}

#######################

filter Get-TopNIndexPointers{

#######################

	param(
		$path,
		$topN = $topNPrincipals
	)
	
	##TODO: Re-deseign this not to use throw. It is polluting $error and just feels bad.
	
	$TopNCollection = @()
	$numberToReadTHisTime = $topN
	
	trap {
		$Error.RemoveAt(0)
		continue
	}
	Get-ChildItem $path | `
		Sort-Object @{expression={$_.name -as [int]}} -descending | `
			Foreach-Object {
				$fileinfo = $_
				Get-Content $fileinfo.fullname -totalCount $numberToReadThisTime | `
					Foreach-Object { 
						$lineInFile = $_
						IF( $topncollection.count -lt $topn){
							$TopNCollection += $lineinfile
						}
						ELSE{
							throw "stop reading now"
						} 
					}
			}
	$topNCollection

}

#######################

filter Get-DeSerializedSelfObjectsFromIndexPointers{

#######################

	param(
		$path,
		$mode = "NotSet"
	)
	
	##TODO: what is up with the "path" parameter?
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	foreach($indexPointer IN $_){
	
		IF( ($mode -eq "Groups") -and ($script:groupsRAMCache.containsKey( $indexPointer)) ){
			$script:groupsRAMCache.$indexPointer
		}
		ELSE{
			$tempIndexPointerTrie2Path = $(
				##@#@#perfwp $myinvocation.mycommand.name ;
				New-Trie2PathString `
					-rootPath $path `
					-keyName $indexPointer `
					-prefixTokenLengths 2,2 `
					-prefixtokenStartingOffset 48 ;
				##@#@#perfwp $myinvocation.mycommand.name -d
			)
			Import-CliXML -Path (join-path $tempIndexPointerTrie2Path "self2.xml" )
			$tempIndexPointerTrie2Path = $null
		}
	}
	
	##@#@#perfwp $myinvocation.mycommand.name
}

######################

function Invoke-SpecialSyntheticFSPShortCut{

######################

	param(
		$specialFSP
	)
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	#Write-Status 1 1 "Creating syntheitc FSPs as needed"
	
	[byte[]]$specialFSPSIDBytes = $(
		SWITCH($specialFSP){
			"Everyone" { (1,1,0,0,0,0,0,1,0,0,0,0) }
			"AuthUsers" { (1,1,0,0,0,0,0,5,11,0,0,0) }	
		}
	)
	
	[string]$specialFSPSyntheticDN = $(
		SWITCH($specialFSP){
			"Everyone" { "CN=S-1-1-0,CN=ForeignSecurityPrincipals,$($currentBaseScope.distinguishedName)" }
			"AuthUsers" { "CN=S-1-1-0,CN=ForeignSecurityPrincipals,$($currentBaseScope.distinguishedName)" }
		}
	)
	
	$specialFSPprotoBasePrincipal = New-Object psobject
	Add-Member -inputObject $specialFSPprotoBasePrincipal -MemberType NoteProperty -Name distinguishedName -Value $specialFSPSyntheticDN
	Add-Member -inputObject $specialFSPprotoBasePrincipal -MemberType NoteProperty -Name sIDKey -Value $(New-SIDKey $specialFSPSIDBytes )
	Add-Member -inputObject $specialFSPprotoBasePrincipal -MemberType NoteProperty -Name effectiveMemberOfTable -Value @{}
	Add-Member -inputObject $specialFSPprotoBasePrincipal -MemberType NoteProperty -Name DNSDomainName -Value $currentBaseScope.DNSDomainName
	Add-Member -inputObject $specialFSPprotoBasePrincipal -MemberType NoteProperty -Name principalType -Value $script:currentBasePrincipalType
	Add-Member -inputObject $specialFSPprotoBasePrincipal -MemberType NoteProperty -Name ExpansionFactor -Value ([int]1)
	Add-Member -inputObject $specialFSPprotoBasePrincipal -MemberType NoteProperty -Name ldapObject -Value "SyntheticFSPDummy"
	Add-Member -inputObject $specialFSPprotoBasePrincipal -MemberType NoteProperty -Name SIDKeyTrie2Path -Value $(
        ##@#@#perfwp $myinvocation.mycommand.name ;
		New-Trie2PathString `
			-rootPath (Join-Path $cacheRootPath Groups) `
			-keyName $specialFSPprotoBasePrincipal.SIDKey `
			-prefixTokenLengths 2,2 `
			-prefixTokenStartingOffset 48 ;
        ##@#@#perfwp $myinvocation.mycommand.name -d
	)
	
	$specialFSPselfMemberOfEntry = $specialFSPprotoBasePrincipal | Select-Object distinguishedName,SIDKey,principalType,DNSDomainName
	Add-Member -inputObject $specialFSPselfMemberOfEntry -MemberType NoteProperty -Name isSIDHistory -Value $false
	
	$specialFSPprotoBasePrincipal.effectiveMemberOfTable.add( $specialFSPprotoBasePrincipal.distinguishedName , $specialFSPselfMemberOfEntry )
	
    ##@#@#perfwp $myinvocation.mycommand.name
	$specialFSPprotoBasePrincipal | Write-BasePrincipalToDiskCacheGroupsOnly
    ##@#@#perfwp $myinvocation.mycommand.name -d
	
	$specialFSPSIDBytes = $null
	$specialFSPSyntheticDN = $null
	$specialFSPprotoBasePrincipal = $null
	$specialFSPselfMemberOfEntry = $null
	##@#@#perfwp $myinvocation.mycommand.name
}


####################

Function Test-Caches{

###################
	param(
		$mode, ##should be "groups" or "TGSExpansion"
		$SIDKey,
		[switch]$RAMOnly
	)
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	## triage mode args
	Switch($mode){
		"GROUPS"{
			$tempCacheRootPath = (Join-Path $cacheRootPath "GROUPS")
			$tempRAMCache = $script:GroupsRAMCache -as [ref]
			break
		}
		"TGSExpansion"{
			$tempCacheRootPath = (Join-Path $cacheRootPath "TGSExpansion")
			$tempRAMCache = $script:TGSExpansionRAMCache -as [ref]
			break
		}
		Default{
			throw "Unexpected 55201c1d-c19b-41ec-859a-5166dc85d7b7"
		}
	}
	
	##@#@#perfwp $myinvocation.mycommand.name
	
	IF( $tempRAMCache.Value.containsKey( $SIDKey )){
		Write-Output $true
	}
	## the sidkey was not in the RAM cache. The remaining possibilities are that the RAM
	## cache has been exceeded and the sidkey should be tested for in the on disk cache,
	## of the RAM cache has not been exceeded, and therefore there is no match
	ELSEIF($RAMOnly){
		Write-Output $false
	}
	ELSEIF( $script:masterresults.Telemetry."$($mode)RAMCacheRowsUsed" -ge $script:masterresults.Telemetry."$($mode)RAMCacheRowsAllowed"   ){
		##@#@#perfwp $myinvocation.mycommand.name -d
		$tempSIDKeyTrie2Path = $(
			New-Trie2PathString `
			 -rootPath $tempCacheRootPath `
			 -keyName $SIDKey `
			 -prefixTokenLengths 2,2 `
			 -prefixTokenStartingOffset 48	;
		)
		#This will return true or false
		Test-Path $tempSIDKeyTrie2Path
		##@#@#perfwp $myinvocation.mycommand.name
	}
	ELSE{
		$false
	}	
	
	##@#@#perfwp $myinvocation.mycommand.name
}




###################

Function Get-TGSExpansionCacheContent{

###################
	param(
		$SIDKey
	)
	
	##@#@#perfwp $myinvocation.mycommand.name -d

	IF( $script:TGSExpansionRAMCache.containsKey( $SIDKey )){
        ##@#@#perfwp $myinvocation.mycommand.name
		Write-Output $script:TGSExpansionRAMCache.$SIDKey
        ##@#@#perfwp $myinvocation.mycommand.name -d
	}
	ELSEIF($script:masterresults.Telemetry.TGSExpansionRAMCacheRowsUsed -ge $script:masterresults.Telemetry.TGSExpansionRAMCacheRowsAllowed){
		$tempSIDKeyTrie2Path = $(
            ##@#@#perfwp $myinvocation.mycommand.name ;
			New-Trie2PathString `
			 -rootPath (join-path $cacherootPath "TGSExpansion")`
			 -keyName $SIDKey `
			 -prefixTokenLengths 2,2 `
			 -prefixTokenStartingOffset 48 ;
            ##@#@#perfwp $myinvocation.mycommand.name -d	
		)
		IF( Test-Path $tempSIDKeyTrie2Path){
			Get-ChildItem $tempSIDKeyTrie2Path | ForEach-Object { Write-Output $_.Name }
		}
		ELSE{
		}
	}
	ELSE{
	}
	
	##@#@#perfwp $myinvocation.mycommand.name
}


####################

Function Get-DeserializedBasePrincipal{

###################
	param(
		$sIDKey
	)
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	IF( $script:GroupsRAMCache.containsKey( $SIDKey )){
		$script:GroupsRAMCache.$SIDKey
		##@#@#perfwp $myinvocation.mycommand.name
	}
	ELSE{
		$tempSIDKeyTrie2Path = $(
			New-Trie2PathString `
			 -rootPath (join-path $cacherootPath "Groups")`
			 -keyName $SIDKey `
			 -prefixTokenLengths 2,2 `
			 -prefixTokenStartingOffset 48 ;
		)
		##@#@#perfwp $myinvocation.mycommand.name
		IF( Test-Path (join-path $tempSIDKeyTrie2Path "self2.xml" )){
			Import-Clixml -Path ( join-path $tempSIDKeyTrie2Path "self2.xml" )
		}
		ELSE{
			##do nothing
		}
		##@#@#perfwp $myinvocation.mycommand.name
	}
	
	##@#@#perfwp $myinvocation.mycommand.name
}



















#######################################  EXTERNAL      ##########
#######################################  FUNCTIONS     ##########
#######################################                ##########



############ The following functions are from Matt's libraries, but have been pasted here
############ to simplify deployment/testing (removes complications around moving multiple 
############ files and loading libraries). Please do not modify these functions here. Instead
############ modify the master library version and paste again (or go back to the library load model)
############


############################################################

function Write-DotEveryNTimes

############################################################
{
	param(
		$n = 5,
		[switch]$noPassThru
	)
	begin{
		[int]$script:printDotCounter = 0
	}
	process{
		IF( ($script:printDotCounter % $n) -eq 0 ){
			Write-Host -NoNewline "."
		}
		$script:printDotCounter++
		IF (-not $noPassThru){ $_ }
	}
	end{
		Write-Host ""
		Remove-Variable -Scope Script -Name printdotCounter
	}
}


############################################################

function Write-COuntEveryNTimes

############################################################
{
	param(
		$n = 50,
		[switch]$noPassThru
	)
	begin{
		[int]$script:printCountCounter = 0
	}
	process{
		IF( (($script:printCountCounter % $n) -eq 0) -and ($script:printCountCounter -ne 0) ){
			Write-Host $script:printCOuntCounter
		}
		$script:printCountCounter++
		IF (-not $noPassThru){ $_ }
	}
	end{
		Write-Host ""
		Remove-Variable -Scope Script -Name printCountCounter
	}
}




############################

filter Format-ByteArrayAsHexString

##########################
{
	param(
		## sets var to pipeline object if nothing is specified
		## TODO: The use of "$_" vs "$input" here varies depending on whether this is a funciton or a filter,
		## need to finalize that status
		$byteArray = @(throw "THROWID:f6e31507-8564-4241-b800-96c3ca358c19__THROWINTENT:FindandFixBrokenCallers__THROWOTHER:RequiredParamOnFormat-ByteArrayAsHexString") ,
		$escapeCharacter = ""
	)	
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	[string]$finalstring = ""
	foreach ($byte In $byteArray)
	{
		##TODO: This seems like a terrible way to do this, but it is
		# faster than any alternative that I have tried for input of
		# unknown length
		$finalString += ($escapeCharacter + "{0:X2}" -f $byte)
	}
	
    ##@#@#perfwp $myinvocation.mycommand.name
	Write-Output $finalString
    ##@#@#perfwp $myinvocation.mycommand.name -d
	
	#cleanup
	$byteArray = $null
	$escapeCharacter = $null
	$finalString = $null
	
	##@#@#perfwp $myinvocation.mycommand.name

}




####################################

Function write-status{

####################################
	param(
		$messageVerbosityLevel,
		$indentLevel = 0,
		$message
	)
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	## only do anything if the message verbosity level meets our desired verbosity level
	IF ($messageVerbositylevel -le $script:statusVerbosityLevel){
		## add intents/tabs to message, this is just a convenience feature so I don't have
		## to insert tabs in all my strings in the calling scripts
		for( $i = 0 ; $i -lt $indentLevel ; $i++ ){
			$message = "`t" + $message
		}
		## if we are using a special output mode (neither host nor file)
##		IF($script:RAPIDMonitorMode){
##			Write-RAPMonitor $message
##		}
		## finally, just write to host (most common usage)
#		ELSE{
			Write-Host $message
#		}
		## if $statusLogFile is specified, also write to file
		IF ($statusLogFile -ne $null){
			$message >> $statusLogFile
		}
	}
	
	#clean up
	$message = $null
	$indentLevel = $null
	$messageVerbosityLevel = $null
	
	##@#@#perfwp $myinvocation.mycommand.name
}






#######################################

function Invoke-SDSPSearch{

#######################################

##
## Description:	Ldap Searching via S.DS.P in .Net. Meant to provide a "one-liner" experience 
## 				for SDSP based AD search (similar to adfind of dsquery) in powershell.
##
## Returns:		S.DS.P SearchEntry Objects.
##
## Usage:		Invoke-SDSPSearch	<-computerName "ip address | dns host name | dns domain name">
##										Note: Defaults to $null which causes S.DS.P to auto-discover
##									<-baseDN "DN of Search Base"> 
##										Note: Defaults to NULL, good for rootDSE and GC searches
##									<-scope Base | OneLevel | SubTree>
##										Note:Defaults to Base
##									<-filter "(standard LDAP filter)">
##										Note: Defaults to "(objectClass=*)"
##									<-attributes "attribute1","attribute2","attr3">
##										Note: Must be a comma separated list of individually quoted attributes 
##										to return, it is possible to skip the quotes for attributes with no special 
##										characters (like "-") in their name. Do not put quotes around the list
##										as a whole
##									<-timeout nn>
##										Note: Optional ability to spcify the client side LDAP timeout in seconds.
##									<-ldapcontrols D,P,DS,A>
##										For adding LDAP controls. Must be comma separated non-quoted or individually quoted
##										characters, do not put quotes around the whole thing if specifying multiple arguments
##										Defaults to none specified
##										"P" = Paging.
##										"D" = Return Deleted Objects
##										"DS"= DOmain Scope control
##										"A" = ASQ control. Use this in conjunction with -ASQAttribute
##									<-connectionKeeping>
##										Note: Useful for returning to a specific DC/connection repeatedly. For example
##										If you are going to do 20000 base searches on individual objects, it is useful
##										to have those all use the same  LDAP connection to avoid problems like
##										TCP port exhaustion and wasting time on repetetive BINDs. The first time that you call Invoke-SDSPSearch 
##										with this option enabled, the connection created to "-computerName" will not be disposed
##										after the search, and will be saved in the script scope. Subsequent calls to invoke-sdspsearch
##										with this option set will re-use the existing connection.
##										To easily dispose of these connections when done using them, use the
##										Dispose-sDSPSearchNamedConnection function also implemented in this library.
##									<-referralChasing "All" | "None">
##										Turns referral chasing on or off on the LDAP connection. Note (particularly if reusing named connections)
##										That this is a per connection setting.
##										Defaults to $null in the script, which invokes the sdsp default of "All." Only specify this option
##										if you want to modify the properties of the connection.
##									<-retry n>
##										Specifies how many times a search/send request should be retried when certain error conditions
##										are encountered. Defaults to 1.
##
##
##
## Sample Usage:
##			1.	Invoke-SDSPSearch
##				Result: Use of all default settings returns rootDSE from an auto-selected DC
##
##			2.	invoke-sdspSearch -computername "contoso.com" -baseDN "DC=Contoso,DC=Com" -filter "(objectclass=domainDNS)" -scope Base -attributes minpwdlength,objectclass
##				Result: Returns two attributes from domain head object corresponding to DC=Contoso,DC=Com
##
##				Also note that for interactive use in powershell.exe the param names can be shortened (just need enough to be unique), yielding:
##			3.	invoke-sdspSearch -comp "domain.com" -b "DC=Contoso,DC=Com" -f "(objectclass=domainDNS)" -s Base -a minpwdlength,objectclass
##				Result: Same as above
##
##			4.	Invoke-SDSPSearch -c "contoso.com:3268" -s SubTree -f "(objectCategory=Person)" -a distinguishedname -ldapcontrols D,P
##				Result: Auto-selects a GC for contoso.com, uses a null search base with subtree scope, which (when used against
##				GC port) results in a search of the entire GC, regardless of tree structure. Uses paging and show deleted objects
##				LDAP controls
##	
	param(
		$computerName = $null,
		$baseDN = $null,
		$filter = "(objectClass=*)",
		$Scope = "Base",
		[string[]]$attributes = "*",
		[string[]]$controls = "",
		[int]$pageSize = 1000,
		[string]$aSQAttribute,
		[int32]$timeout = 20,
		$referralChasing = "None",
		[bool]$connectionKeeping = $false,
		[bool]$Warnings = $true,
		[int]$retry = 1,
		[int]$retrySleepSeconds = 1,
		$exceptionToReThrow = $null,
		[switch]$reThrow,
		$eA = "Continue"
	)		
	
	##@#@#perfwp $myinvocation.mycommand.name -d

	$local:errorActionPreference = $eA
	
	##TODO: add test for S.DS.P loaded status.
	
	##
	## If the user specified connection retaining, sort that out
	## TODO: also creating the connection goes off box immediately, so 
	## we may need some trapping here.
	##
	IF ($connectionKeeping){
		## check if the collection of ldap connections doesn't already exist, create it
		IF (-not ( test-path variable:global:sDSPSearchNamedConnections) ){
			$global:sDSPSearchNamedConnections = @{}
		}
		## if a connection with the name in -computername  doesn't already exist, create it
		## Note additional key material from $timeout now used as well. This is to keep connections separate
		## which use different timeout values due to complications with trying to reset timeouts later.
		IF (-not $global:sDSPSearchNamedConnections.containsKey( "$($computerName)|t$($timeout)" ) ){
			$newconn = New-Object system.directoryservices.protocols.LdapConnection("$computername")	
			$global:sDSPSearchNamedConnections.add( "$($computerName)|t$($timeout)" , $newconn )
		}
		#create a refererence to this so that the rest of the code can be as uniform as possible
		$currentSDSPConnectionRef = $global:sDSPSearchNamedConnections["$($computerName)|t$($timeout)"] -as [ref]
	}
	ELSE{
		## If no special connection name has been specified, then we dont care about any of the above (this will
		## be the most common case). Just create a connection and go!	
		$newLocalSDSPConnection = New-Object system.directoryservices.protocols.LdapConnection("$computername")
		#create a refererence to this so that the rest of the code can be as uniform as possible
		$currentSDSPConnectionRef = $newLocalSDSPConnection -as [ref]
	}
	
	##
	## Set connection options
	##
	
	## Assign the timeout value
	$currentSDSPConnectionRef.Value.timeout = [timespan]::FromSeconds($timeout)
	
	##Assign the referralchasing value
	$currentSDSPConnectionRef.Value.SessionOptions.ReferralChasing = $referralChasing
	
	## TODO: TEMP: Turning on TCP keep alive on all connections for troubleshooting, later need to consider selective use
	## of this option.
	$currentSDSPConnectionRef.Value.SessionOptions.TcpKeepAlive = $true

	
	##
	## Build up a searchrequest to send
	##
	
	$searchRequest = new-object directoryservices.protocols.SearchRequest("$baseDN", "$filter", "$scope", $attributes)
	
	## Adding Controls
	Switch($controls){
		"D"{
				$showDeletedControl = new-object system.directoryservices.protocols.ShowDeletedControl
				[int]$showDeletedControlIndex = $searchRequest.controls.add($showDeletedControl)
				continue
		}
		"P"{
				$pageControl =  new-object system.directoryservices.protocols.PageResultRequestControl($pageSize); 
				[int]$pageControlIndex = $searchRequest.controls.add($pageControl)
				continue
		}
		"DS"{
				$domainScopeControl = new-object system.directoryservices.protocols.DomainScopeControl
				[int]$domainScopeControlIndex = $searchRequest.controls.add($domainScopeControl)
				continue
		}
		"A"{
				$aSQControl = New-Object system.directoryservices.protocols.AsqRequestControl
				$aSQControl.AttributeName = $aSQAttribute
				[int]$aSQControlIndex = $searchRequest.controls.add($aSQControl)
				continue
		}
	}
    
    ##@#@#perfwp $myinvocation.mycommand.name
	
	##
	## Send the search
	## This is in a while loop in order to handle paging and retries
	## Some internal error handling exists within the while loop,
	## Which escalates to throwing exceptions to the calling scope where
	## the internal error handling cannot recover.
	##
	
	##
	## Set initial pre-loop flags which control loop behavior
	##
	[bool]$firstPage = $True
	[bool]$morePagesPending = $False
	[int]$currentRetryCount = 0
	[bool]$retryFlag = $False
	[bool]$errorFlag = $false
	
	while ( ($firstPage -eq $True) -or ($morePagesPending -eq $True ) -or ($retryFlag -eq $True) ){
		##
		## reset all the flags that keep the while loop alive
		## this reduces the chance of an infinite loop in some unexpected condition.
		## We will only continue to loop if we execute code below that sets one of these to continue looping
		##	
		IF ($retryFlag -eq $true){
			Start-Sleep -Seconds $retrySleepSeconds
		}
		$firstPage = $False
		$retryFlag= $False
		$morePagesPending = $False
		$exception = $null
	
		##
		## Send the search!
		##
		##creating a child scope in order to limit the scope of the trap. If I don't do this then exeptions later in 
		# a pipeline wind up coming all the way back here.
		# in v2 try catch shoudl be a better solution
		&{ 
			##try
			Set-Variable -Name resultA -Scope 1 -Value ($currentSDSPConnectionRef.Value.sendrequest($searchRequest))
			
			##catch
			trap {
				##
				## Dig the right exception out of $_
				## Save the result in $exception to be further parsed.
				## In certian cases bail our right here.
				##
				## We have to do all of this because the meaningful exception may be nested in other structures
				##
				SWITCH ($_){
					{$_ -is [system.directoryservices.protocols.ldapexception]}{
						$exception = $_
						break
					}
					{$_.exception -is [system.directoryservices.protocols.ldapexception]}{
						$exception = $_.exception
						break
					}
					{($_.exception.GetBaseException()) -is [system.directoryservices.protocols.ldapexception]}{
						$exception = $_.exception.GetBaseException()
						break
					}
					{($_.exception.GetBaseException()) -is [system.directoryservices.protocols.directoryoperationexception]}{
						$exception = $_.exception.GetBaseException()
						Set-Variable -Name errorFlag -SCope 2 -Value $True
						break
					}					
					Default {
						Write-Warning "An LDAPException could not be found in the current exception"
						Set-Variable -Name errorFlag -SCope 2 -Value $True
						throw $_
						break
					}
				}
				
				## For ldapexceptions found above, take action based on error code
				IF ($exception -is [system.directoryservices.protocols.ldapexception]){
					SWITCH ($exception.ErrorCode){
						{($_ -eq 81) -or ($_ -eq 52) -or ($_ -eq 85)} { ##these are error codes I am willing to retry on
							IF ($currentRetryCount -lt $retry){
								If ($Warnings) {
									$WarningString = "Failure: $($exception.message): WILL RETRY"
									Write-Warning $WarningString
								}
								Set-Variable -Name retryFlag -SCope 2 -Value $True
								Set-Variable -Name errorFlag -SCope 2 -Value $True
								Set-Variable -Name currentRetryCount -Scope 2 -Value ($currentretrycount + 1)
							}
							ELSE {
								If ($Warnings) {
									$WarningString = "Failure: $($exception.message): WILL NOT RETRY (based on `"-retry`" count)"
									Write-Warning $WarningString
								}
								Set-Variable -Name errorFlag -Scope 2 -Value $True
								Set-Variable -Name exceptionToReThrow -Scope 2 -Value $exception
							}
							break
						}
						{($_ -eq 87) -or ($_ -eq 49)} { ##these are error codes I am not willing to retry on
							If ($Warnings) {
								$WarningString = "Failure: $($exception.message): Not Retrying (based on error code)"
								Write-Warning $WarningString
							}
							Set-Variable -Name errorFlag -Scope 2 -Value $True
							Set-Variable -Name exceptionToReThrow -Scope 2 -Value $exception
							break
						}
						Default {
							IF ($Warnings) {Write-Warning "LdapException with unexpected error code"}
							Set-Variable -Name errorFlag -Scope 2 -Value $True
							Set-Variable -Name exceptionToReThrow -Scope 2 -Value $exception
							break
						}
					}
				}
				
				## For directoryoperationexceptions found above, take action
				
				## Currently we just Warn about the exception, and then if there are any results
				## (possibly partial) we go ahead and assign them to the original output variable
				## so that the later checks and emitting can work.
		
				IF ($exception -is [system.directoryservices.protocols.directoryoperationexception]){
					If ($Warnings) {
						$WarningString = "$($exception.response.resultcode)"
						Write-Warning $WarningString
					}
					Set-Variable -Name retryFlag -Scope 2 -Value $False
					Set-Variable -Name exceptionToReThrow -Scope 2 -Value $exception
					
					## set objects which will determine if partial results will be emitted
					IF ($exception.response.entries.count -gt 0){
						Set-Variable -Name errorFlag -Scope 2 -Value $True
						Set-Variable -Name resultA -Scope 2 -Value $exception.response
					}
					ELSE {
						Set-Variable -Name errorFlag -Scope 2 -Value $True
					}
				}
				
				continue
			}
		}
		##
		## Soft error / Warning handling. This is stuff that we want to evaluate even if there was no exception
		## we skip all of this if $errorFlag is set
		##
		IF (($Warnings -eq $true) -and ($errorFlag -eq $false)){
			## look for and Warn on value ranging
			foreach ( $entry in $resultA.entries ){
				IF ( ($entry.attributes.AttributeNames.getEnumerator() -like "*;range=*") -as [bool] ){
					Write-Warning "Value ranging detected on result."
					Write-Warning "In this version of Invoke-SDSPSearch it is up to the caller to request the next range of attribute values on a subsequent call"
				}
			}
			## look for empty result set
			IF ($resultA.entries.count -lt 1){
				Write-Warning "No objects were returned"
			}
			## look for and Warn on unexpected result types
			IF (($resultA -eq $null) -or ($resultA.gettype().fullname -ne "System.DirectoryServices.Protocols.SearchResponse")){
					Write-Warning "Unexpected Result Type"
					$errorFlag = $True
			}
		}
	
		##
		## Emit current page of results and prepare next page request or exit
		##
		IF ($errorFlag -eq $false){
			# EMIT!
			foreach ($entry IN $resultA.entries){
				##@#@#perfwp $myinvocation.mycommand.name
				Write-Output $entry
				##@#@#perfwp $myinvocation.mycommand.name -d
				$entry = $null
			}
		}
		
		##
		## Paging
		## If paging was requested originally, find out if any more pages exist and set up
		##	
		## find out if there is a page control on the result
		IF ( ($errorFlag -eq $false) -and ($controls -eq "P")){
			####code review cursor
			IF ( $pageControlResult = $resultA.controls | Where-Object { $_.Type -eq "1.2.840.113556.1.4.319" } ){
				IF ($pageControlResult.Cookie.Length -ge 1){
					$searchrequest.controls[$pageControlIndex].cookie = $pageControlResult.cookie
					$morePagesPending = $True
				}
				ELSE{
					$morePagesPending = $False
				}
			}
			ELSE{
				Write-Warning "Page control was expected on response, but not found"
			}
		}
		ELSE{
			$morePagesPending = $False
		}
		$resultA = $null

				
	} ## end of while loop
	
	##clean up
	##
	## Set initial pre-loop flags which control loop behavior
	##
	$resultA = $null
	#$firstPage = $null
	#$morePagesPending = $null
	$currentRetryCount = $null
	#$retryFlag = $null
	#$errorFlag = $null
	
	
	
	IF (-not $connectionKeeping){
		$currentSDSPConnectionRef.Value.dispose()
		$currentSDSPConnectionRef = $null
		Remove-Variable currentSDSPConnectionRef
	}
	
	IF (( $exceptionToReThrow -ne $null) -and ($reThrow -eq $True)) {
		throw $exceptionToReThrow
	}
	
	##@#@#perfwp $myinvocation.mycommand.name
}




#########################################

Function Dispose-sDSPSearchKeptConnections{

##########################################
	param(
		[string]$namedConnection,
		[switch]$all
	)
	
	If ($all){
		$global:sDSPSearchNamedConnections.Values | `
		ForEach-Object { $_.dispose() }
		Remove-Variable sDSPSearchNamedConnections -Scope Global
	}
	ELSEIF ($namedConnection){
		$global:sDSPSearchNamedConnections.$namedConnection.dispose()
		$global:sDSPSearchNamedConnections.remove("$namedConnection")
	}
	ELSE{
		Write-Host "You must specify either the -all argument or the -namedConnection `"connectionname`" argument"
	}
}




#################################

Function Convert-DNSDomainNameToDistinguishedName{

#################################
	param(
		[string]$DNSDomainName
	)
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	$DNSDomainName.Insert( 0 , "DC=" ) | % { $_.Replace( "." , ",DC=") }
	
	##@#@#perfwp $myinvocation.mycommand.name
}




#############################

function Get-DCNameEx2{

#-##########################
#
# Returns one or more DC names (optionally as dns fqdn, DC machine accounts, or config NC server objects).
# Represents an alternative approach compared to using the built in DC-Locator options (see Get-DCFromDCLocatorSDSAD)
# This approach entirely ignores DC locator (and its DNS, etc stack) and gets DC information purely by ldap from the
# config NC.
# This approach has several advantages, including raw speed, flexibilty and the ability to mix and match criterea in 
# ways that are are not supported or not efficient with S.DS.AD DC Locator classes.
# Downsides to this approach include ignorance of auto-site-coverage (though for most cases the "tryAdjacentSites" 
# switch should fill in adequately, and general lack of alignment with DC Locator. If you are trying to model
# DC Locator behavior, use Get-DCNameFromDCLocatorSDSAD instead.
#
# Sample usage:
# 	Get-DCNameEx2
#		(returns fqdns of DCs from the current domain and site)
#	Get-DCNameEx2 -domainNC "DC=contoso,DC=com" -gc -output "MachineDN"
#		(returns the machine account DN of GCs in the current site which are also 
#		DCs for contoso.com [importatnt for cases where you need a GC from a particular domain, like
#		for chasing group memberships])
#	Get-DCNameEx2 -siteName "*" -domainNC "*" -gc -expensiveLatencySort
#		(returns an fqdn for every GC in the forest, sorted by distance from the client (as measured
#		by a lightweight rootDSE search against each. This connects to every DC in order to sort and may be slow).
#	Get-DCNameEx2 -site "HQ" -minimumBehaviorVersion 2 -tryAdjacentSitesOnFail -tryAllSitesOnAdjacentSiteFail
#		(returns an fqdn for every Server 2003 or above DC in site "HQ" (literal, per config NC, not per site coverage).
#		If no DCs in the site HQ meet the criterea, sites with site links to "HQ" are tried, if that also returns no
#		results, then all sites are tried.
#	*See the params for other features not described here.
#
	param(
		$output = "dNSHostName",
		$domainNC = (Get-DOmainNCName),
		$ConfigNC = (Get-ConfigNCName),
		$siteName = "NotSet",
		[int]$minimumBehaviorVersion = 0,
		[switch]$excludeRODC,
		[switch]$GC,
		[Int32]$scopeLevel = 1,
		[switch]$expensiveLatencySort,
		[switch]$excludeNonResponsive,
		[switch]$singleResultOnly
	)
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	###
	### triage arguments
	###
	
	Switch($output){
		{$_ -like "dNSHostName"} {$output = "dnshostname" ; break}
		{$_ -like "MachineDN"} {$output = "serverreference" ; break}
		{$_ -like "ConfigServerDN" } {$output = "distinguishedname" ; break}
		default {$output = "dnshostname"}
	}
	
	## Figure out the site
	IF ($siteName -eq "NotSet"){
		$parametersKey = Get-ItemProperty HKLM:\system\currentcontrolset\services\netlogon\parameters
		IF( $parametersKey.dynamicsitename){
			$sitename = $parametersKey.dynamicsitename
		}
		ELSE{
			Write-Verbose "A site name was not specified and could not be determined from the registry"
			Write-Verbose "The tool will behave as though `"*`" had been specified"
			$sitename = "*"
		}
	}
	
	###
	### Build up initial ldap search, based on the filter factors that can be implemented here
	###
	
	$ldapFilterComponentLibrary = @{}
	$ldapFilterComponentLibrary.ntdsObjectCategoryAll = "(|(objectCategory=ntdsdsa)(objectCategory=ntdsdsaro))"
	$ldapFilterComponentLibrary.ntdsObjectCategoryExcludeRODC = "(objectCategory=ntdsdsa)"
	$ldapFilterComponentLibrary.msdsbehaviorVersionEQminimumBehaviorVersion = "(msDS-Behavior-Version>=$minimumBehaviorVersion)"
	$ldapFilterComponentLibrary.optionsIsGC = "(options:1.2.840.113556.1.4.803:=1)"
	#$ldapFilterComponentLibrary.msdshasdomainNCEQDomainNC = "(msDS-HasDomainNCs=$domainNC)"
	$ldapFilterComponentLibrary.msdshasdomainNCEQDomainNC = "(hasMasterNCs=$domainNC)"
	
	
	$ldapInitialFilter = $(
		$protoInitialFilterArray= @()
		
		IF ($excludeRODC){
			$protoInitialFilterArray += $ldapFilterComponentLibrary.ntdsObjectCategoryExcludeRODC
		}
		ELSE{
			$protoInitialFilterArray += $ldapFilterComponentLibrary.ntdsObjectCategoryAll
		}
		IF ($minimumBehaviorVersion -gt 0){
			$protoInitialFilterArray += $ldapFilterComponentLibrary.msdsbehaviorVersionEQminimumBehaviorVersion
		}
		IF ($gc){
			$protoInitialFilterArray += $ldapFilterComponentLibrary.optionsIsGC
		}
		IF ($domainNC -ne "*"){
			$protoInitialFilterArray += $ldapFilterComponentLibrary.msdshasdomainNCEQDomainNC
		}
	
		IF ($protoInitialFilterArray.count -eq 1){
			$protoInitialFilterString = [string]::Join( "" , $protoInitialFilterArray	)
		}
		ELSE{
			$protoInitialFilterString = "(&" + [string]::Join( "" , $protoInitialFilterArray	) + ")"
		}
		
		Write-Output $protoInitialFilterString
	)

	###
	### Figure out the Search base
	###
	
	$initialBaseDN = $(
		IF ($siteName -eq "*"){
			"CN=Sites,$ConfigNC"
		}
		ELSE{
			"CN=$siteName,CN=Sites,$ConfigNC"
		}
	)

	## get relevant ntdsaobjects
	$ntdsaObjects = @(Invoke-SDSPSearch -baseDN $initialBaseDN -filter $ldapInitialFilter -Scope SubTree -warnings $false)
	

	###
	### Figure out whether to proceed to further filtering and output or retry with adjacent sites
	###

	IF ( ($ntdsaObjects -eq $null) -or ($ntdsaObjects.count -eq 0)){
		Write-Verbose "No suitable DCs were found in the first search"
		
		IF ($siteName -ne "*" -and $scopeLevel -ge 1){
			Write-Verbose "Trying adjacent sites. If the site originally specified was a hub site, this may take a long time"

			$directSiteLinks=@(
				invoke-sdspsearch -baseDN "CN=Inter-Site Transports,CN=Sites,$configNC" -scope SubTree -filt "(sitelist=CN=$siteName,CN=Sites,$COnfigNC)" -warnings $false
			)
			$adjacentSiteNames = @( 
				$directSiteLinks | `
					Sort-Object -Property @{Expression={ [Int32](($_.attributes.cost.getvalues([string]))[0])} ; Ascending=$true } |
						ForEach-Object {$_.attributes.sitelist.getvalues([string])} | `
							Where-Object { $_ -notlike "CN=$siteName,*" } | `
								Select-Object -unique
			)
			$ntDSAObjects = @(
				foreach ($adjacentSiteName IN $adjacentSiteNames){
					Invoke-SDSPSearch -baseDN $adjacentSiteName -filter $ldapInitialFilter -Scope SubTree -warnings $false
				}
			)
			IF (($ntDSAObjects -eq $null) -or ($ntDSAObjects.count -eq 0)){
				Write-Verbose "No suitable DCs found based on adjacent Sites"
				IF( $siteName -ne "*" -and $scopeLevel -ge 2 ){
					Write-Verbose "Trying all sites"
					$ntDSAObjects = @(Invoke-SDSPSearch -baseDN "CN=Sites,$ConfigNC" -filter $ldapInitialFilter -Scope SubTree -warnings $false)
				}
				IF ( ($ntDSAObjects -eq $null) -or ($ntDSAObjects.count -eq 0)){
					Write-Warning "No suitable DC found"
				}
			}
		}
	}

	IF ( $ntdsaObjects ){
	
	
		## TODO: FUTURE: The ordering here should be re-considered. For example consider the case where
		## a single DC is returned from one of the loops above (client's site (loop 0)) or adjacent site (loop1).
		## then imagine that DC fails in latencysorting or in obtaining the config server object (as done below).
		## If the user had specified a scope level that indicates we should keep trying to find a DC, it is too late
		## to go back from here.
		
		## TODO: FUTURE: Implement cutoff values to minimize time spend trying to talk to multiple DCs
		## (in cases where the user doesn't want all DCs) in very large environments.
	
		## Derive the config server (parent) object from the ntdsa object, and pipe result to next bit
		
		$configServerObjectsforDCs = @(
			foreach ($ntdsaObject IN $ntdsaObjects){
				##TODO: This feels like a lame way to get the parent DN
				Invoke-SDSPSearch -BaseDN (($ntdsaObject.distinguishedname).substring(17))
			}
		)
	
	
		###
		### Implement further filtering here, like supportedOIDs and latencysorting
		###
		
		
		##latency sorting
		IF ($expensiveLatencySort){
			$configserverObjectsforDCs = @(
				$configserverObjectsforDCs | `
					Foreach-Object `
						-begin { 
							$responseTimes = @{} 
						} `
						-process {
							trap { 
								continue ##TODO:does this do what I want?
							}
							
							[TimeSpan]$responseTime = [TimeSpan]::FromSeconds(0)
							$responseTime = Measure-Command { 
								invoke-sdspsearch `
									-computerName $($_.attributes.dnshostname.getvalues([string])[0]) `
									-attributes 1.1 `
									-rethrow `
									-timeout 4 `
									-retry 0 `
									-warnings $false
							}
							IF( $responsetime -eq ([TimeSpan]::FromSeconds(0)) ){
								IF( $excludeNonResponsive ){
									##dont add non-responsive server to the list for output
								}
								ELSE{
									##put failed machines at the end of the list
									##by adding a pseudo response time that is absurdly high
									$responseTime = [TimeSpan]::FromHours(1)
									$responseTimes.($_.distinguishedName) = @($responseTime , $_ )
								}
							}
							ELSE{
								$responseTimes.($_.distinguishedName) = @($responseTime , $_ )
							}
						} `
						-end {
							$responsetimes.getEnumerator() | Sort-Object -Property @{Expression={$_.Value[0]} ; Ascending=$true } | ForEach-Object { $_.Value[1] } ;
							Remove-Variable responseTimes
						}
			)
		}
		
	
		###
		### Generate final output
		###
	
		## Get and return desired attr from configServerObjectsforDCs
		$outPutReadyStrings = @(
			foreach ($dCServerObject IN $configServerObjectsforDCs){
				$dCServerObject.attributes.$output.getvalues([string])[0]
			}
		)
		
		IF(-not $singleResultOnly){
			$outputreadystrings
		}
		ELSE{
			$outputreadystrings | Select-Object -First 1
		}
	}
	
	##@#@#perfwp $myinvocation.mycommand.name
}


############################

function Get-DomainNCName{

############################

##Description:	Returns DN of "default naming context" from rootDSE for a given
##				DC or auto selected DC based on a dns domain name or if no
##				arguments are given, the domain of the current machine
##				
##Usage:			Get-DomainNCName <-DNSDomainName "contoso.com">
##
##Author:			mreyn@microsoft.com
##
##Legal:			See top of library file

	param(
		$DNSDomainName = $null
	)
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	Invoke-SDSPSearch -computerName "$DNSDomainName" | 
		ForEach-Object { $_.attributes.defaultnamingcontext.getvalues([string]) }

	##@#@#perfwp $myinvocation.mycommand.name
}



#########################################

function Get-ConfigNCName{

#########################################
	##Usage:
		## Get-ConfigNCName <-computerName DCName, DNSDomainName or ip address>
		##
		## Returns as a string the DN of the Config NC for the current forest (with no arguments),
		## or from the forest of a DC specified by -computerName
	param($computerName = "")
	
	trap{
		throw "Failed to determine COnfig NC Name"
	}
	
	(Invoke-SDSPSearch -computername $computername).attributes.configurationnamingcontext.getvalues([string])
}



#########################################

Filter Guess-DNSDomainNameFromDistinguishedName {

#########################################
	##
	## Useful for a number of situations. Based on string parsing. Should be considered unreliable.
	##
	param(
		[string]$DistinguishedName
	)
	##@#@#perfwp $myinvocation.mycommand.name -d
	IF ($_){
		$distinguishedName = $_
	}
	$tempstring0 = $distinguishedName.tolower()
	$tempstring1 = $tempstring0.substring( $($tempstring0.indexOf( "dc=" ) +3 ) , $($tempstring0.length - $tempstring0.indexOf("dc=" )-3) )
	$tempstring2 = $tempString1.Replace( ",dc=" , ".")
	Write-Output $tempString2
	$tempstring0 = $null
	$tempstring1 = $null
	$tempstring2 = $null
	##@#@#perfwp $myinvocation.mycommand.name
}


######################################

function New-Trie2PathString{

#####################################
	param(
		$rootPath,
		[string]$keyName,
		[string[]]$explicitPrefixTokens,
		[int[]]$prefixTokenLengths,
		[int]$prefixTokenStartingOffset = 0
	)
	
	##@#@#perfwp $myinvocation.mycommand.name -d

	## Get prefixTokensfromKeyName
	$prefixTokens = $(
		for ( $i=0 ; $i -lt $prefixTokenLengths.count ; $i++ )
		{
			IF ($i -eq 0){
				$lastPrefixTokenLength = 0
				$lastPrefixTokenOffset = $prefixTokenStartingOffset
			}
			$currentPrefixTokenOffset = $lastPrefixTokenOffset + $lastPrefixTokenLength
			$currentPrefixTokenLength = $prefixTokenLengths[$i]			
			$currentPrefixToken = $keyName.substring( $currentPrefixTokenOffset , $currentPrefixTokenLength )
			#emit this so it gets collected in the prefixTokens array
			Write-Output $currentPrefixToken
			$lastPrefixTokenOffset = $currentPrefixTokenOffset
			$lastPrefixTokenLength = $currentPrefixTokenLength
		}
	)

	##merge in manually specified tokens
	$prefixTokens = $explicitPrefixTokens + $prefixTokens

	$fullpath = join-path -Path "$rootPath" -ChildPath ([string]::Join( "\" , $prefixtokens) + "\" + "$keyName")
	

	Write-Output $fullpath

	
	#clean up
	$prefixTOkens = $null
	$lastPrefixTokenLength = $null
	$lastPrefixTokenOffset = $null
	$keyExists = $null
	$fullPath = $null
	
	##@#@#perfwp $myinvocation.mycommand.name

}


#############################

Function Ensure-Trie2Path {

#############################
	param(
		$Trie2path,
		$extraChildPath,
		$itemType = "directory"
	)
	
	##@#@#perfwp $myinvocation.mycommand.name -d
	
	
	IF ( $extraChildPath -ne $null ){
		$fullPath = Join-Path -Path $trie2path -ChildPath $extrachildpath
	}
	ELSE{
		$fullpath = $trie2path
	}
	
	IF (Test-Path $fullpath){
		## already exists, don't do anything
		## todo: I could additionally check if it is the right itemType
	}
	ELSE{
		New-Item -Path $fullpath -ItemType $itemType > $null
	}
	
	##@#@#perfwp $myinvocation.mycommand.name
}




########################################

Function Invoke-perfwayPoint

########################################
{
	param(
		[string]$tableName,
		[string]$wayPointName = $null,
		[switch]$dummy
	)
	
	## Get a consistent timestamp to use throughout the function
	$now = get-date
	
	##create a table if needed
	IF( -not $global:perfwayPointTables.containsKey( $tableName ) ){
		$global:perfwayPointTables.$tableName = @{}
		$global:perfwayPointTables.$tableName.Add( "lastNow" , $now ) > $null
		$global:perfwayPointTables.$tableName.Add( "tableTotal" , [timespan]::fromseconds(0) ) > $null
	}
	
	## generate a dynamic waypoint name if none was specified
	IF( [string]::IsNullOrEmpty( $wayPointName )){
		$wayPointName = $myInvocation.scriptlinenumber
	}
	
	##reset table timer if requested, useful at the beginning of loops, 
    ## or after calling something if you don't want to measure the time waiting for the callee
	IF ($dummy){
		$global:perfwayPointTables.$tableName.lastNow = $now
	}

	## create a new waypoint object if needed
	IF (-not $global:perfwayPointTables.$tableName.ContainsKey( $wayPointName ) ){
		$global:perfwayPointTables.$tableName.Add( $wayPointName , (select total,count -InputObject $true));
		$global:perfwayPointTables.$tableName.$wayPointName.total = [TimeSpan]::FromSeconds(0)
		$global:perfwayPointTables.$tableName.$wayPointName.count = [int32]0
	}
	
	##calculate timespan and record
	$currentTimeSpan = $( $now - $global:perfwayPointTables.$tableName.lastNow )
	
	$global:perfwayPointTables.$tableName.$waypointname.count++
	
	$global:perfwayPointTables.$tableName.$wayPointName.total+=$currentTimeSpan
	
	$global:perfwayPointTables.$tableName.tableTotal+=$currentTimeSpan

	$global:perfwayPointTables.$tableName.lastNow = $now

}
#note strange construction of the name below to exempt this from global search/replace operations.
 Set-Alias -Name ("perf" + "wp") -Value Invoke-perfwayPoint



##############################

Function Prepare-PerfwayPointTables {

##############################

	While( Test-Path variable:perfwaypointtables ){
		Remove-Variable -Name PerfWayPointTables -Scope Global
	}
	$global:perfwayPointTables = @{}
}



#####################################3

function Get-PerfwaypointtablesReport {

########################################

	$sortedTables = $perfwaypointTables.getenumerator() |
		Sort-Object @{expression={ $_.value.tabletotal }}
		
	Write-Host "########### Begin report"
	foreach( $tableDE IN $sortedTables){
		Format-Table -InputObject $tableDE -Property @{label='tablename';expression={ $_.key }},@{label='tabletotal';expression={ $_.value.tabletotal }},@{label=' ';expression={ ' ' }}
		
		$TableDE.value.getenumerator() |
			Sort-Object @{expression={ $_.value.total }} |
				Format-Table -Property @{label='';expression={ ' ' }},@{label='waypointname';expression={ $_.key }},@{label='total';expression={ $_.value.total }},@{label='average';expression={ [TimeSpan]::FromMilliseconds( $_.value.total.totalmilliseconds / $_.value.count ) }},@{label='count';expression={ $_.value.count }}
	}
}





###
### Execute everything by running the main function in the script scope
###
. MainCore

#extra cleanup
$script:masterResults = $null
$script:ruleThresholds = $null

#perfwp#@#@# -t TTSZOverall -w End


#signature="92488BFAF0629FB3"
