strContainer = "ou=General, ou=AZL, ou=Users and Groups"
strName = "AZ-R-WTS-LotusNotes"

On Error Resume Next

'***********************************************
'*          Connect to an object                 *
'***********************************************
Set objRootDSE = GetObject("LDAP://rootDSE")
If strContainer = "" Then
  Set objItem = GetObject("LDAP://" & _
    objRootDSE.Get("defaultNamingContext"))
Else
  Set objItem = GetObject("LDAP://cn=" & strName & "," & strContainer & "," & _
    objRootDSE.Get("defaultNamingContext"))
End If
'***********************************************
'*         End connect to an object           *
'***********************************************

WScript.Echo VbCrLf & "** General Properties Page**"
WScript.Echo "** (Single-Valued Attributes) **"
strname = objItem.Get("name")
WScript.Echo "name: " & strname
strsamAccountName = objItem.Get("samAccountName")
WScript.Echo "samAccountName: " & strsamAccountName
strdescription = objItem.Get("description")
WScript.Echo "description: " & strdescription
strmail = objItem.Get("mail")
WScript.Echo "mail: " & strmail

WScript.Echo VbCrLf & "** General Properties Page**"
WScript.Echo "** (The groupType attribute) **"
Set objHash = CreateObject("Scripting.Dictionary")
objHash.Add "ADS_GROUP_TYPE_GLOBAL_GROUP", &h2
objHash.Add "ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP", &h4
objHash.Add "ADS_GROUP_TYPE_UNIVERSAL_GROUP", &h8
objHash.Add "ADS_GROUP_TYPE_SECURITY_ENABLED", &h80000000
intgroupType = objItem.Get("groupType")
For Each Key in objHash.Keys
  If objHash(Key) And intgroupType Then
    WScript.Echo Key & " is enabled."
  Else
    WScript.Echo Key & " is disabled."
  End If
Next
If intgroupType AND objHash.Item("ADS_GROUP_TYPE_DOMAIN_LOCAL_GROUP") Then
  WScript.Echo "Group Scope: Domain Local Group"
ElseIf intGroupType AND objHash.Item("ADS_GROUP_TYPE_GLOBAL_GROUP") Then
  WScript.Echo "Group Scope: Global Group"
ElseIf intGroupType AND objHash.Item("ADS_GROUP_TYPE_UNIVERSAL_GROUP") Then
  WScript.Echo "Group Scope: Universal Group"
End If
If intgroupType AND objHash.Item("ADS_GROUP_TYPE_SECURITY_ENABLED") Then
  WScript.Echo "Group Type: Security"
Else
  WScript.Echo "Group Type: Distribution"
End If
WScript.Echo VbCrLf & "** Managed By Properties Page**"
WScript.Echo "** (Single-Valued Attributes) **"
strmanagedBy = objItem.Get("managedBy")
WScript.Echo "managedBy: " & strmanagedBy

If strmanagedBy <> "" Then
  Set objItem1 = GetObject("LDAP://" & strManagedBy)
  WScript.Echo "physicalDeliveryOfficeName: " & _
    objItem1.physicalDeliveryOfficeName
  WScript.Echo "streetAddress: " & _
    objItem1.streetAddress
  WScript.Echo "l: " & _
    objItem1.l
  WScript.Echo "c: " & _
    objItem1.c
  WScript.Echo "telephoneNumber: " & _
    objItem1.telephoneNumber
  WScript.Echo "facsimileTelephoneNumber: " & _
    objItem1.facsimileTelephoneNumber
End If

WScript.Echo VbCrLf & "** Member Properties Page**"
WScript.Echo "** (MultiValued Attributes) **"
strmember = objItem.GetEx("member")
WScript.Echo "member:"
For Each Item in strmember
 WScript.Echo vbTab & Item
Next

WScript.Echo VbCrLf & "** Member Of Properties Page**"
WScript.Echo "** (MultiValued Attributes) **"
strmemberOf = objItem.GetEx("memberOf")
WScript.Echo "memberOf:"
For Each Item in strmemberOf
 WScript.Echo vbTab & Item
Next

WScript.Echo VbCrLf & "** Managed By Properties Page**"
WScript.Echo "** (Single-Valued Attributes) **"
strmanagedBy = objItem.Get("managedBy")
WScript.Echo "managedBy: " & strmanagedBy

If strmanagedBy <> "" Then
  Set objItem1 = GetObject("LDAP://" & strManagedBy)
  WScript.Echo "physicalDeliveryOfficeName: " & _
    objItem1.physicalDeliveryOfficeName
  WScript.Echo "streetAddress: " & _
    objItem1.streetAddress
  WScript.Echo "l: " & _
    objItem1.l
  WScript.Echo "c: " & _
    objItem1.c
  WScript.Echo "telephoneNumber: " & _
    objItem1.telephoneNumber
  WScript.Echo "facsimileTelephoneNumber: " & _
    objItem1.facsimileTelephoneNumber
End If