function Get-HtmlRow($process)
{
	$template = "<TR> <TD>{0}</TD> <TD>{1}</TD> </TR>"
	$template -f $process.Name,$process.ID
}

<#Generate a two column HTML table for processes.   This will be useful

"<HTML><BODY><TABLE> > report.html
Get-Process | Foreach-Object { Get-HtmlRow $_ } >> report.html
"</TABLE></BODY></HTML>" >> report.html
Invoke-Item .\report.html

#>