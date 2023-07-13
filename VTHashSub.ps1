<#
VTSubHash.ps1 
#>
Clear-Host
Write-Host ""
Write-Host ""
Write-Host ""
Write-host -Fore Cyan "
    .',;::cccccc:;.                         ...'''''''..'.  
   .;ccclllloooddxc.                   .';clooddoolcc::;:;. 
   .:ccclllloooddxo.               .,coxxxxxdl:,'..         
   'ccccclllooodddd'            .,,'lxkxxxo:'.              
   'ccccclllooodddd'        .,:lxOkl,;oxo,.                 
   ':cccclllooodddo.      .:dkOOOOkkd;''.                   
   .:cccclllooooddo.  ..;lxkOOOOOkkkd;                      
   .;ccccllloooodddc:coxkkkkOOOOOOx:.                       
    'cccclllooooddddxxxxkkkkOOOOx:.                         
     ,ccclllooooddddxxxxxkkkxlc,.                           
      ':llllooooddddxxxxxoc;.                               
       .';:clooddddolc:,..                                  
           ''''''''''                                                                                                                 
"                
Write-Host -Fore Cyan "               VTHashSub v1.2" 
Write-Host -Fore Gray "     @dwmetz | bakerstreetforensics.com"
Write-Host ""
Write-Host ""
Write-Host -Fore DarkCyan "   It submits the hash to VirusTotal or it"
Write-Host -Fore DarkCyan "   gets the hose again."
write-host " "
$tstamp = (Get-Date -Format "yyyyMMddHHmm")
$script:hash = Read-Host -Prompt 'enter the malware hash value'
$report = "malhash" + "-" + $script:hash + "-" + $tstamp + ".txt" 
write-host " "
"HASH: $script:hash" | Out-File -FilePath $report -Append
" " | Out-File -FilePath $report -Append
$datetime = Get-Date
$date = $datetime.ToUniversalTime()
"DATE/TIME UTC: $date" | Out-File -FilePath $report -Append
" " | Out-File -FilePath $report -Append
$apiKey = (Get-Content vt-api.txt)
"** VIRUS TOTAL RESULTS: **" | Out-File -FilePath $report -Append
write-host "Submitting the hash $script:hash to Virus Total" -Fore DarkCyan
Write-host ""
$uri = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$apiKey&resource=$script:hash"
write-host "VIRUS TOTAL RESULTS:" -Fore Cyan
Invoke-RestMethod -Uri $uri
$vtResults = Invoke-RestMethod -Uri $uri
Invoke-RestMethod -Uri $uri | Out-File -FilePath $report -Append
$vtresults
$vtResults.scans 
$vtResults.scans | Out-File -FilePath $report -Append
" " | Out-File -FilePath $report -Append
Write-host " "
Write-host $vtResults.positives of $vtResults.total vendors detected this sample.
Write-host " "
Write-host -Fore Green "VT Results Permalink:"
Write-host $vtResults.Permalink
Write-host " "
#
$report = "malhash" + "-" + $script:hash + "-" + $tstamp + ".txt" 
"** MALWARE BAZAAR RESULTS: **" | Out-File -FilePath $report -Append
Write-host -Fore Green "Malware Bazaar Results:
" 
$url = "https://mb-api.abuse.ch/api/v1/"
$data = @{
    query = "get_info"
    hash = $script:hash
}
$mb = Invoke-RestMethod -Uri $url -Method POST -Body $data
$mb.data
$mb.data | Out-File -FilePath $report -Append
"** END REPORT **" | Out-File -FilePath $report -Append
Write-host "VTHashSub complete. Report saved as $report" -Fore Cyan