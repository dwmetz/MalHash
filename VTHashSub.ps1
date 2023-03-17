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
Write-Host -Fore Cyan "               VTHashSub v1.0" 
Write-Host -Fore Gray "     @dwmetz | bakerstreetforensics.com"
Write-Host ""
Write-Host ""
Write-Host -Fore DarkCyan "   It submits the hash to VirusTotal or it"
Write-Host -Fore DarkCyan "   gets the hose again."
write-host " "
$tstamp = (Get-Date -Format "yyyy-MM-dd-HH-mm")
$script:hash = Read-Host -Prompt 'enter the malware hash value'
write-host " "
"HASH: $script:hash" | Out-File -FilePath malhash.-t.txt -Append
" " | Out-File -FilePath malhash.-t.txt -Append
$datetime = Get-Date
$date = $datetime.ToUniversalTime()
"DATE/TIME UTC: $date" | Out-File -FilePath malhash.-t.txt -Append
" " | Out-File -FilePath malhash.-t.txt -Append
$apiKey = (Get-Content vt-api.txt)
"** VIRUS TOTAL RESULTS: **" | Out-File -FilePath malhash.-t.txt -Append
write-host "Submitting the hash $script:hash to Virus Total" -Fore DarkCyan
Write-host ""
$uri = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$apiKey&resource=$script:hash"
write-host "VIRUS TOTAL RESULTS:" -Fore Cyan
Invoke-RestMethod -Uri $uri
$vtResults = Invoke-RestMethod -Uri $uri
Invoke-RestMethod -Uri $uri | Out-File -FilePath malhash.-t.txt -Append
$vtresults
$vtResults.scans 
$vtResults.scans | Out-File -FilePath malhash.-t.txt -Append
" " | Out-File -FilePath malhash.-t.txt -Append
"** END REPORT **" | Out-File -FilePath malhash.-t.txt -Append
$report = $script:hash + "." + $tstamp
Get-ChildItem -Filter 'malhash*' -Recurse | Rename-Item -NewName {$_.name -replace '-t', $report }
Write-host " "
Write-host "VTHashSub complete. Report saved as malhash.$report.txt" -Fore Cyan