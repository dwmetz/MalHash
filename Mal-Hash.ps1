<#
Mal-Hash.ps1 v1.5
https://github.com/dwmetz/Mal-Hash
Author: @dwmetz
Function: This script will generate hashes (MD5, SHA1, SHA256) for a specified file, 
        run strings against the file,
        submit the MD5 to Virus Total, 
        produce a report with the results.
        * Now works on Windows, Mac & Linux!
Prerequisites:
        Internet access is required for VT lookup.
        Virus Total API key saved in vt-api.txt
23-January-2023 ascii art update
6-December-2022 simplified hash output; 
                strings (+8); 
                UTC timestamp in report
                report name change
5-July-2023 Changed default hash value submission to SHA256
13-July $report updates
#>
Clear-Host
Write-Host ""
Write-Host ""
Write-Host ""
Write-host -Fore DarkCyan "
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
Write-Host -Fore DarkCyan "                    Mal-Hash v1.6" 
Write-Host -Fore Gray "          https://github.com/dwmetz/Mal-Hash"
Write-Host -Fore Gray "          @dwmetz | bakerstreetforensics.com"
Write-Host ""
Write-Host ""
write-host " "
$tstamp = (Get-Date -Format "yyyyMMddHHmm")
$script:file = Read-Host -Prompt 'enter path and filename'
write-host " "
$sourcefile = [system.IO.Path]::GetFileName("$script:file")
$report = "malhash" + "-" + $sourcefile + "-" + $tstamp + ".txt" 
"SOURCE: $sourcefile" | Out-File -FilePath $report -Append
" " | Out-File -FilePath $report -Append
$datetime = Get-Date
$date = $datetime.ToUniversalTime()
"DATE/TIME UTC: $date" | Out-File -FilePath $report -Append
" " | Out-File -FilePath $report -Append
$apiKey = (Get-Content vt-api.txt)
$MD5hash = (Get-FileHash $file -Algorithm MD5).Hash 
$SHA1hash = (Get-FileHash $file -Algorithm SHA1).Hash
$SHA256hash = (Get-FileHash $file -Algorithm SHA256).Hash
"** HASHES: **" | Out-File -FilePath $report -Append
"MD5: $MD5hash" | Out-File -FilePath $report -Append
"SHA1: $SHA1hash" | Out-File -FilePath $report -Append
"SHA256: $SHA256hash" | Out-File -FilePath $report -Append
" " | Out-File -FilePath $report -Append
"** VIRUS TOTAL RESULTS: **" | Out-File -FilePath $report -Append
$fileHash = (Get-FileHash $file -Algorithm SHA256).Hash
write-host "Submitting SHA256 hash $fileHash to Virus Total" -Fore Cyan
Write-host ""
$uri = "https://www.virustotal.com/vtapi/v2/file/report?apikey=$apiKey&resource=$fileHash"
write-host "VIRUS TOTAL RESULTS:" -Fore Cyan
Invoke-RestMethod -Uri $uri
$vtResults = Invoke-RestMethod -Uri $uri
Invoke-RestMethod -Uri $uri | Out-File -FilePath $report -Append
$vtresults
$vtResults.scans 
$vtResults.scans | Out-File -FilePath $report -Append
Write-host " "
"** STRINGS: ** " | Out-File -FilePath $report -Append
strings -n 8 $script:file | Out-File -FilePath $report -Append
write-host "STRINGS:" -Fore Cyan
strings -n 8 $script:file
" " | Out-File -FilePath $report -Append
Write-host " "
Write-host $vtResults.positives of $vtResults.total vendors detected this sample.
Write-host " "
Write-host -Fore Green "VT Results Permalink:" | Out-File -FilePath $report -Append
Write-host $vtResults.Permalink | Out-File -FilePath $report -Append
Write-host " " | Out-File -FilePath $report -Append
" " | Out-File -FilePath $report -Append
#
$report = "malhash" + "-" + $sourcefile + "-" + $tstamp + ".txt" 
"** MALWARE BAZAAR RESULTS: **" | Out-File -FilePath $report -Append
" " | Out-File -FilePath $report -Append
Write-host -Fore Green "Malware Bazaar Results:
" 
$url = "https://mb-api.abuse.ch/api/v1/"
$data = @{
    query = "get_info"
    hash = $SHA256hash
}
$mb = Invoke-RestMethod -Uri $url -Method POST -Body $data
$mb.data
$mb.data | Out-File -FilePath $report -Append
"** END REPORT **" | Out-File -FilePath $report -Append
Write-host "Mal-Hash complete. Report saved as $report" -Fore Cyan