<div align="center">
 <img style="padding:0;vertical-align:bottom;" height="158" width="311" src="BSF.png"/>
 <p>
  <h1>
   Mal-Hash
  </h1>
 </p>

</div>

## Mal-Hash.ps1
- The script takes the input of a file, calculates the hashes (MD5, SHA1, SHA256), and then submits the SHA256 hash to Virus Total for analysis. 
- The script will also run Strings against the sample.
- The script will check Malware Bazaar to see if a sample matching the hash is available.
- The hashes, strings, Virus Total and Malware Bazaar results are both displayed on screen and saved to a text report. 
- Timestamp of the analysis is recorded in UTC. 

## VTHashSub.ps1
- The script takes a hash value as input and submits the hash to Virus Total for analysis.
- The script will check Malware Bazaar to see if a sample matching the hash is available.
- The hashes, Virus Total and Malware Bazaar results are both displayed on screen and saved to a text report. 
- Timestamp of the analysis is recorded in UTC. 

Mal-Hash.ps1 and VTHashSub.ps1 will operate (via PowerShell) on Windows, Mac & Linux.

## Latest updates: 
- n of x vendors detected
- VT permalink
- Malware Bazaar results
