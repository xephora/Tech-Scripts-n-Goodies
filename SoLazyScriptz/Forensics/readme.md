# Forensic Tools

## Resources:

Useful Forensic Tools:  
https://ericzimmerman.github.io/#!index.md

Alternative Datastreams  
https://blog.malwarebytes.com/101/2015/07/introduction-to-alternate-data-streams/

View Browsing history:  
https://www.nirsoft.net/utils/browsing_history_view.html

Extracting data out of thumbcache:  
https://thumbsviewer.github.io/

USB History:  
https://www.cybrary.it/blog/0p3n/usb-forensics-find-the-history-of-every-connected-usb-device-on-your-computer/

https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download

Retrieve SIDs or current user:  
```
whoami /all
reg query HKU
```

wmic:  
https://resources.infosecinstitute.com/topic/commandline-malware-and-forensics/

sqlite browser:  
https://sqlitebrowser.org/dl/#windows


## Volatility

Resources (Thanks for @Firehawk for providing this link)
https://www.andreafortuna.org/2017/11/15/how-to-retrieve-users-passwords-from-a-windows-memory-dump-using-volatility/ 

```
vol.py -f MEMORY_FILE.raw imageinfo
vol.py -f MEMORY_FILE.raw linuxgetprofile
vol.py -f MEMORY_FILE.raw --profile=PROFILE pslist
vol.py -f MEMORY_FILE.raw --profile=PROFILE netscan
vol.py -f MEMORY_FILE.raw --profile=PROFILE psxview -> look for False's
vol.py -f MEMORY_FILE.raw --profile=PROFILE dlllist
vol.py -f MEMORY_FILE.raw --profile=PROFILE --pid=PID dlldump -D <Destination Directory>
vol.py -f MEMORY_FILE.raw --profile=PROFILE ldrmodules -> look for False's
vol.py -f MEMORY_FILE.raw --profile=PROFILE apihooks -> look for patched system files, look for <unknown>
vol.py -f MEMORY_FILE.raw --profile=PROFILE malfind -D /tmp
vol.py -f MEMORY_FILE.raw --profile=PROFILE --pid=PID dlldump -D <Destination Directory>
vol.py -f MEMORY_FILE.raw --profile=PROFILE --pid=PID hivelist
vol.py -f MEMORY_FILE.raw --profile=PROFILE printkey -K 'Software\Microsoft\Windows\CurrentVersion\Run'
vol.py -f MEMORY_FILE.raw --profile=PROFILE procdump -p PID --dump-dir /tmp  -> generates exe
vol.py -f MEMORY_FILE.raw --profile=PROFILE memdump -p PID --dump-dir /tmp  -> dumps mem dump for process
vol.py -f MEMORY_FILE.raw --profile=PROFILE cmdline  -> cmd history
vol.py -f MEMORY_FILE.raw --profile=PROFILE sockets
vol.py -f MEMORY_FILE.raw --profile=PROFILE connscan
vol.py -f MEMORY_FILE.raw --profile=PROFILE dumpfiles --dump-dir memdump -n
vol.py -f MEMORY_FILE.raw --profile=PROFILE dumpfiles -Q <offset_assoc_with_file>
vol.py -f MEMORY_FILE.raw --profile=PROFILE dumpfiles -r file.txt --dump-dir memdump
vol.py -f MEMORY_FILE.raw --profile=PROFILE dumpfiles -r txt$ --dump-dir memdump -n
vol.py -f MEMORY_FILE.raw --profile=PROFILE filescan | Select-String "keyword"
vol.py -f MEMORY_FILE.raw --profile=PROFILE cmdscan
vol.py -f MEMORY_FILE.raw --profile=PROFILE shellbags
vol.py -f MEMORY_FILE.raw --profile=PROFILE hivelist
vol.py -f MEMORY_FILE.raw --profile=PROFILE dumpregistry -o <hive_virtual_address> -D <output_directory>


vol3 -f MEMORY_FILE.raw -p Win10x64_19041 plugins
vol3 -f MEMORY_FILE.raw windows.envars
vol3 -f MEMORY_FILE.raw -p Win10x64_19041 windows.pslist
vol3 -f MEMORY_FILE.raw windows.dumpfiles --pid <pid>
vol3 -f MEMORY_FILE.raw -p Win10x64_19041 windows.pstree
vol3 -f MEMORY_FILE.raw -p Win10x64_19041 windows.netscan
vol3 -f MEMORY_FILE.raw windows.hashdump
vol3 -f MEMORY_FILE.raw -p Win10x64_19041 windows.filescan > output.txt
vol3 -f MEMORY_FILE.raw -p Win10x64_19041 windows.dumpfiles
vol3 -f MEMORY_FILE.raw -p Win10x64_19041 windows.dumpfiles --virtaddr 0x0000db8d38d58ed0
vol3 -f MEMORY_FILE.raw -p Win10x64_19041 windows.dumpfiles -r "16f2f0042ddbe0e8.customDestinations-ms" --dump-dir dump/

Example Hash Dump:

vol3 -f memdump.raw windows.hashdump

Volatility 3 Framework 2.0.0
Progress:  100.00		PDB scanning finished                        
User	rid	lmhash	nthash

Administrator	500	aad3b435b51404eeaad3b435b51404ee 31d6cfe0d16ae931b73c59d7e0c089c0
Guest	501	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
DefaultAccount	503	aad3b435b51404eeaad3b435b51404ee	31d6cfe0d16ae931b73c59d7e0c089c0
WDAGUtilityAccount	504	aad3b435b51404eeaad3b435b51404ee	0b51f04cf2a0d8f6f4469cd628a78776
Jimmie	1001	aad3b435b51404eeaad3b435b51404ee	0d757ad173d2fc249ce19364fd64c8ec
Admin	1003	aad3b435b51404eeaad3b435b51404ee	29b0d58e146d70278c29dc70f74f1e5d
```

### Volatility profiles
https://github.com/volatilityfoundation/volatility/wiki/2.6-Win-Profiles

### Analzing hibernation files
https://www.forensicxlab.com/posts/hibernation/  
https://www.blackhat.com/presentations/bh-usa-08/Suiche/BH_US_08_Suiche_Windows_hibernation.pdf  
https://andreafortuna.org/2019/05/15/how-to-read-windows-hibernation-file-hiberfil-sys-to-extract-forensic-data/  

## Using pypykatz
https://github.com/skelsec/pypykatz

Installation
```
installing pypykatz
pip3 install pypykatz
```

Local Dump of lsass
```
python3 -m pypykatz lsa minidump lsassdump.dmp
```

### Resources on pypykatz
https://www.stevencampbell.info/Parsing-Creds-From-Lsass.exe-Dumps-Using-Pypykatz/  

### Extracting data from SAM hive
https://hatsoffsecurity.com/2014/05/21/using-the-sam-hive-to-profile-user-accounts/  
https://github.com/keydet89/RegRipper3.0  

> hexeditor may also assist with retrieving information you need from the hive files.

### Parsing BMC
https://github.com/ANSSI-FR/bmc-tools

### Using exiftool
https://github.com/exiftool/exiftool

```
exiftool source.png
```

### binwalk
```
binwalk file

extracting data from an image

binwalk -e file
binwalk --dd='.*'
```

### pdftool remnux
```
retrieve object numbers
pdftool.py iu pdf_file.pdf

select object numbers
pdftool.py iu -s objectnumber pdf_file.pdf

dump object
pdftool.py iu -s objectnumber -d pdf_file.pdf
```

### Linux memory forensics

A great video explaination provided by ippsec  
https://www.youtube.com/watch?v=uYWTfWV3dQI  

```
dd if=mem bs=1 skip=$((0xXXXXX)) count=$((0x1000)) of=/tmp/output
dd if=mem bs=1 skip=$((0xXXXXX)) count=$((0xXXXXX-0xXXXXX)) of=/tmp/output
```
