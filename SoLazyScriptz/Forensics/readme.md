# Forensic Tools

### Usage for unpack_7z
```
./unpack_7z <filename>.7z
```

### Usage for xtract_chromedata
```
./xtract_chromedata

Enter <filename>.doc
```
### Alternative Datastreams
https://blog.malwarebytes.com/101/2015/07/introduction-to-alternate-data-streams/

### Browser history
https://www.nirsoft.net/utils/browsing_history_view.html

### Extracting data out of thumbcache
https://thumbsviewer.github.io/

### USB History
https://www.cybrary.it/blog/0p3n/usb-forensics-find-the-history-of-every-connected-usb-device-on-your-computer/

### Retrieve SIDs or current user
```
whoami /all
reg query HKU
```
### wmic
https://resources.infosecinstitute.com/topic/commandline-malware-and-forensics/

### Resources
https://www.sans.org/security-resources/posters/windows-forensic-analysis/170/download

### sqlite browser
https://sqlitebrowser.org/dl/#windows

### Volatility

```
volatility -f MEMORY_FILE.raw imageinfo
volatility -f MEMORY_FILE.raw --profile=PROFILE pslist
volatility -f MEMORY_FILE.raw --profile=PROFILE netscan
volatility -f MEMORY_FILE.raw --profile=PROFILE psxview -> look for False's
volatility -f MEMORY_FILE.raw --profile=PROFILE dlllist
volatility -f MEMORY_FILE.raw --profile=PROFILE --pid=PID dlldump -D <Destination Directory>
volatility -f MEMORY_FILE.raw --profile=PROFILE ldrmodules -> look for False's
volatility -f MEMORY_FILE.raw --profile=PROFILE apihooks -> look for patched system files, look for <unknown>
volatility -f MEMORY_FILE.raw --profile=PROFILE malfind -D /tmp
volatility -f MEMORY_FILE.raw --profile=PROFILE --pid=PID dlldump -D <Destination Directory>
volatility -f MEMORY_FILE.raw --profile=PROFILE --pid=PID hivelist
volatility -f MEMORY_FILE.raw --profile=PROFILE printkey -K 'Software\Microsoft\Windows\CurrentVersion\Run'
volatility -f MEMORY_FILE.raw --profile=PROFILE procdump -p PID --dump-dir /tmp  -> generates exe
volatility -f MEMORY_FILE.raw --profile=PROFILE memdump -p PID --dump-dir /tmp  -> dumps mem dump for process
volatility -f MEMORY_FILE.raw --profile=PROFILE cmdline  -> cmd history
volatility -f MEMORY_FILE.raw --profile=PROFILE sockets
volatility -f MEMORY_FILE.raw --profile=PROFILE connscan
vol.py -f memimage.raw --profile=<profile> dumpfiles --dump-dir memdump -n
vol.py -f memimage.raw --profile=<profile> dumpfiles -Q <offset_assoc_with_file>
vol.py -f memimage.raw --profile=<profile> dumpfiles -r file.txt --dump-dir memdump
vol.py -f memimage.raw --profile=<profile> dumpfiles -r txt$ --dump-dir memdump -n
vol.py -f memimage.raw --profile=<profile> filescan | Select-String "keyword"
vol.py -f memimage.raw --profile=<profile> cmdscan
vol.py -f memimage.raw --profile=<profile> shellbags
```

### Using pypykatz
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

Resources  
https://www.stevencampbell.info/Parsing-Creds-From-Lsass.exe-Dumps-Using-Pypykatz/  


### Extracting data from SAM hive
https://hatsoffsecurity.com/2014/05/21/using-the-sam-hive-to-profile-user-accounts/  
https://github.com/keydet89/RegRipper3.0  

> hexeditor may also assist with retrieving information you need from the hive files.

### Parsing BMC
https://github.com/ANSSI-FR/bmc-tools


