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
olatility -f MEMORY_FILE.raw --profile=PROFILE --pid=PID dlldump -D <Destination Directory>
volatility -f MEMORY_FILE.raw --profile=PROFILE ldrmodules -> look for False's
volatility -f MEMORY_FILE.raw --profile=PROFILE apihooks -> look for patched system files, look for <unknown>
volatility -f MEMORY_FILE.raw --profile=PROFILE malfind -D /tmp
volatility -f MEMORY_FILE.raw --profile=PROFILE --pid=PID dlldump -D <Destination Directory>
volatility -f MEMORY_FILE.raw --profile=PROFILE --pid=PID hivelist
volatility -f MEMORY_FILE.raw --profile=PROFILE printkey -K 'Software\Microsoft\Windows\CurrentVersion\Run'
```
