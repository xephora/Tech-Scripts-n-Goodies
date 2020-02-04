@echo off
color 0f
title SpotCheck Script

echo 1 to Begin Checking
set /p var="Check this system?"
IF '%var%' == '1' GOTO start

:start
echo "===============Checking Services==============="
echo May not work if you lack privileges!
wmic service list full > %userprofile%\services.log
echo log generated: %userprofile%\services.log
ping 127.0.0.1 -n 2 > nul
echo "===============Checking Processes==============="
echo May not work if you lack privileges!
wmic process list full > %userprofile%\processes.log
echo log generated: %userprofile%\processes.log
ping 127.0.0.1 -n 2 > nul
echo "===============Checking Modules==============="
tasklist -m > %userprofile%\modules.log
echo log generated: %userprofile%\modules.log
ping 127.0.0.1 -n 2 > nul
echo "===============Checking Registries==============="
REG QUERY "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" >> %userprofile%\registries.log
REG QUERY "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" >> %userprofile%\registries.log
REG QUERY "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" >> %userprofile%\registries.log
REG QUERY "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce" >> %userprofile%\registries.log
echo log generated: %userprofile%\registries.log
ping 127.0.0.1 -n 2 > nul
echo "===============Checking Scheduled Tasks==============="
schtasks /query /fo LIST > %userprofile%\sheduledtsks.log
echo log generated: %userprofile%\scheduledtsks.log
ping 127.0.0.1 -n 2 > nul
echo "===============Checking \Appdata\Local==============="
powershell gci -Force %userprofile%\Appdata\Local >> %userprofile%\FileSys.log
cd %userprofile%\AppData\Local
ping 127.0.0.1 -n 2 > nul
attrib *.exe -s -h -r /s /d
attrib *.bat -s -h -r /s /d
attrib *.js -s -h -r /s /d
attrib *.jar -s -h -r /s /d
ping 127.0.0.1 -n 2 > nul
set errorlevel=*.exe
IF EXIST %ERRORLEVEL% echo Suspicious Binary found in Profile\Appdata\Local
dir /b *.exe >> %userprofile%\FileSys.log
ping 127.0.0.1 -n 2 > nul
echo Checking JavaScripts..
set errorlevel=*.js
IF EXIST %ERRORLEVEL% echo Suspicious JavaScript found in Profile\Appdata\Local
dir /b *.js >> %userprofile%\FileSys.log
ping 127.0.0.1 -n 2 > nul
echo Checking BatchFiles..
set errorlevel=*.bat
IF EXIST %ERRORLEVEL% echo Suspicious BatScript found in Profile\Appdata\Local
dir /b *.bat >> %userprofile%\FileSys.log
ping 127.0.0.1 -n 2 > nul
echo Checking JavaFiles..
set errorlevel=*.jar
IF EXIST %ERRORLEVEL% echo Suspicious JavaFile found in Profile\Appdata\Local 
dir /b *.jar >> %userprofile%\FileSys.log
echo "===============Checking \Appdata\Local\Microsoft==============="
ping 127.0.0.1 -n 2 > nul
powershell gci -Force %userprofile%\Appdata\Local\Microsoft >> %userprofile%\FileSys.log
cd %userprofile%\AppData\Local\Microsoft
ping 127.0.0.1 -n 2 > nul
attrib *.exe -s -h -r /s /d
attrib *.bat -s -h -r /s /d
attrib *.js -s -h -r /s /d
attrib *.jar -s -h -r /s /d
ping 127.0.0.1 -n 2 > nul
set errorlevel=*.exe
IF EXIST %ERRORLEVEL% echo Suspicious Binary found in Profile\Appdata\Local\Microsoft
dir /b *.exe >> %userprofile%\FileSys.log
ping 127.0.0.1 -n 2 > nul
echo Checking JavaScripts..
set errorlevel=*.js
IF EXIST %ERRORLEVEL% echo Suspicious JavaScript found in Profile\Appdata\Local\Microsoft
dir /b *.js >> %userprofile%\FileSys.log
ping 127.0.0.1 -n 2 > nul
echo Checking BatchFiles..
set errorlevel=*.bat
IF EXIST %ERRORLEVEL% echo Suspicious BatScript found in Profile\Appdata\Local\Microsoft
dir /b *.bat >> %userprofile%\FileSys.log
ping 127.0.0.1 -n 2 > nul
echo Checking JavaFiles..
set errorlevel=*.jar
IF EXIST %ERRORLEVEL% echo Suspicious JavaFile found in Profile\Appdata\Local\Microsoft
dir /b *.jar >> %userprofile%\FileSys.log
echo "===============Checking \Appdata\Roaming==============="
ping 127.0.0.1 -n 2 > nul
powershell gci -Force %userprofile%\Appdata\Roaming >> %userprofile%\FileSys.log
cd %userprofile%\AppData\Roaming
ping 127.0.0.1 -n 2 > nul
attrib *.exe -s -h -r /s /d
attrib *.bat -s -h -r /s /d
attrib *.js -s -h -r /s /d
attrib *.jar -s -h -r /s /d
ping 127.0.0.1 -n 2 > nul
set errorlevel=*.exe
IF EXIST %ERRORLEVEL% echo Suspicious Binary found in Profile\Appdata\Roaming
dir /b *.exe >> %userprofile%\FileSys.log
ping 127.0.0.1 -n 2 > nul
echo Checking JavaScripts..
set errorlevel=*.js
IF EXIST %ERRORLEVEL% echo Suspicious JavaScript found in Profile\Appdata\Roaming
dir /b *.js >> %userprofile%\FileSys.log
ping 127.0.0.1 -n 2 > nul
echo Checking BatchFiles..
set errorlevel=*.bat
IF EXIST %ERRORLEVEL% echo Suspicious BatScript found in Profile\Appdata\Roaming
dir /b *.bat >> %userprofile%\FileSys.log
ping 127.0.0.1 -n 2 > nul
echo Checking JavaFiles..
set errorlevel=*.jar
IF EXIST %ERRORLEVEL% echo Suspicious JavaFile found in Profile\Appdata\Roaming 
dir /b *.jar >> %userprofile%\FileSys.log
echo "===============Checking \Appdata\Roaming\Microsoft==============="
ping 127.0.0.1 -n 2 > nul
powershell gci -Force %userprofile%\Appdata\Roaming\Microsoft >> %userprofile%\FileSys.log
cd %userprofile%\AppData\Roaming\Microsoft
ping 127.0.0.1 -n 2 > nul
attrib *.exe -s -h -r /s /d
attrib *.bat -s -h -r /s /d
attrib *.js -s -h -r /s /d
attrib *.jar -s -h -r /s /d
ping 127.0.0.1 -n 2 > nul
set errorlevel=*.exe
IF EXIST %ERRORLEVEL% echo Suspicious Binary found in Profile\Appdata\Roaming\Microsoft
dir /b *.exe >> %userprofile%\FileSys.log
ping 127.0.0.1 -n 2 > nul
echo Checking JavaScripts..
set errorlevel=*.js
IF EXIST %ERRORLEVEL% echo Suspicious JavaScript found in Profile\Appdata\Roaming\Microsoft
dir /b *.js >> %userprofile%\FileSys.log
ping 127.0.0.1 -n 2 > nul
echo Checking BatchFiles..
set errorlevel=*.bat
IF EXIST %ERRORLEVEL% echo Suspicious BatScript found in Profile\Appdata\Roaming\Microsoft
dir /b *.bat >> %userprofile%\FileSys.log
ping 127.0.0.1 -n 2 > nul
echo Checking JavaFiles..
set errorlevel=*.jar
IF EXIST %ERRORLEVEL% echo Suspicious JavaFile found in Profile\Appdata\Roaming\Microsoft
dir /b *.jar >> %userprofile%\FileSys.log
echo log generated: %userprofile%\Filesys.log
echo "===============END==============="
echo 0 to Exit
set /p var=Review data Before Proceeding:
IF '%var%' == '0' GOTO exit
:exit
exit
