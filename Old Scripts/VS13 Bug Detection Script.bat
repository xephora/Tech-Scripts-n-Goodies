@echo off
cls
color 0f
title Visual Studios 2013 Bug Detection Script

set /p var=Check System for MSI Log dumps (Y/N)?:

IF '%var%' == 'y' GOTO main
IF '%var%' == 'Y' GOTO main
IF '%var%' == 'n' GOTO exit

:main
setlocal enableextensions
cd C:\windows\temp
cls

echo Detecting MSI Logs
echo -------------------

set errorlevel=MSI*.LOG
IF EXIST %errorlevel% (echo Detected Logs!!!!!!!!!!) else (echo Nothing Detected)
IF EXIST %errorlevel% (echo This workstation has the VS13 BUG) else (echo Nothing Detected)
pause
echo -------------------

echo Counting files..

set count=0
for %%x in (MSI*.LOG) do set /a count+=1
IF EXIST %errorlevel% (echo %count% File/Files were found..) else (GOTO exit)
echo -------------------
pause
echo Saving LOG Data to DumpFile to c:\windows\temp named VS13bug.log
forfiles /m MSI*.LOG /c "cmd /c echo File Name: @path File size: @fsize" >> VS13bug.log
timeout /t 3
VS13bug.log
pause

endlocal
exit

:exit
exit
