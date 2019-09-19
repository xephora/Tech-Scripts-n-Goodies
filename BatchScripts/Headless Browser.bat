@echo off
cls

:main

echo Headless Browser - Insert URL to evaluate - Example https://google.com
set /p var=""

"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --headless --disable-gpu --enable-logging --dump-dom %var%

set /p menu=Try another? (y/n)

IF '%menu%' == 'y' GOTO main
IF '%menu%' == 'Y' GOTO main
IF '%menu%' == 'n' GOTO depart
IF '%menu%' == 'N' GOTO depart

:depart
exit
