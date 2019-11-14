@echo off

echo 'Insert URL: '
set /p var=""
cls

python E:\Dump\Grabber\grabber.py --spider 1 --sql --xss --url %var%