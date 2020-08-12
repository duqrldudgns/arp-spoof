@echo off
:loop
cls
set /a a+=1
echo %a%
arp -a
timeout /t 2 > NUL
goto loop