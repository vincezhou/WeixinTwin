@echo off
cd /d "%~dp0"
go build -ldflags "-H windowsgui -s -w" -o WeixinTwin.exe .
if errorlevel 1 exit /b 1
echo Built: %~dp0WeixinTwin.exe
