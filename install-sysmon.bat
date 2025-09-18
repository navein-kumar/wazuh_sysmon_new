@echo off
echo Downloading and Installing Sysmon...

REM Check admin rights
net session >nul 2>&1 || (echo Run as Administrator! & pause & exit)

REM Download files
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/navein-kumar/wazuh_sysmon_new/raw/refs/heads/main/Sysmon64.exe' -OutFile 'Sysmon64.exe'"
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/navein-kumar/wazuh_sysmon_new/raw/refs/heads/main/windows_sysmon_config.xml' -OutFile 'windows_sysmon_config.xml'"

REM Install Sysmon
.\Sysmon64.exe -accepteula -i windows_sysmon_config.xml

echo Done!
pause
