@echo off
set "DEST=%ProgramFiles%\IESSLHelper"
%SystemRoot%\System32\regsvr32.exe /s /u "%DEST%\IESSLHelper.dll"
rmdir /s /q "%DEST%"
