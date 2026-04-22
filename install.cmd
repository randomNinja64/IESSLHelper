@echo off
set "DEST=%ProgramFiles%\IESSLHelper"
if not exist "%DEST%" mkdir "%DEST%"
copy /Y "%~dp0IESSLHelper.dll" "%DEST%\"
copy /Y "%~dp0curl.exe"        "%DEST%\"
copy /Y "%~dp0curl-ca-bundle.crt"      "%DEST%\"
%SystemRoot%\System32\regsvr32.exe "%DEST%\IESSLHelper.dll"
