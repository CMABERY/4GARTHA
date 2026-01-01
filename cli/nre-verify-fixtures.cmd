@echo off
setlocal
py -3 "%~dp0nre-verify-fixtures" %*
exit /b %errorlevel%
