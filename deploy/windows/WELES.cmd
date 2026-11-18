@echo off
rem WELES launcher. User data goes to %LOCALAPPDATA%\Weles - never to the installation directory.
start "" "%~dp0app\Weles.exe" %*
