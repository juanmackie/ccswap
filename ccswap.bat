@echo off
setlocal EnableExtensions EnableDelayedExpansion
:: ccswap – Claude-Code profile switcher for Windows

set "PDIR=%USERPROFILE%\.claude\profiles"
set "SFILE=%USERPROFILE%\.claude\settings.json"
set "CUR=%PDIR%\_current.txt"

if not exist "%PDIR%" mkdir "%PDIR%"

:: Handle commands
if "%~1"=="" goto :show_usage

if /i "%~1"=="ls" (
  echo Profiles:
  for %%f in ("%PDIR%\*.json") do (
    set "n=%%~nf"
    findstr /X "!n!" "%CUR%" >nul 2>&1 && echo   * !n! || echo     !n!
  )
  goto :eof
)

if /i "%~1"=="use" (
  if "%~2"=="" goto :show_usage
  if not exist "%PDIR%\%~2.json" (
    echo Error: Profile %~2 does not exist >&2
    exit /b 1
  )
  copy /Y "%PDIR%\%~2.json" "%SFILE%" >nul 2>&1
  if errorlevel 1 (
    echo Error: Could not copy profile >&2
    exit /b 1
  )
  echo %~2>"%CUR%"
  echo Switched to profile %~2
  goto :eof
)

if /i "%~1"=="save" (
  if "%~2"=="" goto :show_usage
  if not exist "%SFILE%" (
    echo Error: No settings.json to save >&2
    exit /b 1
  )
  copy /Y "%SFILE%" "%PDIR%\%~2.json" >nul 2>&1
  if errorlevel 1 (
    echo Error: Could not save profile >&2
    exit /b 1
  )
  echo Profile %~2 saved
  echo **PATH TO NEWLY CREATED PROFILE**: %PDIR%\%~2.json
  goto :eof
)

if /i "%~1"=="rm" (
  if "%~2"=="" goto :show_usage
  if not exist "%PDIR%\%~2.json" (
    echo Error: Profile %~2 does not exist >&2
    exit /b 1
  )
  del "%PDIR%\%~2.json" >nul 2>&1
  if errorlevel 1 (
    echo Error: Could not delete profile >&2
    exit /b 1
  )
  if exist "%CUR%" (
    findstr /X "%~2" "%CUR%" >nul 2>&1 && del "%CUR%" >nul 2>&1
  )
  echo Profile %~2 removed
  goto :eof
)

:show_usage
echo Usage:
echo   ccswap ls                list profiles
echo   ccswap use  ^<name^>       switch to profile
echo   ccswap save ^<name^>       save current settings as profile
echo   ccswap rm   ^<name^>       delete profile
goto :eof