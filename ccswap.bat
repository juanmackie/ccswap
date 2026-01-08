@echo off
setlocal EnableExtensions EnableDelayedExpansion
:: ccswap – Claude-Code profile switcher for Windows
:: Version 2.0.0

set "PDIR=%USERPROFILE%\.claude\profiles"
set "SFILE=%USERPROFILE%\.claude\settings.json"
set "CUR=%PDIR%\_current.txt"
set "SCRIPT_DIR=%~dp0"
set "OAUTH_HELPER=%SCRIPT_DIR%ccswap_oauth.ps1"

if not exist "%PDIR%" mkdir "%PDIR%"

:: Handle commands
if "%~1"=="" goto :show_usage

if /i "%~1"=="oauth" (
  if /i "%~2"=="login" goto :oauth_login
  if /i "%~2"=="status" goto :oauth_status
  if /i "%~2"=="logout" goto :oauth_logout
  goto :oauth_usage
)

if /i "%~1"=="ls" (
  echo Profiles:
  for %%f in ("%PDIR%\*.json") do (
    set "n=%%~nf"
    set "indicator="
    :: Check if OAuth2 profile
    findstr /C:"auth_type" "%%f" >nul 2>&1
    if not errorlevel 1 (
      findstr /C:"\"auth_type\": \"oauth2\"" "%%f" >nul 2>&1
      if not errorlevel 1 set "indicator= [OAuth2]"
    )
    findstr /X "!n!" "%CUR%" >nul 2>&1 (
      echo   * !n!!indicator! ^(active^)
    ) || (
      echo     !n!!indicator!
    )
  )
  goto :eof
)

if /i "%~1"=="use" (
  if "%~2"=="" goto :show_usage
  if not exist "%PDIR%\%~2.json" (
    echo Error: Profile %~2 does not exist >&2
    exit /b 1
  )

  :: Backup current settings
  if exist "%SFILE%" (
    set "BACKUP=%PDIR%\_backup_%date:~10,4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%.json"
    set "BACKUP=!BACKUP: =0!"
    copy /Y "%SFILE%" "!BACKUP!" >nul 2>&1
    echo Backed up current settings to: !BACKUP!
  )

  :: Check if OAuth2 profile
  findstr /C:"\"auth_type\": \"oauth2\"" "%PDIR%\%~2.json" >nul 2>&1
  if not errorlevel 1 (
    echo Profile %~2 uses OAuth2 authentication

    :: Check for token file
    set "TOKEN_FILE=%PDIR%\%~2_tokens.enc"
    if not exist "!TOKEN_FILE!" (
      echo Error: No OAuth tokens found
      echo Run 'ccswap oauth login %~2' to authenticate
      exit /b 1
    )

    :: Prompt for password and process OAuth profile
    call :use_oauth_profile "%~2" "!TOKEN_FILE!"
    exit /b !errorlevel!
  )

  :: Regular API key profile
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

  :: Copy settings to profile
  copy /Y "%SFILE%" "%PDIR%\%~2.json" >nul 2>&1
  if errorlevel 1 (
    echo Error: Could not save profile >&2
    exit /b 1
  )

  :: If current profile is OAuth2, copy token file
  if exist "%CUR%" (
    set /p ACTIVE=<"%CUR%"
    set "ACTIVE_PROF=%PDIR%\!ACTIVE!.json"
    set "ACTIVE_TOK=%PDIR%\!ACTIVE!_tokens.enc"

    findstr /C:"\"auth_type\": \"oauth2\"" "!ACTIVE_PROF!" >nul 2>&1
    if not errorlevel 1 (
      if exist "!ACTIVE_TOK!" (
        copy /Y "!ACTIVE_TOK!" "%PDIR%\%~2_tokens.enc" >nul 2>&1
        echo Note: OAuth2 credentials copied to new profile
      )
    )
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

  :: Also delete token file if exists
  set "TOKEN_FILE=%PDIR%\%~2_tokens.enc"
  if exist "!TOKEN_FILE!" (
    del "!TOKEN_FILE!" >nul 2>&1
    echo OAuth2 tokens also deleted
  )

  if exist "%CUR%" (
    findstr /X "%~2" "%CUR%" >nul 2>&1 && del "%CUR%" >nul 2>&1
  )
  echo Profile %~2 removed
  goto :eof
)

:show_usage
echo Usage:
echo   ccswap ls                      list profiles
echo   ccswap use  ^<name^>             switch to profile
echo   ccswap save ^<name^>             save current settings as profile
echo   ccswap rm   ^<name^>             delete profile
echo   ccswap oauth login ^<name^>     authenticate profile with OAuth2
echo   ccswap oauth status ^<name^>    show OAuth2 token status
echo   ccswap oauth logout ^<name^>    remove OAuth2 credentials
goto :eof

:oauth_usage
echo Usage: ccswap oauth ^<login^|status^|logout^> ^<profile^>
echo.
echo Commands:
echo   login    Authenticate profile with OAuth2
echo   status   Show OAuth2 token status
echo   logout   Remove OAuth2 credentials
exit /b 1

:oauth_login
if "%~3"=="" (
  echo Error: Profile name required
  echo Usage: ccswap oauth login ^<profile^>
  exit /b 1
)

if not exist "%PDIR%\%~3.json" (
  echo Error: Profile %~3 not found
  exit /b 1
)

powershell -ExecutionPolicy Bypass -File "%OAUTH_HELPER%" -Action login -Profile "%~3"
exit /b %errorlevel%

:oauth_status
if "%~3"=="" (
  echo Error: Profile name required
  echo Usage: ccswap oauth status ^<profile^>
  exit /b 1
)

powershell -ExecutionPolicy Bypass -File "%OAUTH_HELPER%" -Action status -Profile "%~3"
exit /b %errorlevel%

:oauth_logout
if "%~3"=="" (
  echo Error: Profile name required
  echo Usage: ccswap oauth logout ^<profile^>
  exit /b 1
)

powershell -ExecutionPolicy Bypass -File "%OAUTH_HELPER%" -Action logout -Profile "%~3"
exit /b %errorlevel%

:use_oauth_profile
set "PROFILE_NAME=%~1"
set "TOKEN_FILE=%~2"

:: Prompt for password
set /p "PWD=Enter password for OAuth tokens: "

:: Use PowerShell to decrypt tokens, refresh if needed, and get access token
for /f "delims=" %%a in ('powershell -NoProfile -Command "^
  $ErrorActionPreference = 'Stop'; ^
  $profileFile = Join-Path $env:USERPROFILE '.claude\profiles\%PROFILE_NAME%.json'; ^
  $tokenFile = '%TOKEN_FILE%'; ^
  $password = '%PWD%'; ^
  & '%SCRIPT_DIR%ccswap_oauth.ps1' -Action refresh -Profile '%PROFILE_NAME%' -Password $password 2^>$null; ^
  if ($?) { ^
    $tempTokens = [System.IO.Path]::GetTempFileName(); ^
    if (& '%SCRIPT_DIR%ccswap_oauth.ps1' -Action status -Profile '%PROFILE_NAME%' -Password $password 2^>&1 ^| Select-String 'Active' ^| Measure-Object).Count -gt 0 { ^
      $encrypted = Get-Content $tokenFile -Raw -ByteArray; ^
      $salt = $encrypted[0..15]; ^
      $data = $encrypted[16..($encrypted.Length-1)]; ^
      $pbkdf2 = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($password, $salt, 100000); ^
      $key = $pbkdf2.GetBytes(32); $iv = $pbkdf2.GetBytes(16); ^
      $aes = [System.Security.Cryptography.Aes]::Create(); ^
      $aes.Key = $key; $aes.IV = $iv; ^
      $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC; ^
      $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7; ^
      $dec = $aes.CreateDecryptor(); ^
      $plaintext = $dec.TransformFinalBlock($data, 0, $data.Length); ^
      $json = [System.Text.Encoding]::UTF8.GetString($plaintext); ^
      $tokens = $json ^| ConvertFrom-Json; ^
      Write-Output $tokens.access_token; ^
    } else { ^
      Write-Error 'Token expired or invalid'; exit 1; ^
    }; ^
  } else { ^
    Write-Error 'Token refresh failed'; exit 1; ^
  }"') do set "ACCESS_TOKEN=%%a"

if errorlevel 1 (
  echo Error: Failed to decrypt tokens ^(wrong password?^)
  exit /b 1
)

:: Create temp settings with access token
set "TEMP_SETTINGS=%PDIR%\_temp_settings.json"
powershell -Command "$json = Get-Content '%PDIR%\%PROFILE_NAME%.json' ^| ConvertFrom-Json; $json.env.ANTHROPIC_AUTH_TOKEN = '%ACCESS_TOKEN%'; $json ^| ConvertTo-Json ^| Out-File '%TEMP_SETTINGS%'"

if exist "%TEMP_SETTINGS%" (
  copy /Y "%TEMP_SETTINGS%" "%SFILE%" >nul 2>&1
  del "%TEMP_SETTINGS%"
  echo %PROFILE_NAME%>"%CUR%"
  echo Switched to OAuth2 profile: %PROFILE_NAME%
  exit /b 0
) else (
  echo Error: Failed to process OAuth2 profile
  exit /b 1
)
