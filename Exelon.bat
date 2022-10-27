:: Copyright (C) 2022-present Exelon Labs
::
:: Exelon is not open-source and any commercial use will be punished

shift /0
@echo off
title Exelon
echo off & cls
mode 100, 30

SETLOCAL EnableDelayedExpansion
for /F "tokens=1,2 delims=#" %%a in ('"prompt #$H#$E# & echo on & for %%b in (1) do rem"') do (
  set "DEL=%%a"
cls
)

:: Directories
mkdir C:\Exelon >nul 2>&1
mkdir C:\Exelon\Resources >nul 2>&1
mkdir C:\Exelon\ExelonRevert >nul 2>&1
mkdir C:\Exelon\Drivers >nul 2>&1
cd C:\Exelon

:welcomescreen
cls
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo.
echo                                      [38;5;55m_____          [0m_             
echo                                     [38;5;55m^| ____^|_  _____[0m^| ^| ___  _ __  
echo                                     [38;5;55m^|  _^| \ \/ / _ \ [0m^|/ _ \^| '_ \ 
echo                                     [38;5;55m^| ^|___ ^>  ^<  __/ [0m^| (_) ^| ^| ^| ^|
echo                                     [38;5;55m^|_____/_/\_\___[0m^|_^|\___/^|_^| ^|_^|
echo.
echo                                        Constructed by [38;5;55mExelon Labs[0m 
echo                                 Copyright [38;5;34m(C) [0m2022-present [38;5;55mExelon Labs 
echo                                          [90;40mVersion 2.1 10/27/22 [38;5;0m
timeout /t 3 /nobreak

:starthw
mode 100, 25
cls
echo.
echo                                      [38;5;55m_____          [0m_             
echo                                     [38;5;55m^| ____^|_  _____[0m^| ^| ___  _ __  
echo                                     [38;5;55m^|  _^| \ \/ / _ \ [0m^|/ _ \^| '_ \ 
echo                                     [38;5;55m^| ^|___ ^>  ^<  __/ [0m^| (_) ^| ^| ^| ^|
echo                                     [38;5;55m^|_____/_/\_\___[0m^|_^|\___/^|_^| ^|_^|
echo.
echo                        Select category with [38;5;55m[A][0m ^& [38;5;55m[D][0m and press [38;5;55m[X][0m to proceed
echo.
echo.
echo.
echo.
echo.
echo           [38;5;55mHARDWARE       [38;5;55m^|       [0mNetwork       [38;5;55m^|       [0mLatency       [38;5;55m^|      [0mClean ^& Debloat              
choice /c:adx /n /m "%BS% ~
set MenuItem=%errorlevel%

if "%MenuItem%"=="1" goto startcd
if "%MenuItem%"=="2" goto startnet
if "%MenuItem%"=="3" goto hardware

:startnet
mode 100, 25
cls
echo.
echo                                      [38;5;55m_____          [0m_             
echo                                     [38;5;55m^| ____^|_  _____[0m^| ^| ___  _ __  
echo                                     [38;5;55m^|  _^| \ \/ / _ \ [0m^|/ _ \^| '_ \ 
echo                                     [38;5;55m^| ^|___ ^>  ^<  __/ [0m^| (_) ^| ^| ^| ^|
echo                                     [38;5;55m^|_____/_/\_\___[0m^|_^|\___/^|_^| ^|_^|
echo.
echo                        Select category with [38;5;55m[A][0m ^& [38;5;55m[D][0m and press [38;5;55m[X][0m to proceed
echo                             [0mThe process after picking it will be [38;5;52mAUTOMATIC 
echo.
echo.
echo.
echo.
echo           [0mHardware       [38;5;55m^|       [38;5;55mNETWORK       [38;5;55m^|       [0mLatency       [38;5;55m^|      [0mClean ^& Debloat              
choice /c:adx /n /m "%BS% ~
set MenuItem=%errorlevel%

if "%MenuItem%"=="1" goto starthw
if "%MenuItem%"=="2" goto startlatency
if "%MenuItem%"=="3" goto network

:startlatency
mode 100, 25
cls
echo.
echo                                      [38;5;55m_____          [0m_             
echo                                     [38;5;55m^| ____^|_  _____[0m^| ^| ___  _ __  
echo                                     [38;5;55m^|  _^| \ \/ / _ \ [0m^|/ _ \^| '_ \ 
echo                                     [38;5;55m^| ^|___ ^>  ^<  __/ [0m^| (_) ^| ^| ^| ^|
echo                                     [38;5;55m^|_____/_/\_\___[0m^|_^|\___/^|_^| ^|_^|
echo.
echo                        Select category with [38;5;55m[A][0m ^& [38;5;55m[D][0m and press [38;5;55m[X][0m to proceed
echo.
echo.
echo.
echo.
echo.
echo           [0mHardware       [38;5;55m^|       [0mNetwork       [38;5;55m^|       [38;5;55mLATENCY       [38;5;55m^|      [0mClean ^& Debloat              
choice /c:adx /n /m "%BS% ~
set MenuItem=%errorlevel%

if "%MenuItem%"=="1" goto startnet
if "%MenuItem%"=="2" goto startcd
if "%MenuItem%"=="3" goto latency

:startcd
mode 100, 25
cls
echo.
echo                                      [38;5;55m_____          [0m_             
echo                                     [38;5;55m^| ____^|_  _____[0m^| ^| ___  _ __  
echo                                     [38;5;55m^|  _^| \ \/ / _ \ [0m^|/ _ \^| '_ \ 
echo                                     [38;5;55m^| ^|___ ^>  ^<  __/ [0m^| (_) ^| ^| ^| ^|
echo                                     [38;5;55m^|_____/_/\_\___[0m^|_^|\___/^|_^| ^|_^|
echo.
echo                        Select category with [38;5;55m[A][0m ^& [38;5;55m[D][0m and press [38;5;55m[X][0m to proceed
echo.
echo.
echo.
echo.
echo.
echo           [0mHardware       [38;5;55m^|       [0mNetwork       [38;5;55m^|       [0mLatency       [38;5;55m^|      [38;5;55mCLEAN ^& DEBLOAT              
choice /c:adx /n /m "%BS% ~
set MenuItem=%errorlevel%

if "%MenuItem%"=="1" goto startlatency
if "%MenuItem%"=="2" goto starthw
if "%MenuItem%"=="3" goto cd

:hardware
mode 100, 25
cls
echo        [38;5;0m"  [38;5;55m_   _               _                          [0m____            _   _              [38;5;0m"
echo        [38;5;0m" [38;5;55m| | | | __ _ _ __ __| |_      ____ _ _ __ ___  [0m/ ___|  ___  ___| |_(_) ___  _ __   [38;5;0m"
echo        [38;5;0m" [38;5;55m| |_| |/ _` | '__/ _` \ \ /\ / / _` | '__/ _ \ [0m\___ \ / _ \/ __| __| |/ _ \| '_ \  [38;5;0m"
echo        [38;5;0m" [38;5;55m|  _  | (_| | | | (_| |\ V  V / (_| | | |  __/  [0m___) |  __/ (__| |_| | (_) | | | | [38;5;0m"
echo        [38;5;0m" [38;5;55m|_| |_|\__,_|_|  \__,_| \_/\_/ \__,_|_|  \___| [0m|____/ \___|\___|\__|_|\___/|_| |_| [38;5;0m"
echo.
echo             [0m[ [38;5;55m1 [0m] Disable C-States                       [0m[ [38;5;55m4 [0m] Memory Optimisation
echo                [38;5;236mKeep CPU at C0 stopping throttling,         [38;5;236mOptimizes your fsutil, win
echo                 will make PC generate more heat             startup settings etc.
echo.
echo             [0m[ [38;5;55m2 [0m] SvcHostSplitThreshold                  [0m[ [38;5;55m5 [0m] MSI Mode
echo                [38;5;236mChanges the split threshold for             [38;5;236mEnable MSI Mode for gpu and
echo                  service host to your RAM                   network adapters
echo.
echo             [0m[ [38;5;55m3 [0m] Affinity                               [0m[ [38;5;55m6 [0m] Power Plan
echo                [38;5;236mThis tweak will spread devices              [38;5;236mAllows hardware to take more 
echo                  on multiple CPU cores                      power. Not good for batteries
echo                                              [38;5;55m----------
echo. 
echo             [0m[ [38;5;55mC [0m] CPU                                    [0m[ [38;5;55mG [0m] GPU
echo               [38;5;236mSpecial tweaks for Intel/                    [38;5;236mSpecial tweaks for NVidia/
echo                 AMD CPUs                                    Radeon Graphics Cards
echo.
echo                                             [0m[ [38;5;55mR [0m] Return
choice /c:123456CGR /n /m "%BS% ~
set MenuItem=%errorlevel%

if "%MenuItem%"=="1" goto cstates
if "%MenuItem%"=="2" goto shst
if "%MenuItem%"=="3" goto affinity
if "%MenuItem%"=="4" goto mo
if "%MenuItem%"=="5" goto msi
if "%MenuItem%"=="6" goto powerplan
if "%MenuItem%"=="7" goto cpu
if "%MenuItem%"=="8" goto gpu
if "%MenuItem%"=="9" goto starthw

:cstates
cls
Reg add "HKLM\SYSTEM\ControlSet001\Control\Class\{4D36E968-E325-11CE-BFC1-08002BE10318}\0000" /v "AllowDeepCStates" /t REG_DWORD /d "0" /f >nul 2>&1
goto hardware

:msi
	for /f %%g in ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do Reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >nul 2>&1
	for /f %%g in ('wmic path win32_VideoController get PNPDeviceID ^| findstr /L "VEN_"') do Reg add "HKLM\System\CurrentControlSet\Enum\%%g\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority" /t REG_DWORD /d "3" /f >nul 2>&1
	for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do Reg add "HKLM\SYSTEM\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties" /v "MSISupported" /t REG_DWORD /d "1" /f >nul 2>&1
	for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID ^| findstr /L "VEN_"') do Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePriority " /t REG_DWORD /d "3" /f >nul 2>&1
goto hardware

:mo
	::Disable Background apps
	Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t Reg_DWORD /d "1" /f
	Reg add "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t Reg_DWORD /d "2" /f
	Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t Reg_DWORD /d "0" /f
	::Disallow drivers to get paged into virtual memory
	Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t Reg_DWORD /d "1" /f
	::Disable Paging Combining
	Reg add "HKLM\SYSTEM\currentcontrolset\control\session manager\Memory Management" /v "DisablePagingCombining" /t Reg_DWORD /d "1" /f
	::Use Large System Cache to improve microstuttering
	Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t Reg_DWORD /d "1" /f
	::Unload .dll to Free Memory
	Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "AlwaysUnloadDLL" /t REG_DWORD /d "1" /f
	::Free unused ram
	Reg add "HKLM\System\CurrentControlSet\Control\Session Manager" /v "HeapDeCommitFreeBlockThreshold" /t REG_DWORD /d "262144" /f
	::Auto restart Powershell on error
	Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoRestartShell" /t REG_DWORD /d "1" /f
	::Disk Optimizations
	Reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "DontVerifyRandomDrivers" /t REG_DWORD /d "1" /f
	Reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d "0" /f
	::Disable Memory Compression
	powershell -NoProfile -Command "Disable-MMAgent -mc"
	::Disable Prefetch
	Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t Reg_DWORD /d "0" /f
	Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t Reg_DWORD /d "0" /f
	::Disable Hibernation + Fast Startup
	Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f
	Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabledDefault" /t REG_DWORD /d "0" /f
	Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f
	::Wait time to kill app during shutdown
	Reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t Reg_SZ /d "1000" /f
	::Wait to end service at shutdown
	Reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t Reg_SZ /d "1000" /f
	::Wait to kill non-responding app
	Reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t Reg_SZ /d "1000" /f
	::fsutil
	if exist "%windir%\System32\fsutil.exe" (
		::Raise the limit of paged pool memory
		fsutil behavior set memoryusage 2
		::https://www.serverbrain.org/solutions-2003/the-mft-zone-can-be-optimized.html
		fsutil behavior set mftzone 2
		::Disable Last Access information on directories, performance/privacy
		fsutil behavior set disablelastaccess 1
		::Disable Virtual Memory Pagefile Encryption
		fsutil behavior set encryptpagingfile 0
		::Disables the creation of legacy 8.3 character-length file names on FAT- and NTFS-formatted volumes.
		fsutil behavior set disable8dot3 1
		::Disable NTFS compression
		fsutil behavior set disablecompression 1
		::Enable Trim
		fsutil behavior set disabledeletenotify 0
	)
goto hardware

:shst
cls
for /f "tokens=2 delims==" %%i in ('wmic os get TotalVisibleMemorySize /value') do set /a mem=%%i + 1024000
Reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d %mem% /f >nul 2>&1
goto hardware

:affinity
for /f "tokens=*" %%f in ('wmic cpu get NumberOfCores /value ^| find "="') do set %%f
for /f "tokens=*" %%f in ('wmic cpu get NumberOfLogicalProcessors /value ^| find "="') do set %%f

if "%NumberOfCores%"=="2" (cls
	echo Affinity won't work on 2-core CPUs
	pause && goto Tweaks
)

if %NumberOfCores% gtr 4 (
	for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
		Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "3" /f >nul 2>&1
		Reg delete "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /f >nul 2>&1
	)
	for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
		Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "5" /f >nul 2>&1
		Reg delete "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /f >nul 2>&1
	)
	goto Tweaks
)

if %NumberOfLogicalProcessors% gtr %NumberOfCores% (
::You have HyperThreading Enabled!
	for /f %%i in ('wmic path Win32_USBController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
		Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f >nul 2>&1
		Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "C0" >nul 2>&1
	)
	for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
		Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f >nul 2>&1
		Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "C0" /f >nul 2>&1
	)
	for /f %%i in ('wmic path Win32_NetworkAdapter get PNPDeviceID^| findstr /l "PCI\VEN_"') do (
		Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "DevicePolicy" /t REG_DWORD /d "4" /f >nul 2>&1
		Reg add "HKLM\System\CurrentControlSet\Enum\%%i\Device Parameters\Interrupt Management\Affinity Policy" /v "AssignmentSetOverride" /t REG_BINARY /d "30" /f >nul 2>&1
	)
goto hardware

:powerplan
::Import Windows Ultimate PowerPlan
powercfg /delete 88888888-8888-8888-8888-888888888888 >nul 2>&1
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 88888888-8888-8888-8888-888888888888 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
powercfg /setactive 88888888-8888-8888-8888-888888888888 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
::Import Pow Under 9
powercfg /delete 99999999-9999-9999-9999-999999999999 >nul 2>&1
powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 99999999-9999-9999-9999-999999999999 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
powercfg /setactive 99999999-9999-9999-9999-999999999999 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
powercfg /delete 88888888-8888-8888-8888-888888888888 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
set ExelonPowName=Exelon
rem powercfg /powerthrottling disable /path "%temp%\EchoPow.pow" >nul 2>&1
echo Power Plan

::Require a password on wakeup: OFF
powercfg -setacvalueindex scheme_current sub_none 0E796BDB-100D-47D6-A2D5-F7D2DAA51F51 0

::Allow Throttle States: OFF
powercfg /setacvalueindex scheme_current sub_processor 3b04d4fd-1cc7-4f23-ab1c-d1337819c4bb 0

::USB 3 Link Power Management: OFF 
powercfg -setacvalueindex scheme_current 2a737441-1930-4402-8d77-b2bebba308a3 d4e98f31-5ffe-4ce1-be31-1b38b384c009 0

::Device Idle Policy Power Savings
powercfg -setacvalueindex scheme_current sub_none 4faab71a-92e5-4726-b531-224559672d19 1 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"

::Device Idle Policy Performance
powercfg -setacvalueindex scheme_current sub_none 4faab71a-92e5-4726-b531-224559672d19 0 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"

if "%Idle%"=="0x1" (
set ExelonPowName=%ExelonPowName% Dildo
::Disable Idle
powercfg /setacvalueindex scheme_current sub_processor 5d76a2ca-e8c0-402f-a133-2158492d58ad 1 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
echo Disable Idle
) else (
::Enable Idle
powercfg -setacvalueindex scheme_current sub_processor 5d76a2ca-e8c0-402f-a133-2158492d58ad 0 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
echo Enable Idle
)

if "%MaxPow%"=="0x1" (
set ExelonPowName=%ExelonPowName% MAX
::1/1 Increase Decrease
powercfg -setacvalueindex scheme_current sub_processor 06cadf0e-64ed-448a-8927-ce7bf90eb35d 1 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
powercfg -setacvalueindex scheme_current sub_processor 12a0ab44-fe28-4fa9-b3bd-4b64f44960a6 1 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
echo 1/1 Increase Decrease
::100/100 Promote Demote
powercfg -setacvalueindex scheme_current sub_processor 7b224883-b3cc-4d79-819f-8374152cbe7c 100 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
powercfg -setacvalueindex scheme_current sub_processor 4b92d758-5a24-4851-a470-815d78aee119 100 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
echo 100/100 Promote Demote
) else (
::30/10 Increase Decrease
powercfg -setacvalueindex scheme_current sub_processor 06cadf0e-64ed-448a-8927-ce7bf90eb35d 30 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
powercfg -setacvalueindex scheme_current sub_processor 12a0ab44-fe28-4fa9-b3bd-4b64f44960a6 10 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
echo 30/10 Increase Decrease
::60/40 Promote Demote
powercfg -setacvalueindex scheme_current sub_processor 7b224883-b3cc-4d79-819f-8374152cbe7c 60 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
powercfg -setacvalueindex scheme_current sub_processor 4b92d758-5a24-4851-a470-815d78aee119 40 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
echo 60/40 Promote Demote
)

::Apply
powercfg -setactive scheme_current >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
powercfg /changename scheme_current "%ExelonPowName%" "Constructed by Exelon. (C) Exelon Labs 2022" >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"

if "%Throttling%"=="0x1" (
::Enable Power Throttling
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
Reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
echo Enable Power Throttling
) else (
::Disable Power Throttling
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t Reg_DWORD /d "1" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
echo Disable Power Throttling
)
goto hardware

:network
cls
rem Reg add "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /v "a" /t REG_DWORD /d "0" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt" 

Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPerServer" /t REG_DWORD /d "16" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt" 
::Maximum number of HTTP 1.0 connections to a Web server
Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "MaxConnectionsPer1_0Server" /t REG_DWORD /d "16" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt" 

Reg add "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "0200" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt" 
Reg add "HKLM\System\CurrentControlSet\Control\Nsi\{eb004a03-9b1a-11d4-9123-0050047759bc}\0" /v "1700" /t REG_BINARY /d "0000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000ff000000000000000000000000000000000000000000ff000000000000000000000000000000" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt" 

Reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "EnableAutoDoh" /t REG_DWORD /d "2" /f >nul 2>&1

Reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t Reg_DWORD /d "1" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
Reg add "HKLM\System\CurrentControlSet\Services\AFD\Parameters" /v "DoNotHoldNicBuffers" /t Reg_DWORD /d "1" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"

Reg add "HKLM\Software\Policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t Reg_DWORD /d "0" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
Reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t Reg_DWORD /d "1" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"

Reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t Reg_DWORD /d "0" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"

Reg add "HKLM\Software\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"

Reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t Reg_DWORD /d "10" /f >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"

::Netsh
netsh int tcp set supplemental Internet congestionprovider=ctcp >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
netsh int tcp set heuristics disabled >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"
netsh int tcp set global rss=enabled autotuninglevel=normal initialRto=2000 rsc=disabled ^
dca=enabled netdma=disabled ecncapability=enabled timestamps=disabled ^
nonsackrttresiliency=disabled MaxSynRetransmissions=2 >>"%temp%\ExelonLog.txt" 2>>"%temp%\ExelonError.txt"

for /f "tokens=3*" %%s in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkCards" /f "ServiceName" /s^|findstr /i /l "ServiceName"') do (
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
 	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
 	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
	reg.add "HKLM\SYSTEM\CurrentControlSet\Services\Psched\Parameters\Adapters\%%s" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "TcpInitialRTT" /t REG_DWORD /d "0" /f 
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%s" /v "DeadGWDetectDefault" /t REG_DWORD /d "1" /f
)
Reg.exe add "HKLM\System\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "MIMOPowerSaveMode" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\System\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "PowerSavingMode" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "*EEE" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0001" /v "PnPCapabilities" /t REG_DWORD /d "24" /f
Reg.exe add "HKLM\System\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0002" /v "MIMOPowerSaveMode" /t REG_SZ /d "3" /f
Reg.exe add "HKLM\System\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0002" /v "PowerSavingMode" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0002" /v "EnableGreenEthernet" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0002" /v "*EEE" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\System\ControlSet001\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}\0002" /v "PnPCapabilities" /t REG_DWORD /d "24" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUDiscovery" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableICMPRedirect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnablePMTUBHDetect" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxConnectRetransmissions" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "UseDelayedAcceptance" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MaxSockAddrLength" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Winsock" /v "MinSockAddrLength" /t REG_DWORD /d "16" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NegativeSOACacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "NetFailureCacheTime" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
cls
goto startnet

:cpu
cls
mode 100, 25
echo.
echo                  [38;5;0m"  [38;5;55m____  _      _                                [0m____ ____  _   _   [38;5;0m"
echo                  [38;5;0m" [38;5;55m|  _ \(_) ___| | __  _   _  ___  [0m_   _ _ __   / ___|  _ \| | | | [38;5;0m"
echo                  [38;5;0m" [38;5;55m| |_) | |/ __| |/ / | | | |/ _ \[0m| | | | '__| | |   | |_) | | | | [38;5;0m"
echo                  [38;5;0m" [38;5;55m|  __/| | (__|   <  | |_| | (_) | [0m|_| | |    | |___|  __/| |_| | [38;5;0m"
echo                  [38;5;0m" [38;5;55m|_|   |_|\___|_|\_\  \__, |\___/ [0m\__,_|_|     \____|_|    \___/  [38;5;0m"
echo                  [38;5;0m"                      [38;5;55m|___/                                       [38;5;0m"
echo.
echo                           [0mSelect GPU with [38;5;55m[A][0m ^& [38;5;55m[D][0m and press [38;5;55m[X][0m to proceed
echo.
echo.
echo.
echo.
echo.
echo.
echo                                         [38;5;55mAMD      [38;5;55m^|      [0mINTEL
echo.
echo.
echo.
echo.
echo.
echo.
echo                                          [97;40mPress [97;40m[[38;5;55mR[97;40m] to Return
echo. 
choice /c:adxr /n /m "%BS% ~0
set MenuItem=%errorlevel%

if "%MenuItem%"=="1" goto cpu1
if "%MenuItem%"=="2" goto cpu1
if "%MenuItem%"=="3" goto AMD
if "%MenuItem%"=="4" goto hardware

:cpu1
cls
mode 100, 25
echo.
echo                  [38;5;0m"  [38;5;55m____  _      _                                [0m____ ____  _   _   [38;5;0m"
echo                  [38;5;0m" [38;5;55m|  _ \(_) ___| | __  _   _  ___  [0m_   _ _ __   / ___|  _ \| | | | [38;5;0m"
echo                  [38;5;0m" [38;5;55m| |_) | |/ __| |/ / | | | |/ _ \[0m| | | | '__| | |   | |_) | | | | [38;5;0m"
echo                  [38;5;0m" [38;5;55m|  __/| | (__|   <  | |_| | (_) | [0m|_| | |    | |___|  __/| |_| | [38;5;0m"
echo                  [38;5;0m" [38;5;55m|_|   |_|\___|_|\_\  \__, |\___/ [0m\__,_|_|     \____|_|    \___/  [38;5;0m"
echo                  [38;5;0m"                      [38;5;55m|___/                                       [38;5;0m"
echo.
echo                           [0mSelect GPU with [38;5;55m[A][0m ^& [38;5;55m[D][0m and press [38;5;55m[X][0m to proceed
echo.
echo.
echo.
echo.
echo.
echo.
echo                                         [0mAMD      [38;5;55m^|      [38;5;55mINTEL
echo.
echo.
echo.
echo.
echo.
echo.
echo                                          [97;40mPress [97;40m[[38;5;55mR[97;40m] to Return
echo. 
choice /c:adxr /n /m "%BS% ~0
set MenuItem=%errorlevel%

if "%MenuItem%"=="1" goto cpu
if "%MenuItem%"=="2" goto cpu
if "%MenuItem%"=="3" goto Intel
if "%MenuItem%"=="4" goto hardware

:intel
@echo Disable HPET
bcdedit /deletevalue useplatformclock
@echo
@echo Disable dynamic tick (laptop power savings)
bcdedit /set disabledynamictick yes
@echo
@echo Disable synthetic timers
bcdedit /set useplatformtick yes
@echo
@echo Boot timeout 0
bcdedit /timeout 0
@echo
@echo Disable boot screen animation
bcdedit /set bootux disabled
@echo
@echo Speed up boot times
bcdedit /set bootmenupolicy standard
@echo
@echo Disable hyper virtualization
bcdedit /set hypervisorlaunchtype off
@echo
@echo Remove windows login logo
bcdedit /set quietboot yes
@echo
@echo
@echo Disable boot logo
bcdedit /set {globalsettings} custom:16000067 true
@echo
@echo Disable spinning animation
bcdedit /set {globalsettings} custom:16000069 true
@echo
@echo Disable boot messages
bcdedit /set {globalsettings} custom:16000068 true
cls
goto hardware

:amd
@echo Disable HPET
bcdedit /deletevalue useplatformclock
@echo
@echo Disable dynamic tick (laptop power savings)
bcdedit /set disabledynamictick yes
@echo
@echo Disable synthetic timers
bcdedit /set useplatformtick yes
@echo
@echo Boot timeout 0
bcdedit /timeout 0
@echo
@echo Disable nx
bcdedit /set nx optout
@echo
@echo Disable boot screen animation
bcdedit /set bootux disabled
@echo
@echo Speed up boot times
bcdedit /set bootmenupolicy standard
@echo
@echo Disable hyper virtualization
bcdedit /set hypervisorlaunchtype off
@echo
@echo Disable trusted platform module (TPM)
bcdedit /set tpmbootentropy ForceDisable
@echo
@echo Remove windows login logo
bcdedit /set quietboot yes
@echo
@echo
@echo Disable boot logo
bcdedit /set {globalsettings} custom:16000067 true
@echo
@echo Disable spinning animation
bcdedit /set {globalsettings} custom:16000069 true
@echo
@echo Disable boot messages
bcdedit /set {globalsettings} custom:16000068 true
@echo
cls
goto hardware

:gpu
cls
mode 100, 25
echo.
echo                  [38;5;0m"  [38;5;55m____  _      _                                [0m____ ____  _   _  [38;5;0m"
echo                  [38;5;0m" [38;5;55m|  _ \(_) ___| | __  _   _  ___  [0m_   _ _ __   / ___|  _ \| | | | [38;5;0m"
echo                  [38;5;0m" [38;5;55m| |_) | |/ __| |/ / | | | |/ _ \[0m| | | | '__| | |  _| |_) | | | | [38;5;0m"
echo                  [38;5;0m" [38;5;55m|  __/| | (__|   <  | |_| | (_) | [0m|_| | |    | |_| |  __/| |_| | [38;5;0m"
echo                  [38;5;0m" [38;5;55m|_|   |_|\___|_|\_\  \__, |\___/ [0m\__,_|_|     \____|_|    \___/  [38;5;0m"
echo                  [38;5;0m"                      [38;5;55m|___/                                       [38;5;0m"
echo.
echo                           [0mSelect GPU with [38;5;55m[A][0m ^& [38;5;55m[D][0m and press [38;5;55m[X][0m to proceed
echo.
echo.
echo.
echo.
echo.
echo.
echo                              [38;5;55mNVIDIA      [38;5;55m^|      [0mRADEON      [38;5;55m^|      [0mINTEL
echo.
echo.
echo.
echo.
echo.
echo.
echo                                          [97;40mPress [97;40m[[38;5;55mR[97;40m] to Return
echo. 
choice /c:adxr /n /m "%BS% ~0
set MenuItem=%errorlevel%

if "%MenuItem%"=="1" goto gpu2
if "%MenuItem%"=="2" goto gpu1
if "%MenuItem%"=="3" goto nvidia
if "%MenuItem%"=="4" goto hardware

:gpu1
cls
mode 100, 25
echo.
echo                  [38;5;0m"  [38;5;55m____  _      _                                [0m____ ____  _   _  [38;5;0m"
echo                  [38;5;0m" [38;5;55m|  _ \(_) ___| | __  _   _  ___  [0m_   _ _ __   / ___|  _ \| | | | [38;5;0m"
echo                  [38;5;0m" [38;5;55m| |_) | |/ __| |/ / | | | |/ _ \[0m| | | | '__| | |  _| |_) | | | | [38;5;0m"
echo                  [38;5;0m" [38;5;55m|  __/| | (__|   <  | |_| | (_) | [0m|_| | |    | |_| |  __/| |_| | [38;5;0m"
echo                  [38;5;0m" [38;5;55m|_|   |_|\___|_|\_\  \__, |\___/ [0m\__,_|_|     \____|_|    \___/  [38;5;0m"
echo                  [38;5;0m"                      [38;5;55m|___/                                       [38;5;0m"
echo.
echo                           [0mSelect GPU with [38;5;55m[A][0m ^& [38;5;55m[D][0m and press [38;5;55m[X][0m to proceed
echo.
echo.
echo.
echo.
echo.
echo.
echo                              [0mNVIDIA      [38;5;55m^|      [38;5;55mRADEON      [38;5;55m^|      [0mINTEL
echo.
echo.
echo.
echo.
echo.
echo.
echo                                          [97;40mPress [97;40m[[38;5;55mR[97;40m] to Return
echo. 
choice /c:adxr /n /m "%BS% ~0
set MenuItem=%errorlevel%

if "%MenuItem%"=="1" goto gpu
if "%MenuItem%"=="2" goto gpu2
if "%MenuItem%"=="3" goto radeon
if "%MenuItem%"=="4" goto hardware

:gpu2
cls
mode 100, 25
echo.
echo                  [38;5;0m"  [38;5;55m____  _      _                                [0m____ ____  _   _  [38;5;0m"
echo                  [38;5;0m" [38;5;55m|  _ \(_) ___| | __  _   _  ___  [0m_   _ _ __   / ___|  _ \| | | | [38;5;0m"
echo                  [38;5;0m" [38;5;55m| |_) | |/ __| |/ / | | | |/ _ \[0m| | | | '__| | |  _| |_) | | | | [38;5;0m"
echo                  [38;5;0m" [38;5;55m|  __/| | (__|   <  | |_| | (_) | [0m|_| | |    | |_| |  __/| |_| | [38;5;0m"
echo                  [38;5;0m" [38;5;55m|_|   |_|\___|_|\_\  \__, |\___/ [0m\__,_|_|     \____|_|    \___/  [38;5;0m"
echo                  [38;5;0m"                      [38;5;55m|___/                                       [38;5;0m"
echo.
echo                           [0mSelect GPU with [38;5;55m[A][0m ^& [38;5;55m[D][0m and press [38;5;55m[X][0m to proceed
echo.
echo.
echo.
echo.
echo.
echo.
echo                              [0mNVIDIA      [38;5;55m^|      [0mRADEON      [38;5;55m^|      [38;5;55mINTEL
echo.
echo.
echo.
echo.
echo.
echo.
echo                                          [97;40mPress [97;40m[[38;5;55mR[97;40m] to Return
echo. 
choice /c:adxr /n /m "%BS% ~0
set MenuItem=%errorlevel%

if "%MenuItem%"=="1" goto gpu1
if "%MenuItem%"=="2" goto gpu
if "%MenuItem%"=="3" goto intel
if "%MenuItem%"=="4" goto hardware

:nvidia
	For /F "tokens=*" %%i in ('reg query "HKLM\SYSTEM\ControlSet001\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}" /t REG_SZ /s /e /f "NVIDIA" ^| findstr "HK"') do (
		Reg add "%%i" /v "DisableDynamicPstate" /t REG_DWORD /d "1" /f >nul 2>&1
	)
cls
Reg add "HKCU\Software\Exelon" /v "NvidiaTweaks" /f
::Enable Hardware Accelerated Scheduling
reg query "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" >nul 2>&1
if "%errorlevel%" equ "0" Reg add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t Reg_DWORD /d "2" /f
::Enable gdi hardware acceleration
for /f %%a in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class" /v "VgaCompatible" /s ^| findstr "HKEY"') do ( 
reg query "%%a" /v "KMD_EnableGDIAcceleration" >nul 2>&1
if "!errorlevel!" equ "0" Reg add "%%a" /v "KMD_EnableGDIAcceleration" /t Reg_DWORD /d "1" /f
)
::Enable GameMode
Reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t Reg_DWORD /d "1" /f
Reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t Reg_DWORD /d "1" /f
::FSO
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "1" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /t REG_DWORD /d "1" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /t REG_DWORD /d "2" /f
::Nvidia Reg
for /f %%a in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class" /v "VgaCompatible" /s ^| findstr "HKEY"') do ( Reg add "%%a" /v "TCCSupported" /t REG_DWORD /d "0" /f
)
Reg add "HKCU\Software\NVIDIA Corporation\Global\NVTweak\Devices\509901423-0\Color" /v "NvCplUseColorCorrection" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /t Reg_DWORD /d "1" /f
::Unrestricted Clocks
cd "%SystemDrive%\Program Files\NVIDIA Corporation\NVSMI\" >nul 2>&1
start "" /I /WAIT /B "nvidia-smi" -acp 0 >nul 2>&1
::Opt out of nvidia telemetry
reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /t Reg_DWORD /d "1" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "NvBackend" /f >nul 2>&1
::Disable GpuEnergyDrv
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t Reg_DWORD /d "4" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDr" /v "Start" /t Reg_DWORD /d "4" /f
::Disable Tiled Display
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableTiledDisplay" /t Reg_DWORD /d "0" /f
if exist "%windir%\system32\wbem\WMIC.exe" for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID') do (
set "str=%%i" & if "!str:PCI\VEN_=!" neq "!str!" for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\%%i" /v "Driver"') do Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%a" /v "EnableTiledDisplay" /t REG_DWORD /d "0" /f
)
::Disable Preemption
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemption" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableCudaContextPreemption" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableCEPreemption" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemptionOnS3S4" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "ComputePreemption" /t Reg_DWORD /d "0" /f
::Disable HDCP
for /f %%a in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class" /v "VgaCompatible" /s ^| findstr "HKEY"') do ( Reg add "%%a" /v "RMHdcpKeyglobZero" /t REG_DWORD /d "1" /f 
)
)>nul 2>&1 else (
Reg delete "HKCU\Software\Exelon" /v "NvidiaTweaks" /f
::Enable Hardware Accelerated Scheduling
reg query "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode"
if "%errorlevel%" equ "0" Reg add "HKLM\System\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchMode" /t Reg_DWORD /d "1" /f
::Disable gdi hardware acceleration
for /f %%a in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class" /v "VgaCompatible" /s ^| findstr "HKEY"') do ( 
reg query "%%a" /v "KMD_EnableGDIAcceleration" >nul 2>&1
if "!errorlevel!" equ "0" Reg delete "%%a" /v "KMD_EnableGDIAcceleration" /f
)
::Enable GameMode
Reg add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t Reg_DWORD /d "1" /f
Reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t Reg_DWORD /d "1" /f
::FSO
reg delete "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /f
reg delete "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehaviorMode" /f
reg delete "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /f
reg delete "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /f
reg delete "HKCU\System\GameConfigStore" /v "GameDVR_DXGIHonorFSEWindowsCompatible" /f
reg delete "HKCU\System\GameConfigStore" /v "GameDVR_EFSEFeatureFlags" /f
reg delete "HKCU\System\GameConfigStore" /v "GameDVR_DSEBehavior" /f
::Nvidia Reg
for /f %%a in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class" /v "VgaCompatible" /s ^| findstr "HKEY"') do ( Reg add "%%a" /v "TCCSupported" /t REG_DWORD /d "0" /f 
)
Reg delete "HKCU\Software\NVIDIA Corporation\Global\NVTweak\Devices\509901423-0\Color" /v "NvCplUseColorCorrection" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t Reg_DWORD /d "1" /f
Reg delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\NVTweak" /v "DisplayPowerSaving" /f
Reg delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableWriteCombining" /f
::Opt out of nvidia telemetry
reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /f
reg delete "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /f
reg delete "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /f
Reg delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" /v "EnableRID61684" /f
::Disable GpuEnergyDrv
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDrv" /v "Start" /t Reg_DWORD /d "2" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\GpuEnergyDr" /v "Start" /t Reg_DWORD /d "2" /f
::Disable Tiled Display
Reg delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableTiledDisplay" /f
if exist "%windir%\system32\wbem\WMIC.exe" for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID') do (
set "str=%%i" & if "!str:PCI\VEN_=!" neq "!str!" for /f "tokens=3" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Enum\%%i" /v "Driver"') do Reg delete "HKLM\SYSTEM\CurrentControlSet\Control\Class\%%a" /v "EnableTiledDisplay" /f
)
::Disable Preemption
Reg delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemption" /f
Reg delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisableCudaContextPreemption" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers\Scheduler" /v "EnablePreemption" /t Reg_DWORD /d "1" /f
Reg delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "EnableCEPreemption" /f
Reg delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "DisablePreemptionOnS3S4" /f
Reg delete "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm" /v "ComputePreemption" /f
::Disable HDCP
if exist "%windir%\system32\wbem\WMIC.exe" for /f %%i in ('wmic path Win32_VideoController get PNPDeviceID') do (
for /f %%a in ('Reg query "HKLM\SYSTEM\CurrentControlSet\Control\Class" /v "VgaCompatible" /s ^| findstr "HKEY"') do Reg add "%%a" /v "RMHdcpKeyglobZero" /t REG_DWORD /d "0" /f
)
)>nul 2>&1

if "%KBOOF%" equ "%COL%[91mOFF" (
	for /f %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class" /v "VgaCompatible" /s ^| findstr "HKEY"') do (
		Reg add "%%a" /v "PowerMizerEnable" /t REG_DWORD /d "1" /f >nul 2>&1
		Reg add "%%a" /v "PowerMizerLevel" /t REG_DWORD /d "1" /f >nul 2>&1
		Reg add "%%a" /v "PowerMizerLevelAC" /t REG_DWORD /d "1" /f >nul 2>&1
		Reg add "%%a" /v "PerfLevelSrc" /t REG_DWORD /d "8738" /f >nul 2>&1
	)
) else (
	for /f %%a in ('reg query "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Class" /v "VgaCompatible" /s ^| findstr "HKEY"') do (
		Reg delete "%%a" /v "PowerMizerEnable" /f >nul 2>&1
		Reg delete "%%a" /v "PowerMizerLevel" /f >nul 2>&1
		Reg delete "%%a" /v "PowerMizerLevelAC" /f >nul 2>&1
		Reg delete "%%a" /v "PerfLevelSrc" /f >nul 2>&1
	)
)

if "%NPIOF%" equ "%COL%[91mOFF" (
	Reg add "HKCU\Software\Exelon" /v NpiTweaks /f
	rmdir /S /Q "C:\Exelon\Resources\nvidiaProfileInspector\"
	curl -g -L -o C:\Exelon\Resources\nvidiaProfileInspector.zip "https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip"
	powershell -NoProfile Expand-Archive 'C:\Exelon\Resources\nvidiaProfileInspector.zip' -DestinationPath 'C:\Exelon\Resources\nvidiaProfileInspector\'
	del /F /Q "C:\Exelon\Resources\nvidiaProfileInspector.zip"
	curl -g -L -o "C:\Exelon\Resources\nvidiaProfileInspector\Latency_and_Performances_Settings_by_Exelon_Team2.nip" "https://raw.githubusercontent.com/auraside/ExelonCtrl/main/Files/Latency_and_Performances_Settings_by_Exelon_Team2.nip"
	cd "C:\Exelon\Resources\nvidiaProfileInspector\"
	nvidiaProfileInspector.exe "Latency_and_Performances_Settings_by_Exelon_Team2.nip" 
) >nul 2>&1 else (
::https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip
	Reg delete "HKCU\Software\Exelon" /v NpiTweaks /f
	rmdir /S /Q "C:\Exelon\Resources\nvidiaProfileInspector\"
	curl -g -L -o C:\Exelon\Resources\nvidiaProfileInspector.zip "https://github.com/Orbmu2k/nvidiaProfileInspector/releases/latest/download/nvidiaProfileInspector.zip"
	powershell -NoProfile Expand-Archive 'C:\Exelon\Resources\nvidiaProfileInspector.zip' -DestinationPath 'C:\Exelon\Resources\nvidiaProfileInspector\'
	del /F /Q "C:\Exelon\Resources\nvidiaProfileInspector.zip"
	curl -g -L -o "C:\Exelon\Resources\nvidiaProfileInspector\Base_Profile.nip" "https://raw.githubusercontent.com/auraside/ExelonCtrl/main/Files/Base_Profile.nip"
	cd "C:\Exelon\Resources\nvidiaProfileInspector\"
	nvidiaProfileInspector.exe "Base_Profile.nip"
) >nul 2>&1

Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d "384" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d "64000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxSOACacheEntryTtlLimit" /t REG_DWORD /d "301" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Clock Rate" /t REG_DWORD /d "2710" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\System\CurrentControlSet\Services\Tcpip\QoS" /v "Do not use NLA" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "4410" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostPriority" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f
Reg.exe add "HKLM\SYSTEM\ControlSet002\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\MSMQ\Parameters" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "10" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "26" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ8Priority" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "IRQ16Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Affinity" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Clock Rate" /t REG_DWORD /d "2710" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Low Latency" /v "Priority" /t REG_DWORD /d "2" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v "DisableCachingOfSSLPages" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion" /v "SmoothScroll" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKU\S-1-5-19\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKU\S-1-5-19\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKU\S-1-5-19\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
Reg.exe add "HKU\S-1-5-19\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKU\S-1-5-20\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f
Reg.exe add "HKU\S-1-5-20\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "1000" /f
Reg.exe add "HKU\S-1-5-20\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "8" /f
Reg.exe add "HKU\S-1-5-20\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "1000" /f
cls
goto hardware

:radeon
cls
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "3D_Refresh_Rate_Override_DEF" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "3to2Pulldown_NA" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AAF_NA" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "Adaptive De-interlacing" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowRSOverlay" /t Reg_SZ /d "false" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSkins" /t Reg_SZ /d "false" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSnapshot" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AllowSubscription" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AntiAlias_NA" /t Reg_SZ /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AreaAniso_NA" /t Reg_SZ /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "ASTT_NA" /t Reg_SZ /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "AutoColorDepthReduction_NA" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableSAMUPowerGating" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableUVDPowerGatingDynamic" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableVCEPowerGating" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableAspmL0s" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableAspmL1" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps_NA" /t Reg_SZ /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_DeLagEnabled" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_FRTEnabled" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableBlockWrite" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "StutterMode" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t Reg_DWORD /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_EnableComputePreemption" /t Reg_DWORD /d "0" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D_DEF" /t Reg_SZ /d "1" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D" /t Reg_BINARY /d "3100" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "FlipQueueSize" /t Reg_BINARY /d "3100" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ShaderCache" /t Reg_BINARY /d "3200" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_OPTION" /t Reg_BINARY /d "3200" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation" /t Reg_BINARY /d "3100" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "VSyncControl" /t Reg_BINARY /d "3000" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TFQ" /t Reg_BINARY /d "3200" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\DAL2_DATA__2_0\DisplayPath_4\EDID_D109_78E9\Option" /v "ProtectionControl" /t Reg_BINARY /d "0100000001000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableVceSwClockGating" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUvdClockGating" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableVCEPowerGating" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableUVDPowerGatingDynamic" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisablePowerGating" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableSAMUPowerGating" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableFBCForFullScreenApp" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableFBCSupport" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableEarlySamuInit" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_GPUPowerDownEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDrmdmaPowerGating" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_SclkDeepSleepDisable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ThermalAutoThrottlingEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ActivityTarget" /t REG_DWORD /d "30" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ODNFeatureEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "GCOOPTION_DisableGPIOPowerSaveMode" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_AllGraphicLevel_DownHyst" /t REG_DWORD /d "20" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_AllGraphicLevel_UpHyst" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_FRTEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableDMACopy" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DisableBlockWrite" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_ODNFeatureEnable" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "KMD_MaxUVDSessions" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DalAllowDirectMemoryAccessTrig" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "DalAllowDPrefSwitchingForGLSync" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "WmAgpMaxIdleClk" /t REG_DWORD /d "32" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "PP_MCLKStutterModeThreshold" /t REG_DWORD /d "4096" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "StutterMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "TVEnableOverscan" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "MLF" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "EQAA" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "PowerState" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AreaAniso_DEF" /t REG_SZ /d "8" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "SurfaceFormatReplacements_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoType_DEF" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoDegree_DEF" /t REG_SZ /d "4" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceTripleBuffering" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceTripleBuffering_DEF" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureOpt_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureLod_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TruformMode_DEF" /t REG_SZ /d "2" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "LodAdj" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_OPTION_DEF" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "NoOSPowerOptions" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_DEF" /t REG_SZ /d "0" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoType" /t REG_BINARY /d "32000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisotropyOptimise" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TrilinearOptimise" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AnisoDegree" /t REG_BINARY /d "3400" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureLod" /t REG_BINARY /d "31000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureOpt" /t REG_BINARY /d "31000000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TextureOpt_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TruformMode_NA" /t REG_BINARY /d "3200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Tessellation_OPTION" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "Main3D_SET" /t REG_BINARY /d "302031203220332034203500" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ForceZBufferDepth_SET" /t REG_BINARY /d "3020313620323400" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "FlipQueueSize" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "SurfaceFormatReplacements" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TFQ" /t REG_BINARY /d "3200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TFQ_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ZFormats_NA" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "PowerState" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "AntiStuttering" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "TurboSync" /t REG_BINARY /d "3000" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "HighQualityAF" /t REG_BINARY /d "3300" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000\UMD" /v "ShaderCache" /t REG_BINARY /d "3200" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\amdkmdag\UMD" /v "FlipQueueSize" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\amdkmdag\UMD" /v "Main3D" /t REG_BINARY /d "3100" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\amdkmdag\UMD" /v "Main3D_DEF" /t REG_SZ /d "1" /f
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\amdkmdag\UMD" /v "Main3D_SET" /t REG_BINARY /d "302031203220332034203500" /f
cls
goto hardware

:intel
reg add "HKLM\SOFTWARE\Intel\GMM" /v "DedicatedSegmentSize" /t REG_DWORD /d "1024" /f >nul 2>&1
goto hardware

:latency
cls
echo              [38;5;0m"  [38;5;55m_          _                          [0m____            _   _              [38;5;0m"
echo              [38;5;0m" [38;5;55m| |    __ _| |_ ___ _ __   ___ _   _  [0m/ ___|  ___  ___| |_(_) ___  _ __   [38;5;0m"
echo              [38;5;0m" [38;5;55m| |   / _` | __/ _ \ '_ \ / __| | | | [0m\___ \ / _ \/ __| __| |/ _ \| '_ \  [38;5;0m"
echo              [38;5;0m" [38;5;55m| |__| (_| | ||  __/ | | | (__| |_| |  [0m___) |  __/ (__| |_| | (_) | | | | [38;5;0m"
echo              [38;5;0m" [38;5;55m|_____\__,_|\__\___|_| |_|\___|\__, | [0m|____/ \___|\___|\__|_|\___/|_| |_| [38;5;0m"
echo              [38;5;0m"                                 [38;5;55m|__/                                      [38;5;0m"
echo.
echo             [0m[ [38;5;55m1 [0m] NetworkThrottlingIndex                 [0m[ [38;5;55m4 [0m] Priority Separation
echo                [38;5;236mKeep your network stopping                  [38;5;236mChanges the priority for
echo                 throttling                                  different apps
echo.
echo             [0m[ [38;5;55m2 [0m] SystemResponsiveness                   [0m[ [38;5;55m5 [0m] BCDEdit
echo                [38;5;236mUndetermines the percentage                 [38;5;236mChanges BCD settings and
echo                   of CPU resources.                         corrects input lag
echo.
echo             [0m[ [38;5;55m3 [0m] Timer Resolution                       [0m[ [38;5;55m6 [0m] ShellExperienceHost
echo                [38;5;236mChanges how fast your CPU                   [38;5;236mExelon Labs official script, 
echo                  refreshes                                  destroys Task Scheduler
echo. 
echo.
echo.
echo.
echo.
echo                                             [0m[ [38;5;55mR [0m] Return
choice /c:123456R /n /m "%BS% ~
set MenuItem=%errorlevel%

if "%MenuItem%"=="1" goto nti
if "%MenuItem%"=="2" goto sr
if "%MenuItem%"=="3" goto tr
if "%MenuItem%"=="4" goto ps
if "%MenuItem%"=="5" goto bcd
if "%MenuItem%"=="6" goto seh
if "%MenuItem%"=="7" goto startlatency


:nti
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "ffffffff" /f
goto latency

:sr
Reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f

:tr
cd C:\Exelon\Resources
	if not exist SetTimerResolutionService.exe (
		::https://forums.guru3d.com/threads/windows-timer-resolution-tool-in-form-of-system-service.376458/
		curl -g -L -# -o "C:\Hone\Resources\SetTimerResolutionService.exe" "https://github.com/auraside/HoneCtrl/raw/main/Files/SetTimerResolutionService.exe" >nul 2>&1
		%windir%\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /i SetTimerResolutionService.exe >nul 2>&1
	)
	sc config "STR" start=auto >nul 2>&1
	start /b net start STR >nul 2>&1
	bcdedit /set useplatformtick yes >nul 2>&1
	bcdedit /set disabledynamictick yes >nul 2>&1
goto latency

:ps
reg add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f >nul 2>&1
goto latency

:bcd
	::tscsyncpolicy
	bcdedit /set tscsyncpolicy enhanced
	::Quick Boot
	if "%duelboot%" equ "no" (bcdedit /timeout 3)
	bcdedit /set bootux disabled
	bcdedit /set bootmenupolicy standard
	bcdedit /set hypervisorlaunchtype off
	bcdedit /set tpmbootentropy ForceDisable
	bcdedit /set quietboot yes
	::Windows 8 Boot (windows 8.1)
	for /f "tokens=4-9 delims=. " %%i in ('ver') do set winversion=%%i.%%j
	if "!winversion!" == "6.3.9600" (
	bcdedit /set {globalsettings} custom:16000067 true
	bcdedit /set {globalsettings} custom:16000069 true
	bcdedit /set {globalsettings} custom:16000068 true
	)
	::nx
	echo %PROCESSOR_IDENTIFIER% ^| find "Intel" >nul && bcdedit /set nx optout || bcdedit /set nx alwaysoff
	::Linear Address 57
	bcdedit /set linearaddress57 OptOut
	bcdedit /set increaseuserva 268435328
	::Disable some of the kernel memory mitigations
	rem Forcing Intel SGX and setting isolatedcontext to No will cause a black screen
	rem bcdedit /set isolatedcontext No
	bcdedit /set allowedinmemorysettings 0x0
	::Disable DMA memory protection and cores isolation
	bcdedit /set vsmlaunchtype Off
	bcdedit /set vm No
	Reg add "HKLM\Software\Policies\Microsoft\FVE" /v "DisableExternalDMAUnderLock" /t Reg_DWORD /d "0" /f
	Reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t Reg_DWORD /d "0" /f
	Reg add "HKLM\Software\Policies\Microsoft\Windows\DeviceGuard" /v "HVCIMATRequired" /t Reg_DWORD /d "0" /f
	::Avoid using uncontiguous low-memory. Boosts memory performance & microstuttering.
	rem Can freeze the system on unstable memory OC
	rem bcdedit /set firstmegabytepolicy UseAll
	rem bcdedit /set avoidlowmemory 0x8000000
	rem bcdedit /set nolowmem Yes
	::Enable X2Apic and enable Memory Mapping for PCI-E devices
	bcdedit /set x2apicpolicy Enable
	bcdedit /set uselegacyapicmode No
	bcdedit /set configaccesspolicy Default
	bcdedit /set MSI Default
	bcdedit /set usephysicaldestination No
	bcdedit /set usefirmwarepcisettings No
goto latency

:seh
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\ahcache" /v "Start" /t REG_DWORD /d "1" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\systemeventsbroker" /v "Start" /t REG_DWORD /d "2" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\samss" /v "Start" /t REG_DWORD /d "2" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v "Start" /t REG_DWORD /d "3" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\schedule" /v "Start" /t REG_DWORD /d "2" /f
PowerRun.exe /SW:0 "Reg.exe" add "HKLM\SYSTEM\CurrentControlSet\Services\schedule" /v "errorcontrol" /t REG_DWORD /d "1" /f
taskkill /f /im explorer.exe
cd C:\Windows\System32
takeown /f "runtimebroker.old"
icacls "C:\Windows\System32\RuntimeBroker.old" /grant Administrators:F
ren runtimebroker.old runtimebroker.exe
start explorer.exe
start runtimebroker.exe
cls
echo Please reboot your system later.
pause
goto latency

:cd
cls
echo              [38;5;0m"   [38;5;55m____ _                     [0m___     [38;5;55m____       _     _             _    [38;5;0m"
echo              [38;5;0m"  [38;5;55m/ ___| | ___  __ _ _ __    [0m( _ )   [38;5;55m|  _ \  ___| |__ | | ___   __ _| |_  [38;5;0m"
echo              [38;5;0m" [38;5;55m| |   | |/ _ \/ _` | '_ \   [0m/ _ \/\ [38;5;55m| | | |/ _ \ '_ \| |/ _ \ / _` | __| [38;5;0m"
echo              [38;5;0m" [38;5;55m| |___| |  __/ (_| | | | | [0m| (_>  < [38;5;55m| |_| |  __/ |_) | | (_) | (_| | |_  [38;5;0m"
echo              [38;5;0m"  [38;5;55m\____|_|\___|\__,_|_| |_|  [0m\___/\/ [38;5;55m|____/ \___|_.__/|_|\___/ \__,_|\__| [38;5;0m"
echo              [38;5;0m"                  [0m/ ___|  ___  ___| |_(_) ___  _ __                       [38;5;0m"
echo              [38;5;0m"                  [0m\___ \ / _ \/ __| __| |/ _ \| '_ \                      [38;5;0m"
echo              [38;5;0m"                   [0m___) |  __/ (__| |_| | (_) | | | |                     [38;5;0m"
echo              [38;5;0m"                  [0m|____/ \___|\___|\__|_|\___/|_| |_|                     [38;5;0m"
echo.
echo.
echo.
echo             [0m[ [38;5;55m1 [0m] Remove Bloatware                       [0m[ [38;5;55m3 [0m] Junk Cleaner
echo                [38;5;236mRemoves your trackware                      [38;5;236mDeletes Junk from your
echo                 and bloatware                               PC, check Recycle Bin before.
echo.
echo             [0m[ [38;5;55m2 [0m] System Debloat                         [0m[ [38;5;55m4 [0m] Delete Services
echo                [38;5;236mDebloats your system making                 [38;5;236mDeletes useless services
echo                 it more comfortable in use                  that are using hardware resources
echo.
echo.
echo.
echo                                             [0m[ [38;5;55mR [0m] Return
choice /c:1234R /n /m "%BS% ~
set MenuItem=%errorlevel%

if "%MenuItem%"=="1" goto bloatware
if "%MenuItem%"=="2" goto debloat
if "%MenuItem%"=="3" goto junk
if "%MenuItem%"=="4" goto ds
if "%MenuItem%"=="5" goto startcd

:bloatware
cls
PowerShell -Command "Get-AppxPackage *windowsalarms* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *bingsports* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.549981C3F5F10* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *feedback* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *getstarted* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *windowsmaps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.MixedReality.Portal* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *bingfinance* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.MSPaint* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *people* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *windowspExelon* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.YourPExelon* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *photos* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Print3D* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.ScreenSketch* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *soundrecorder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.WebMediaExtensions* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.WebpImageExtension* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *xboxapp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxGamingOverlay* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage"
Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticErrorText" /t REG_SZ /d "" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticLinkText" /t REG_SZ /d "" /f
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "OptimizeWindowsSearchResultsForScreenReaders" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" /v "FPEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /v "AllowAddressBarDropdown" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /v "EnableEncryptedMediaExtensions" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgradePeriod" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdatePeriod" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SYSTEM\ControlSet001\Services\wuauserv" /v "Start" /t REG_DWORD /d "4" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" /v "RegisteredWithAU" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\OneDrive" /v "PreventNetworkTrafficPreUserSignIn" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f
Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
Reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
cls
goto cd

:debloat
cls
	schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable 
	Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticErrorText" /t REG_SZ /d "" /f  
	Reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /v "DiagnosticLinkText" /t REG_SZ /d "" /f  
	Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f   
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /v "Value" /t REG_SZ /d "Deny" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" /v "Value" /t REG_SZ /d "Deny" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "DoNotTrack" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "OptimizeWindowsSearchResultsForScreenReaders" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" /v "FPEnabled" /t REG_DWORD /d "0" /f   
	Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /v "AllowAddressBarDropdown" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Privacy" /v "EnableEncryptedMediaExtensions" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgradePeriod" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdatePeriod" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f  	
	Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f  
	Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" /v "RegisteredWithAU" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Microsoft\OneDrive" /v "PreventNetworkTrafficPreUserSignIn" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpyNetReporting" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f  
	Reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f  
	Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f
    schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Enable >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "Allow Telemetry" /t REG_DWORD /d "0" /f >nul 2>&1
    Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "DiagnosticErrorText" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings" /f >nul 2>&1
    Reg.exe delete "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Messaging" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /f >nul 2>&1
    Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /f >nul 2>&1
    Reg.exe delete "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /f >nul 2>&1
    Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /f >nul 2>&1
    Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /f >nul 2>&1
    Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /f >nul 2>&1
    Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /f >nul 2>&1
    Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\DeviceAccess" /f >nul 2>&1
    Reg.exe delete "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Browser" /f >nul 2>&1
    Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /f >nul 2>&1
    Reg.exe delete "HKCU\Software\Microsoft\Windows NT\CurrentVersion\Sensor" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"" /f >nul 2>&1
    Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Speech" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Microsoft\OneDrive" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /f >nul 2>&1
    Reg.exe delete "HKLM\SOFTWARE\Policies\Microsoft\MRT" /f >nul 2>&1
    Reg.exe delete "HKCU\Software\Microsoft\Siuf" /f >nul 2>&1
    Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "1" /f >nul 2>&1
    Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
    Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" /v "RegisteredWithAU" /t REG_DWORD /d "0" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "1" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "0" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "0" /f >nul 2>&1
    Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "0" /f >nul 2>&1
    Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f >nul 2>&1
    Reg.exe add "HKLM\SOFTWARE\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "1" /f >nul 2>&1
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
    Reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "1" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "1" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "1" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "1" /f >nul 2>&1
    Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "1" /f  
) >nul 2>&1
goto cd

:ds
cls
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "4" /f 
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\spectrum" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wcncsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WebClient" /v "Start" /t REG_DWORD /d "4" /f 
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NcaSvc" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UserDataSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\stisvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AdobeFlashPlayerUpdateSvc" /v "Start" /t REG_DWORD /d "4" /f 
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TrkWks" /v "Start" /t REG_DWORD /d "4" /f 
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f   
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "4" /f   
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f 
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\GoogleChromeElevationService" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "4" /f 
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ibtsiva" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMPTRAP" /v "Start" /t REG_DWORD /d "4" /f   	
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\pla" /v "Start" /t REG_DWORD /d "4" /f 
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ssh-agent" /v "Start" /t REG_DWORD /d "4" /f   
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\sshd" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" /v "Start" /t REG_DWORD /d "4" /f    
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetTcpPortSharing" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wersvc" /v "Start" /t REG_DWORD /d "4" /f   
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdate" /v "Start" /t REG_DWORD /d "4" /f   
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\gupdatem" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MSiSCSI" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "4" /f   
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UnistoreSvc" /v "Start" /t REG_DWORD /d "4" /f 
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MapsBroker" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\debugregsvc" /v "Start" /t REG_DWORD /d "4" /f  
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Ndu" /v "Start" /d "2" /t REG_DWORD /f  
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\TimeBrokerSvc" /v "Start" /d "3" /t REG_DWORD /f 
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\VaultSvc" /v "Start" /t REG_DWORD /d "3" /f 
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
	Reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertPropSvc" /v "Start" /t REG_DWORD /d "3" /f
goto cd

:junk
rem Delete Temporary Files
del /s /f /q %WinDir%\Temp\*.*
del /s /f /q %WinDir%\Prefetch\*.*
del /s /f /q %Temp%\*.*
del /s /f /q %AppData%\Temp\*.*
del /s /f /q %HomePath%\AppData\LocalLow\Temp\*.*

rem Delete Used Drivers Files (Not needed because already installed)
del /s /f /q %SYSTEMDRIVE%\AMD\*.*
del /s /f /q %SYSTEMDRIVE%\NVIDIA\*.*
del /s /f /q %SYSTEMDRIVE%\INTEL\*.*

rem Delete Temporary Folders
rd /s /q %WinDir%\Temp
rd /s /q %WinDir%\Prefetch
rd /s /q %Temp%
rd /s /q %AppData%\Temp
rd /s /q %HomePath%\AppData\LocalLow\Temp

rem Delete Used Drivers Folders (Not needed because already installed)
rd /s /q %SYSTEMDRIVE%\AMD
rd /s /q %SYSTEMDRIVE%\NVIDIA
rd /s /q %SYSTEMDRIVE%\INTEL

rem Recreate Empty Temporary Folders
md %WinDir%\Temp
md %WinDir%\Prefetch
md %Temp%
md %AppData%\Temp
md %HomePath%\AppData\LocalLow\Temp
echo.
cls
goto cd