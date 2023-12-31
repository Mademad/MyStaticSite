<# :: MadnessWinUtil Version 1.3.1
@echo off
:GETPERM
	set vbs=%temp%\getadmin.vbs
	net session >nul 2>&1
	if [%errorLevel%] == [0] ( 
		if not "%~1" == "" call :%~1
		goto Main
		)
	if exist "%vbs%" ( net session >nul 2>&1 || (
			echo Failed to elevate... Run as administrator
			del "%vbs%" && pause && exit
		) )
    echo Set UAC = CreateObject^("Shell.Application"^) > "%vbs%"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%vbs%"
    "%vbs%" && exit /B
:MAIN
	if exist "%vbs%" ( del "%vbs%" )
    color 0b && cls
    echo -------------------------------------------------------------------------------
    echo                           Welcome MademadWinUtil
    echo -------------------------------------------------------------------------------
    echo 1- Disable Windows Update (Will Restart The System) For Windows 10 And 11
    echo 2- Disable Windows Defender (May Need To Restart) For Windows 10 And 11
	echo 3- Performance and Privacy Tweaks Menu (May Need To Restart)
    echo 4- Windows Debloat Menu (For Windows 10 and 11)
    echo 5- Run Everything (Will Restart The System)
	echo 6- Exit
    CHOICE /C:123456
	if [%errorlevel%] == [6] ( exit )
	if [%errorlevel%] == [5] ( call :All )
    if [%errorlevel%] == [4] ( call :WinDebloat)
	if [%errorlevel%] == [3] ( call :TWEAKS )
    if [%errorlevel%] == [2] ( call :MAINDWD )
    if [%errorlevel%] == [1] ( call :MAINDWU )
	goto MAIN
	:MAINDWU
		Choice /m "Note: Disable Windows Update - Your System Will Restart, Do You Wish To Continue?"
		if errorlevel 2 exit /B 0
		:DWU
		reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU /v NoAutoUpdate /t REG_DWORD /d 1 /f
		net stop wuauserv
		reg add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d 4 /f
		net stop BITS
		reg add "HKLM\SYSTEM\CurrentControlSet\Services\BITS" /v "Start" /t REG_DWORD /d 4 /f
		set DisableWUTasks=%DisableWUTasks% "Microsoft\Windows\WindowsUpdate\Automatic App Update" "Microsoft\Windows\WindowsUpdate\Scheduled Start"
		set DisableWUTasks=%DisableWUTasks% "Microsoft\Windows\WindowsUpdate\sih" "Microsoft\Windows\WindowsUpdate\sihboot" "Microsoft\Windows\WindowsUpdate\sihpostreboot"
		(for %%a in (%DisableWUTasks%) do ( schtasks /change /disable /tn %%a ))
		reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv /v Start /t REG_DWORD /d 0x4 /f
		call :RE
		exit /B 0
	:MAINDWD
		Choice /m "Note: Disable Windows Defender - Your System Will Restart, Do You Wish To Continue?"
		if errorlevel 2 exit /B 0
		:DWD
		PowerShell -c ^"Invoke-Expression ('^& {' + (get-content -raw '%~f0') + '; DisableWinDefender} ') "
		set HSMWD=HKLM\SOFTWARE\Microsoft\Windows Defender
		set HSPWD=HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
		set DWDREG=			"%HSMWD%\Features"~"TamperProtection"~"0" "%HSMWD%\Real-Time Protection"~"DisableRealtimeMonitoring"~"1" "%HSPWD%"~"DisableAntiSpyware"~"1"
		set DWDREG=%DWDREG% "%HSPWD%"~"DisableRealtimeMonitoring"~"1" "%HSPWD%"~"DisableRoutinelyTakingAction"~"1" "%HSPWD%\Real-Time Protection"~"DisableBehaviorMonitoring"~"1"
		set DWDREG=%DWDREG% "%HSPWD%\Real-Time Protection"~"DisableRealtimeMonitoring"~"1" "%HSPWD%\Real-Time Protection"~"DisableScanOnRealtimeEnable"~"1"
		set DWDREG=%DWDREG% "HKLM\SOFTWARE\Microsoft\Security Center\Svc"~"AntiSpywareOverride"~"1"
		for %%A in (%DWDREG%) do ( for /f "tokens=1,2,3 delims=~" %%C in ("%%A") do ( reg add %%C /v %%D /t REG_DWORD /d %%E /f ))
		exit /B 0
	:TWEAKS
		if exist "%vbs%" ( del "%vbs%" )
		cls && color 09	&& set TweakVar=0
		echo -------------------------------------------------------------------------------
		echo                                 The Tweak Menu  
		echo -------------------------------------------------------------------------------
		echo 1- Set Services To Manual (Some Services are set to Disabled)
		echo 2- Disable Most Tasks From Task Scheduler
		echo 3- Performance and System Privacy Tweaks (restart is needed)
		echo 4- User Tweaks, Clean up and Dark Mode (Might need to sign out)
		echo 5- Disable UAC for Admin Users
		echo 6- all of the above
		echo 7- Exit
		CHOICE /C:1234567
		if [%errorlevel%] == [7] ( exit /B 0 )
		if [%errorlevel%] == [6] ( call :RunAllTweaks )
		if [%errorlevel%] == [5] ( call :DisUAC )
		if [%errorlevel%] == [4] ( call :PTFU )
		if [%errorlevel%] == [3] ( call :PTMFG )
		if [%errorlevel%] == [2] ( call :TASKSCH )
		if [%errorlevel%] == [1] ( call :SSTM )
		goto MAIN
		:RunAllTweaks
			Choice /m "Note: Running All Tweaks - Are You Sure?"
			if errorlevel 2 exit /B 0
			set TweakVar=1
			call :NPSC
			call :NPTK
			call :PTMFG
			call :PTFU
			call :DisUAC
			echo "All Tweaks Done."
			pause && exit /B 0
		:SSTM
			Choice /m "Note: Set Services To Manual - Are You Sure?"
			if errorlevel 2 exit /B 0
			:NPSC
			echo Setting Services To Manual, Delayed and Disabled
			set SVCs=		ALG~"3" AppIDSvc~"3" AppMgmt~"3" AppReadiness~"3" AppXSvc~"3" Appinfo~"3" AxInstSV~"3" BDESVC~"3" BTAGService~"3"
			set SVCs=%SVCs% BcastDVRUserService~"3" BluetoothUserService~"3" Browser~"3" CDPSvc~"3" COMSysApp~"3" CaptureService~"3" CertPropSvc~"3"
			set SVCs=%SVCs% ClipSVC~"3" ConsentUxUserSvc~"3" CredentialEnrollmentManagerUserSvc~"3" CscService~"3" DcpSvc~"3" DevQueryBroker~"3"
			set SVCs=%SVCs% DeviceAssociationBrokerSvc~"3" DeviceAssociationService~"3" DeviceInstall~"3" DevicePickerUserSvc~"3" DevicesFlowUserSvc~"3"
			set SVCs=%SVCs% DisplayEnhancementService~"3" DmEnrollmentSvc~"3" DsSvc~"3" DsmSvc~"3" EFS~"3" EapHost~"3" EntAppSvc~"3" FDResPub~"3"
			set SVCs=%SVCs% Fax~"3" FrameServer~"3" FrameServerMonitor~"3" GraphicsPerfSvc~"3" HomeGroupListener~"3" HomeGroupProvider~"3" HvHost~"3"
			set SVCs=%SVCs% IEEtwCollectorService~"3" IKEEXT~"3" InstallService~"3" InventorySvc~"3" IpxlatCfgSvc~"3" KtmRm~"3" LicenseManager~"3"
			set SVCs=%SVCs% LxpSvc~"3" MSDTC~"3" MSiSCSI~"3" McpManagementService~"3" MessagingService~"3" MicrosoftEdgeElevationService~"3"
			set SVCs=%SVCs% MixedRealityOpenXRSvc~"3" MsKeyboardFilter~"3" NPSMSv~"3" NaturalAuthentication~"3" NcaSvc~"3" NcbService~"3" NcdAutoSetup~"3"
			set SVCs=%SVCs% NetSetupSvc~"3" Netlogon~"3" Netman~"3" NgcCtnrSvc~"3" NgcSvc~"3" NlaSvc~"3" P9RdrService~"3" PNRPAutoReg~"3" PNRPsvc~"3"
			set SVCs=%SVCs% PcaSvc~"3" PeerDistSvc~"3" PenService~"3" PerfHost~"3" PhoneSvc~"3" PimIndexMaintenanceSvc~"3" PlugPlay~"3" PolicyAgent~"3"
			set SVCs=%SVCs% PrintNotify~"3" PrintWorkflowUserSvc~"3" PushToInstall~"3" QWAVE~"3" RasAuto~"3" RasMan~"3" RetailDemo~"3" RmSvc~"3"
			set SVCs=%SVCs% RpcLocator~"3" SCPolicySvc~"3" SCardSvr~"3" SDRSVC~"3" SEMgrSvc~"3" SNMPTrap~"3" SSDPSRV~"3" ScDeviceEnum~"3"
			set SVCs=%SVCs% SecurityHealthService~"3" Sense~"3" SensorDataService~"3" SensorService~"3" SensrSvc~"3" SessionEnv~"3" SharedAccess~"3"
			set SVCs=%SVCs% SharedRealitySvc~"3" SmsRouter~"3" SstpSvc~"3" StateRepository~"3" StiSvc~"3" StorSvc~"3" TabletInputService~"3" TapiSrv~"3"
			set SVCs=%SVCs% TextInputManagementService~"3" TieringEngineService~"3" TimeBroker~"3" TimeBrokerSvc~"3" TokenBroker~"3" TroubleshootingSvc~"3"
			set SVCs=%SVCs% TrustedInstaller~"3" UI0Detect~"3" UdkUserSvc~"3" UmRdpService~"3" UnistoreSvc~"3" UserDataSvc~"3" UsoSvc~"3" VSS~"3"
			set SVCs=%SVCs% VacSvc~"3" W32Time~"3" WEPHOSTSVC~"3" WFDSConMgrSvc~"3" WMPNetworkSvc~"3" WManSvc~"3" WPDBusEnum~"3" WSService~"3"
			set SVCs=%SVCs% WaaSMedicSvc~"3" WalletService~"3" WarpJITSvc~"3" WbioSrvc~"3" WcsPlugInService~"3" WdNisSvc~"3" WdiServiceHost~"3"
			set SVCs=%SVCs% WdiSystemHost~"3" WebClient~"3" Wecsvc~"3" WerSvc~"3" WiaRpc~"3" WinHttpAutoProxySvc~"3" WinRM~"3" WpcMonSvc~"3"
			set SVCs=%SVCs% WpnService~"3" WwanSvc~"3" XblAuthManager~"3" XblGameSave~"3" XboxGipSvc~"3" XboxNetApiSvc~"3" autotimesvc~"3" bthserv~"3"
			set SVCs=%SVCs% camsvc~"3" cbdhsvc~"3" cloudidsvc~"3" dcsvc~"3" defragsvc~"3" diagnosticshub.standardcollector.service~"3" diagsvc~"3"
			set SVCs=%SVCs% dmwappushservice~"3" dot3svc~"3" edgeupdate~"3" edgeupdatem~"3" embeddedmode~"3" fdPHost~"3" fhsvc~"3" hidserv~"3"
			set SVCs=%SVCs% icssvc~"3" lfsvc~"3" lltdsvc~"3" lmhosts~"3" msiserver~"3" netprofm~"3" p2pimsvc~"3" p2psvc~"3" perceptionsimulation~"3"
			set SVCs=%SVCs% pla~"3" seclogon~"3" smphost~"3" spectrum~"3" svsvc~"3" swprv~"3" upnphost~"3" vds~"3" vm3dservice~"3"
			set SVCs=%SVCs% vmicguestinterface~"3" vmicheartbeat~"3" vmickvpexchange~"3" vmicrdv~"3" vmicshutdown~"3" vmictimesync~"3" vmicvmsession~"3"
			set SVCs=%SVCs% vmicvss~"3" vmvss~"3" wbengine~"3" wcncsvc~"3" webthreatdefsvc~"3" wercplsupport~"3" wisvc~"3" wlidsvc~"3" wlpasvc~"3"
			set SVCs=%SVCs% wmiApSrv~"3" workfolderssvc~"3" wudfsvc~"3" AJRouter~"4" AppVClient~"4" AssignedAccessManagerSvc~"4" DiagTrack~"4"
			set SVCs=%SVCs% DialogBlockingService~"4" NetTcpPortSharing~"4" RemoteAccess~"4" RemoteRegistry~"4" UevAgentService~"4" shpamsvc~"4" ssh-agent~"4"
			set SVCs=%SVCs% tzautoupdate~"4" uhssvc~"4" SysMain~"4" WSearch~"4" DoSvc~"2" MapsBroker~"2" sppsvc~"2" wscsvc~"2"
			(for %%A in (%SVCs%) do (for /f "tokens=1,2 delims=~" %%B in ("%%A") do (
				echo %%B
				reg add "HKLM\SYSTEM\CurrentControlSet\Services\%%B" /v "Start" /t REG_DWORD /d %%C /f
			)))
			if not %TweakVar% == 1 ( pause )
			exit /B 0
		:TASKSCH
			Choice /m "Note: Disable Scheduled Tasks - Are You Sure?"
			if errorlevel 2 exit /B 0
			:NPTK
			echo Disabling Scheduled Tasks
			set DisableTasks=%DisableTasks% "Microsoft\Windows\Autochk\Proxy" "Microsoft\Windows\Application Experience\MareBackup"
			set DisableTasks=%DisableTasks% "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" "Microsoft\Windows\Application Experience\PcaPatchDbTask"
			set DisableTasks=%DisableTasks% "Microsoft\Windows\Application Experience\ProgramDataUpdater" "Microsoft\Windows\Application Experience\StartupAppTask"
			set DisableTasks=%DisableTasks% "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
        	set DisableTasks=%DisableTasks% "Microsoft\Windows\Customer Experience Improvement Program\Uploader" "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
			set DisableTasks=%DisableTasks% "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" "Microsoft\Windows\Feedback\Siuf\DmClient"
			set DisableTasks=%DisableTasks% "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" "Microsoft\Windows\Location\Notifications" "Microsoft\Windows\Location\WindowsActionDialog"
			set DisableTasks=%DisableTasks% "Microsoft\Windows\Maps\MapsToastTask" "Microsoft\Windows\Maps\MapsUpdateTask" "Microsoft\Windows\Windows Error Reporting\QueueReporting"
			(for %%a in (%DisableTasks%) do ( schtasks /change /disable /tn %%a ))
			if not %TweakVar% == 1 ( pause )
			exit /B 0
		:PTMFG
			echo Performance Tweaks
			echo ...
			echo Disabling Power Throttling
			reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d 0 /f
			echo Disabling Network Throttling
			reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d 0xffffffff /f
			echo Increasing I/O Request Packet Stack Size to 30
			reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d 30 /f
			echo Reserving 100% of CPU to Multimedia/Gaming tasks...
			echo Setting SystemResponsiveness to 0 .
			reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d 0 /f
			echo Setting Multimedia Class Scheduler Service To Prioritize Games
			reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d 0xf /f
			reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f
			reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d 6 /f
			reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d High /f
			reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d High /f
			reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Rate" /t REG_DWORD /d 4 /f
			echo Disabling CPU Core Parking
			reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" /v "Attributes" /t REG_DWORD /d 0 /f
			echo Decreasing Direct3D Maximum Pre-rendered Frames
			reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\Direct3D" /v "MaxPreRenderedFrames" /t REG_DWORD /d 1 /f
			echo Disabling Windows Feedback Experience program
			reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
			echo Stopping Cortana from being used as part of your Windows Search Function
			reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
			echo Disabling Bing Search in Start Menu
			reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 0 /f
			reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
			echo Disabling Wi-Fi Sense
			reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "Value" /t REG_DWORD /d 0 /f
			reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "Value" /t REG_DWORD /d 0 /f
			reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f
			echo Disabling Data Collection and Telemtry
			reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
			reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
			reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
			echo Disabling Activity Feed (Timeline)
			reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d 0 /f
			echo Disabling Collect Activity History
			reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f
			echo Disabling Sync Activities from PC to Cloud
			reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d 0 /f
			echo Disabling Location Tracking
			reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f
			reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f
			echo Disabling Microsoft Consumer Experiences
			reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
			echo Disabling Windows Error Reporting
			reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
			echo Disabling Autorun for all Drives
			reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f
			echo Removing 3D Objects from the 'My Computer' submenu in explorer
			reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
			reg delete "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
			echo Enabling Long Paths
			reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d 1 /f
			::echo Set Time To UTC (Useful For Dual Booting)
			::reg add "HKLM\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" /v "RealTimeIsUniversal" /d 1 /f
			echo Setting NDU Service to Delayed Start
			reg add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /v "Start" /t REG_DWORD /d 2 /f
			if not %TweakVar% == 1 ( pause )
			exit /B 0
		:PTFU
			echo User Tweak
			echo ...
			echo Adding Computer To Desktop
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d 0 /f
			echo Enabling Dark Mode
			reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f
			reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f
			echo Enabling "EnthusiastMode" To Show More Details in File Transfer Dialog Box
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d 1 /f
			echo Disabling 'Show Recently Used Files', 'Show Frequently Used Folders'
			echo And 'Show Files From Office.com' from Folder Options
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d 0 /f
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d 0 /f
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowCloudFilesInQuickAccess" /t REG_DWORD /d 0 /f
			echo Disabling hide file extension setting
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f
			echo Disabling Window shake to minimize all other windows
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d 1 /f
			echo Disabling Autoplay for the User
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d 1 /f
			echo Disabling Bing Search in Start Menu
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
			echo Disabling the Windows Feedback Experience program
			reg add "HKCU\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d 0 /f
			echo Disabling Start Menu Live Tiles
			reg add "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d 1 /f
			echo Disabling Cortana
			reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
			reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
			reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
			reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
			echo Disabling Send typing info to Microsoft ( if not disabled by default )
			reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
			echo Disabling StorageSense
			reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d 0 /f
			echo Disabling '- Shortcut' name after creating a shortcut
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "Link" /t REG_BINARY /d "0 0 0 0" /f
			echo Disabling Sticky Keys...
			reg add "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f | rem Default Value=510
			reg add "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f  | rem Default Value=126
			reg add "HKCU\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d "58" /f | rem Default Value=62
			echo Hiding Talk to Cortana Button
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t REG_DWORD /d 0 /f
			echo Hiding TaskView Button
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
			echo Hiding People Button
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d 0 /f
			echo Hiding Searchbox From Taskbar
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
			echo Hiding News and Interests From Taskbar
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d 2 /f
			echo Hiding Windows Ink Workspace From Taskbar
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceButtonDesiredVisibility" /t REG_DWORD /d 0 /f
			echo Hiding Touch Keyboard Button From Taskbar
			reg add "HKCU\Software\Microsoft\TabletTip\1.7" /v "TipbandDesiredVisibility" /t REG_DWORD /d 0 /f
			echo Hiding Widgets
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f
			echo Setting Taskbar Alignment to the Left
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d 0 /f
			echo Changing explorer's "LaunchTo" setting to "This PC"
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f
			echo Changing Control Panel's view to All Items Icons
			reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v "AllItemsIconView" /t REG_DWORD /d 1 /f
			echo Disabling Content Delivery Manager (It's for Preinstalled and Sponsored Apps)
			reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
			reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
			reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
			reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
			reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
			reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
			reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
			reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
			reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f
			reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
			echo restarting Explorer.exe in
			set time=3 && call :TIMER
			taskkill /f /im explorer.exe && start explorer
			if not %TweakVar% == 1 ( pause )
			exit /B 0
		:DisUAC
			echo Disabling UAC for Admin Users 
			reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 0 /f
			if not %TweakVar% == 1 ( pause )
			exit /B 0
	:WinDebloat
		color 0b && cls
		echo -------------------------------------------------------------------------------
		echo                           Windows Debloat Menu
		echo -------------------------------------------------------------------------------
		echo 1- Partially Debloat Windows
		echo 2- Uninstall Microsoft OneDrive
		echo 3- Uninstall Microsoft Edge
		echo 4- All of the Above
		echo 5- Exit
		CHOICE /C:12345
		if [%errorlevel%] == [5] ( exit /B 0 )
		if [%errorlevel%] == [4] ( call :RunAllDebloat )
		if [%errorlevel%] == [3] ( call :UninEdge )
		if [%errorlevel%] == [2] ( call :UninOneDrive )
		if [%errorlevel%] == [1] ( call :DebloatWindows )
		goto MAIN
		:RunAllDebloat
			echo Will Remove AppX Packages (Partially Debloat Windows)
			echo Will Uninstall Microsoft OneDrive
			echo Will Uninstall Microsoft Edge
			Choice /m "Are You Sure You Want to Proceed?"
			if errorlevel 2 exit /B 0
			call :DBWDW
			call :DBWUO
			call :DBWUE
			exit /B 0
		:DebloatWindows
			echo Will Remove AppX Packages (Partially Debloat Windows)
			Choice /m "Are You Sure You Want to Proceed?"
			if errorlevel 2 exit /B 0
			:DBWDW
			echo Debloating Windows
			PowerShell -c ^"Invoke-Expression ('^& {' + (get-content -raw '%~f0') + '; Win-Debloat} ') "
			exit /B 0
		:UninOneDrive
			echo Will Uninstall Microsoft OneDrive
			Choice /m "Are You Sure You Want to Proceed?"
			if errorlevel 2 exit /B 0
			:DBWUO
			echo Uninstalling OneDrive
			PowerShell -c ^"Invoke-Expression ('^& {' + (get-content -raw '%~f0') + '; UninstallOneDrive} ') "
			exit /B 0
		:UninEdge
			echo Will Uninstall Microsoft Edge (Not Recommended but I Hate Edge)
			Choice /m "Are You Sure You Want to Proceed?"
			if errorlevel 2 exit /B 0
			:DBWUE
			echo Uninstalling Microsoft Edge
			PowerShell -c ^"Invoke-Expression ('^& {' + (get-content -raw '%~f0') + '; UninstallEdge} ') "
			exit /B 0
	:All
		echo Will Disable Windows Update and Defender
		echo Will Run All Tweaks
		echo Will Remove AppX Packages (Partially Debloat Windows)
		echo Will Uninstall Microsoft OneDrive
		echo Will Uninstall Microsoft Edge
		Choice /m "Are You Sure You Want to Proceed?"
		if errorlevel 2 exit /B 0
		echo Disabling Windows Defender
		call :DWD
		echo Starting Tweaks
		call :NPSC
		call :NPTK
		call :PTMFG
		call :PTFU
		call :DisUAC
		echo Starting Debloat
		call :DBWDW
		call :DBWUO
		call :DBWUE
		echo Disabling Windows Updates
		call :DWU
		exit /B 0
:TIMER
		ping localhost -n 2 >nul
		echo %time%
		set /a time=%time%-1
		if %time% EQU 0 exit /B 0
		goto TIMER
:RE
		echo ------System will restart.------
		shutdown /r /f /t 0
		exit /B 0
#>

function DisableWinDefender {
	Write-Host "Disabling Archive Scanning"
	Set-MpPreference -DisableArchiveScanning 1 -ErrorAction SilentlyContinue
	Write-Host "Disabling Behavior Monitoring"
	Set-MpPreference -DisableBehaviorMonitoring 1 -ErrorAction SilentlyContinue
	Write-Host "Disabling Intrusion Prevention System"
	Set-MpPreference -DisableIntrusionPreventionSystem 1 -ErrorAction SilentlyContinue
	Write-Host "Disabling IOAV Protection"
	Set-MpPreference -DisableIOAVProtection 1 -ErrorAction SilentlyContinue
	Write-Host "Disabling Removable Drive Scanning"
	Set-MpPreference -DisableRemovableDriveScanning 1 -ErrorAction SilentlyContinue
	Write-Host "Disabling Block At First Seen"
	Set-MpPreference -DisableBlockAtFirstSeen 1 -ErrorAction SilentlyContinue
	Write-Host "Disabling Scanning Mapped Network Drives For Full Scan"
	Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan 1 -ErrorAction SilentlyContinue
	Write-Host "Disabling Scanning Network Files"
	Set-MpPreference -DisableScanningNetworkFiles 1 -ErrorAction SilentlyContinue
	Write-Host "Disabling Script Scanning"
	Set-MpPreference -DisableScriptScanning 1 -ErrorAction SilentlyContinue
	Write-Host "Disabling Realtime Monitoring"
	Set-MpPreference -DisableRealtimeMonitoring 1 -ErrorAction SilentlyContinue
	exit 0
}
	
function Win-Debloat {
	$ComputerInfo = Get-ComputerInfo
	if ($ComputerInfo.WindowsProductName -like "Windows 10*") {
		$Bloatware = @(
			"Microsoft.BingNews", "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftOfficeHub"
			"Microsoft.MicrosoftSolitaireCollection", "Microsoft.NetworkSpeedTest", "Microsoft.News", "Microsoft.Office.Lens", "Microsoft.Office.OneNote"
			"Microsoft.Office.Sway", "Microsoft.OneConnect", "Microsoft.People", "Microsoft.Print3D", "Microsoft.RemoteDesktop", "Microsoft.SkypeApp"
			"Microsoft.StorePurchaseApp", "Microsoft.Office.Todo.List", "Microsoft.Whiteboard", "Microsoft.WindowsAlarms", "Microsoft.WindowsCamera"
			"microsoft.windowscommunicationsapps", "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "Microsoft.WindowsSoundRecorder", "Microsoft.Xbox.TCUI"
			"Microsoft.XboxApp", "Microsoft.XboxGameOverlay", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.ZuneMusic", 
			"Microsoft.ZuneVideo", "Microsoft.Wallet"
			#Sponsored Windows 10 AppX Apps #Add sponsored/featured apps to remove in the "*AppName*" format
			"*EclipseManager*", "*ActiproSoftwareLLC*", "*AdobeSystemsIncorporated.AdobePhotoshopExpress*", "*Duolingo-LearnLanguagesforFree*", "*PandoraMediaInc*", "*CandyCrush*"
			"*BubbleWitch3Saga*", "*Wunderlist*", "*Flipboard*", "*Twitter*", "*Facebook*", "*Spotify*", "*Minecraft*", "*Royal Revolt*", "*Sway*", "*Speed Test*", "*Dolby*"
			"*Microsoft.BingWeather*"
		)
		foreach ($Bloat in $Bloatware) {
			Get-AppxPackage -Name $Bloat| Remove-AppxPackage
			Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
			Write-Output "Trying to remove $Bloat."
		}
		Write-Host "Creating A Variable"
		New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
		$Keys = @(
			#Remove Background Tasks
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
			#Windows File
			"HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
			#Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
			#Scheduled Tasks to delete
			"HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
			#Windows Protocol Keys
			"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
			"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
			#Windows Share Target
			"HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
		)
        #This writes the output of each key it is removing and also removes the keys listed above.
		ForEach ($Key in $Keys) {
			Write-Output "Removing $Key from registry"
			Remove-Item $Key -Recurse
		}
	}
	if ($ComputerInfo.WindowsProductName -like "Windows 11*") {
		#Windows11Debloat WIP
		$Bloatware = @(
			"Microsoft.BingNews", "Microsoft.GetHelp", "Microsoft.Getstarted", "Microsoft.Messaging", "Microsoft.Microsoft3DViewer", "Microsoft.MicrosoftOfficeHub"
			"Microsoft.MicrosoftSolitaireCollection", "Microsoft.NetworkSpeedTest", "Microsoft.News", "Microsoft.Office.Lens", "Microsoft.Office.OneNote"
			"Microsoft.Office.Sway", "Microsoft.OneConnect", "Microsoft.People", "Microsoft.Print3D", "Microsoft.RemoteDesktop", "Microsoft.SkypeApp"
			"Microsoft.StorePurchaseApp", "Microsoft.Office.Todo.List", "Microsoft.Whiteboard", "Microsoft.WindowsAlarms", "Microsoft.WindowsCamera"
			"microsoft.windowscommunicationsapps", "Microsoft.WindowsFeedbackHub", "Microsoft.WindowsMaps", "Microsoft.WindowsSoundRecorder", "Microsoft.Xbox.TCUI"
			"Microsoft.XboxApp", "Microsoft.XboxGameOverlay", "Microsoft.XboxIdentityProvider", "Microsoft.XboxSpeechToTextOverlay", "Microsoft.ZuneMusic",
			"Microsoft.ZuneVideo", "Microsoft.Todos", "Microsoft.Wallet",
			#Sponsored Windows 10 AppX Apps #Add sponsored/featured apps to remove in the "*AppName*" format
			"*EclipseManager*", "*ActiproSoftwareLLC*", "*AdobeSystemsIncorporated.AdobePhotoshopExpress*", "*Duolingo-LearnLanguagesforFree*", "*PandoraMediaInc*", "*CandyCrush*"
			"*BubbleWitch3Saga*", "*Wunderlist*", "*Flipboard*", "*Twitter*", "*Facebook*", "*Spotify*", "*Minecraft*", "*Royal Revolt*", "*Sway*", "*Speed Test*", "*Dolby*"
			"*Microsoft.BingWeather*"
		)
		foreach ($Bloat in $Bloatware) {
			Get-AppxPackage -Name $Bloat| Remove-AppxPackage
			Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
			Write-Output "Trying to remove $Bloat."
		}
		Write-Host "Creating A Variable"
		New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
		$Keys = @(
			#Remove Background Tasks
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
			#Windows File
			"HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
			#Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
			#Scheduled Tasks to delete
			"HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
			#Windows Protocol Keys
			"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
			"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
			"HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
			#Windows Share Target
			"HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
		)
        #This writes the output of each key it is removing and also removes the keys listed above.
		ForEach ($Key in $Keys) {
			Write-Output "Removing $Key from registry"
			Remove-Item $Key -Recurse
		}
	}
}

Function UninstallOneDrive {
    Write-Host "Checking for pre-existing files and folders located in the OneDrive folders..."
    Start-Sleep 1
    If (Test-Path "$env:USERPROFILE\OneDrive\*") {
        Write-Host "Files found within the OneDrive folder! Checking to see if a folder named OneDriveBackupFiles exists."
        Start-Sleep 1
        If (Test-Path "$env:USERPROFILE\Desktop\OneDriveBackupFiles") {
            Write-Host "A folder named OneDriveBackupFiles already exists on your desktop. All files from your OneDrive location will be moved to that folder." 
        } else {
            If (!(Test-Path "$env:USERPROFILE\Desktop\OneDriveBackupFiles")) {
                Write-Host "A folder named OneDriveBackupFiles will be created and will be located on your desktop. All files from your OneDrive location will be located in that folder."
                New-item -Path "$env:USERPROFILE\Desktop" -Name "OneDriveBackupFiles"-ItemType Directory -Force
                Write-Host "Successfully created the folder 'OneDriveBackupFiles' on your desktop."
            }
        }
        Start-Sleep 1
        Move-Item -Path "$env:USERPROFILE\OneDrive\*" -Destination "$env:USERPROFILE\Desktop\OneDriveBackupFiles" -Force
        Write-Host "Successfully moved all files/folders from your OneDrive folder to the folder 'OneDriveBackupFiles' on your desktop."
        Start-Sleep 1
        Write-Host "Proceeding with the removal of OneDrive."
        Start-Sleep 1
    } else {
        Write-Host "Either the OneDrive folder does not exist or there are no files to be found in the folder. Proceeding with removal of OneDrive."
        Start-Sleep 1
        Write-Host "Enabling the Registry Key 'Prevent the usage of OneDrive for File Storage'."
        $OneDriveKey = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
        If (!(Test-Path $OneDriveKey)) { Mkdir $OneDriveKey }
        Set-ItemProperty $OneDriveKey -Name OneDrive -Value DisableFileSyncNGSC
    }
    Write-Host "Uninstalling OneDrive. Please wait..."
    New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    $ExplorerReg1 = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    $ExplorerReg2 = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    Stop-Process -Name "OneDrive*"
    Start-Sleep 2
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
        New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
        $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
        $ExplorerReg1 = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        $ExplorerReg2 = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
        Stop-Process -Name "OneDrive*"
        Start-Sleep 2
        If (!(Test-Path $onedrive)) { $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe" }
        Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
        Start-Sleep 2
        Write-Output "Stopping explorer"
        Start-Sleep 1
        taskkill.exe /F /IM explorer.exe
        Start-Sleep 3
        Write-Output "Removing leftover files"
        Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse
        Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse
        Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse
        If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") { Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse }
        Write-Output "Removing OneDrive from windows explorer"
        If (!(Test-Path $ExplorerReg1)) { New-Item $ExplorerReg1 }
        Set-ItemProperty $ExplorerReg1 System.IsPinnedToNameSpaceTree -Value 0 
        If (!(Test-Path $ExplorerReg2)) { New-Item $ExplorerReg2 }
        Set-ItemProperty $ExplorerReg2 System.IsPinnedToNameSpaceTree -Value 0
        Write-Output "Restarting Explorer that was shut down before."
        Start-Process explorer.exe -NoNewWindow
        Write-Host "Enabling the Registry Key 'Prevent the usage of OneDrive for File Storage'."
        $OneDriveKey = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
        If (!(Test-Path $OneDriveKey)) { Mkdir $OneDriveKey }
        Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
        Start-Sleep 2
        Write-Host "Stopping explorer"
        Start-Sleep 1
        taskkill.exe /F /IM explorer.exe
        Start-Sleep 3
        Write-Host "Removing leftover files"
        If (Test-Path "$env:USERPROFILE\OneDrive") { Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse }
        If (Test-Path "$env:LOCALAPPDATA\Microsoft\OneDrive") { Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse }
        If (Test-Path "$env:PROGRAMDATA\Microsoft OneDrive") { Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse }
        If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") { Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse }
        Write-Host "Removing OneDrive from windows explorer"
        If (!(Test-Path $ExplorerReg1)) { New-Item $ExplorerReg1 }
        Set-ItemProperty $ExplorerReg1 System.IsPinnedToNameSpaceTree -Value 0 
        If (!(Test-Path $ExplorerReg2)) { New-Item $ExplorerReg2 }
        Set-ItemProperty $ExplorerReg2 System.IsPinnedToNameSpaceTree -Value 0
        Write-Host "Restarting Explorer that was shut down before."
        Start-Process explorer.exe -NoNewWindow
        Write-Host "OneDrive has been successfully uninstalled!"
        Remove-item env:OneDrive
    }
}

Function UninstallEdge {
    [String] $ProgramX86 = "$env:SystemDrive\Program Files (x86)"
    [String] $edgepath = "$ProgramX86\Microsoft\Edge\Application\*.*.*.*\Installer"
    [String] $arguments = "--uninstall --system-level --verbose-logging --force-uninstall"
    if (Test-Path "$ProgramX86\Microsoft\Edge\Application") {
        Write-Host "Uninstalling Microsoft Edge!"
        Start-Process -FilePath "$edgepath\setup.exe" -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -Wait
        "\MicrosoftEdgeUpdateTaskMachineUA", "\MicrosoftEdgeUpdateTaskMachineCore" | ForEach-Object { Disable-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue | Out-Null }
        [Array] @("edgeupdatem", "edgeupdate", "MicrosoftEdgeElevationService") | ForEach-Object {
			Set-Service -Name $_ -StartupType Disabled -ErrorAction SilentlyContinue | Out-Null
			Stop-Service -Name $_ -NoWait -Force -ErrorAction SilentlyContinue | Out-Null
		}
        New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name DisableEdgeDesktopShortcutCreation -PropertyType DWORD -Value 1
        Write-Host "Microsoft Edge is removed"
    } else { Write-Host "Microsoft Edge is not even installed?!" }
}