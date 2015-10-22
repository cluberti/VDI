' // ======================================================================== 
' // Original generated with VDIOptimizer - http://www.autoitscript.com/tools 
' // (c)2010 Jonathan Bennett 
' // 
' // Current version updated by Jeff Stokes (MSFT) 
' // Last Modified: 10/18/2012 
' // ========================================================================


' // ============== 
' // General Advice 
' // ============== 
' 
' Before finalizing the image perform the following tasks: 
' - Ensure no unwanted startup files by using autoruns.exe from SysInternals 
' - Run the Disk Cleanup tool as administrator and delete all temporary files and system restore points (can be automated with this script) 
' - Run disk defrag and consolidate free space: defrag c: /v /x 
' - Reboot the machine 6 times and wait 120 seconds after logging on before performing the next reboot (boot prefetch training) 
' - Run disk defrag and optimize boot files (Windows 7 only): defrag c: /v /b 
' - If using a dynamic virtual disk, use the vendor's utilities to perform a "shrink" operation


' // ************* 
' // *  CAUTION  * 
' // ************* 
' 
' THIS SCRIPT MAKES CONSIDERABLE CHANGES TO THE DEFAULT CONFIGURATION OF WINDOWS 7. 
' 
' Please review this script THOROUGHLY before applying to your virtual machine, and disable changes below as necessary to suit your current 
' environment. 
' 
' This script is provided AS-IS - usage of this source assumes that you are at the very least familiar with the vbscript language being used and the 
' tools used to create and debug this file. 
' 
' In other words, if you break it, you get to keep the pieces.


' Constants 
Const ForReading = 1 
Const Disable_Aero = False 
Const Disable_BranchCache = False 
Const Disable_EFS = False 
Const Disable_iSCSI = False 
Const Disable_MachPass = False 
Const Disable_Search = False

' Common objects 
Set oShell = WScript.CreateObject ("WScript.Shell") 
Set oFSO = CreateObject("Scripting.FileSystemObject") 
Set oEnv = oShell.Environment("User")

' Command Line Arguments for Some Settings 
Set colNamedArguments = WScript.Arguments.Named

If colNamedArguments.Exists("Aero") Then 
     strAero = colNamedArguments.Item("Aero") 
Else 
     strAero = Disable_Aero 
End If

If colNamedArguments.Exists("BranchCache") Then 
     strBranchCache = colNamedArguments.Item("BranchCache") 
Else 
     strBranchCache = Disable_BranchCache 
End If

If colNamedArguments.Exists("EFS") Then 
     strEFS = colNamedArguments.Item("EFS") 
Else 
     strEFS = Disable_EFS 
End If

If colNamedArguments.Exists("iSCSI") Then 
     striSCSI = colNamedArguments.Item("iSCSI") 
Else 
     striSCSI = Disable_iSCSI 
End If

If colNamedArguments.Exists("MachPass") Then 
     strMachPass = colNamedArguments.Item("MachPass") 
Else 
     strMachPass = Disable_MachPass 
End If

If colNamedArguments.Exists("Search") Then 
    strSearch = colNamedArguments.Item("Search") 
Else 
    strSearch = Disable_Search 
End If

' First things first - enable RDP Connections!!! 
RunWait "WMIC rdtoggle where AllowTSConnections=0 call SetAllowTSConnections 1,1" 
RunWait "netsh advfirewall firewall set rule group=" & Chr(34) & "remote desktop" & Chr(34) & " new enable=Yes"


' // ================== 
' // Configure Services 
' // ==================

' Disable Adaptive Brightness Service 
RunWait "sc config SensrSvc start= disabled"

' Disable Application Layer Gateway Service 
RunWait "sc config ALG start= disabled"

' Disable Background Intelligent Transfer Service 
RunWait "sc config BITS start= disabled"

' Disable Background Layout Service 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OptimalLayout\EnableLayout", 0, "REG_DWORD"

' Disable Bitlocker Drive Encryption Service 
RunWait "sc config BDESVC start= disabled"

' Disable Block Level Backup Engine Service 
RunWait "sc config wbengine start= disabled"

' Disable Bluetooth Support Service 
RunWait "sc config bthserv start= disabled"

If strBranchCache = True Then 
' Disable BranchCache Service 
RunWait "sc config PeerDistSvc start= disabled" 
End If

' Disable Computer Browser Service 
RunWait "sc config Browser start= disabled"

' Disable Diagnostic Policy Service 
RunWait "sc config DPS start= disabled"

' Disable Disk Defragmenter Service 
RunWait "schtasks /change /tn ""microsoft\windows\defrag\ScheduledDefrag"" /disable" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction\Enable", "N", "REG_SZ" 
RunWait "sc config defragsvc start= disabled"

' Disable Distributed Link Tracking Service 
RunWait "sc stop TrkWks" 
RunWait "sc config TrkWks start= disabled"

If strEFS = True Then 
' Disable Encrypting File System Service 
RunWait "sc config EFS start= disabled" 
End If

' Disable Function Discovery Resource Publication Service 
RunWait "sc config fdPHost start= disabled"

' Disable HomeGroup Listener Service 
RunWait "sc config HomeGroupListener start= disabled"

' Disable HomeGroup Provider Service 
RunWait "sc config HomeGroupProvider start= disabled"

If striSCSI = True Then 
' Disable Microsoft iSCSI Provider Service 
RunWait "sc config msiscsi start= disabled" 
End If

' Disable Microsoft Software Shadow Copy Provider Service 
RunWait "sc config swprv start= disabled"

' Disable Parental Controls Service 
RunWait "sc config WPCSvc start= disabled"

' Disable Secure Socket Tunneling Protocol Service 
RunWait "sc config SstpSvc start= disabled"

' Disable Shell Hardware Detection Service 
RunWait "sc config ShellHWDetection start= disabled"

' Disable SNMP Trap Service 
RunWait "sc config SNMPTRAP start= disabled"

' Disable Superfetch Service 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher", &H00000000, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnableSuperfetch", &H00000000, "REG_DWORD" 
RunWait "sc stop SysMain" 
RunWait "sc config SysMain start= disabled"

' Disable SSDP Discovery Service 
RunWait "sc stop SSDPSRV" 
RunWait "sc config SSDPSRV start= disabled"

' Disable Tablet PC Input Service 
RunWait "sc config TabletInputService start= disabled"

' Disable Telephony Service 
RunWait "sc config TapiSrv start= disabled"

' Disable TPM Base Services Service 
RunWait "sc config TBS start= disabled"

' Disable UPnP Device Host Service 
RunWait "sc config upnphost start= disabled"

' Disable Windows Backup Service 
RunWait "sc config SDRSVC start= disabled"

' Disable Windows CardSpace Service 
RunWait "sc config idsvc start= disabled"

' Disable Windows Color System Service 
RunWait "sc config WcsPlugInService start= disabled"

' Disable Windows Connect Now - Config Registrar Service 
RunWait "sc config wcncsvc start= disabled"

' Disable Windows Defender Service 
RunWait "schtasks /change /tn ""microsoft\windows Defender\MPIdleTask"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows Defender\MP Scheduled Scan"" /disable" 
RunWait "sc stop WinDefend" 
RunWait "sc config WinDefend start= disabled"

' Disable Windows Error Reporting Service 
RunWait "sc config WerSvc start= disabled"

' Disable Windows Media Center Receiver Service 
RunWait "sc config ehRecvr start= disabled"

' Disable Windows Media Center Scheduler Service 
RunWait "sc config ehSched start= disabled"

' Disable Windows Media Player Network Sharing Service 
RunWait "sc config WMPNetworkSvc start= disabled"

' Break out Windows Management Instrumentation Service 
RunWait "winmgmt /standalonehost" 
RunWait "sc config winmgmt group= COM Infrastructure"

'Disable Windows Search Service 
If strSearch = True Then 
    RunWait "sc stop WSearch" 
    RunWait "sc config WSearch start= disabled" 
End If

' Disable Wireless Zero Configuration Service 
RunWait "sc config WZCSVC start= disabled"

' Disable WLAN AutoConfig Service 
RunWait "sc config Wlansvc start= disabled"

' Disable WWAN AutoConfig Service 
RunWait "sc config WwanSvc start= disabled"


' // ================ 
' // MACHINE SETTINGS 
' // ================

' Do you want users to have the ability to use Aero themes for their desktop when connecting? 
' If so, leave these two services enabled.  Disabling these services will disable Aero and DWM, and 
' thus disable the use of any Aero themes: 
If strAero = True Then 
    ' Disable Desktop Window Manager Session Manager Service 
    RunWait "sc config UxSms start= disabled" 
    ' Disable Themes Service 
    RunWait "sc config Themes start= disabled" 
End If


' Disable Hard disk timeouts 
RunWait "POWERCFG /SETACVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0" 
RunWait "POWERCFG /SETDCVALUEINDEX 381b4222-f694-41f0-9685-ff5bb260df2e 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0"


' Disable TCP/IP / Large Send Offload 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DisableTaskOffload", &H00000001, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BNNS\Parameters\EnableOffload", &H00000000, "REG_DWORD"


' Disable hibernate 
RunWait "powercfg -h off"


' Disable System Restore 
Set objWMIService = GetObject("winmgmts:\\.\root\default") 
Set objItem = objWMIService.Get("SystemRestore") 
objItem.Disable("") 
RunWait "schtasks /change /tn ""microsoft\windows\SystemRestore\SR"" /disable" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\SystemRestore\DisableSR", &H00000001, "REG_DWORD"


' Disable NTFS Last Access Timestamps 
RunWait "FSUTIL behavior set disablelastaccess 1"


If strMachPass = True Then 
    ' Disable Machine Account Password Changes 
    oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\DisablePasswordChange", &H00000001, "REG_DWORD" 
End If


' Disable memory dumps 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\CrashDumpEnabled", &H00000000, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\LogEvent", &H00000000, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\SendAlert", &H00000000, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CrashControl\AutoReboot", &H00000001, "REG_DWORD"


' Disable default system screensaver 
oShell.RegWrite "HKEY_USERS\.DEFAULT\Control Panel\Desktop\ScreenSaveActive", 0, "REG_DWORD"


' Increase service startup timeouts 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\ServicesPipeTimeout", &H0002bf20, "REG_DWORD"


' Increase Disk I/O Timeout to 200 seconds. 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Disk\TimeOutValue", &H000000C8, "REG_DWORD"


' Disable Other Scheduled Tasks 
RunWait "schtasks /change /tn ""microsoft\windows\Application Experience\AitAgent"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\Application Experience\ProgramDataUpdater"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\Autochk\Proxy"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\Customer Experience Improvement Program\Consolidator"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\Customer Experience Improvement Program\KernelCeipTask"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\Customer Experience Improvement Program\UsbCeip"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\Diagnosis\Scheduled"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\Maintenance\WinSAT"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\MobilePC\HotStart"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\Power Efficiency Diagnostic\AnalyzeSystem"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\RAC\RacTask"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\Ras\MobilityManager"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\Registry\RegIdleBackup"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\SideShow\AutoWake"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\SideShow\GadgetManager"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\SideShow\SessionAgent"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\SideShow\SystemDataProviders"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\WDI\ResolutionHost"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\Windows Filtering Platform\BfeOnServiceStartTypeChange"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\Windows Media Sharing\UpdateLibrary"" /disable" 
RunWait "schtasks /change /tn ""microsoft\windows\Windows Backup\ConfigNotification"" /disable"


' Configure Event Logs to 1028KB (Minimum size under Vista/7) and set retention to "overwrite" 
Set oEventLogs = GetObject("winmgmts:{impersonationLevel=impersonate,(Security)}!//./root/cimv2").InstancesOf("Win32_NTEventLogFile") 
For Each e in oEventLogs 
    e.MaxFileSize = 1052672 
    e.OverWritePolicy = "WhenNeeded" 
    e.OverWriteOutdated = 0 
    e.Put_ 
    e.ClearEventLog() 
Next

oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\eventlog\Application\Retention", 0, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\eventlog\Security\Retention", 0, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\eventlog\System\Retention", 0, "REG_DWORD"


' Set PopUp Error Mode to "Neither" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Windows\ErrorMode", 2, "REG_DWORD"


' Disable bootlog and boot animation 
RunWait "bcdedit /set {default} bootlog no" 
RunWait "bcdedit /set {default} quietboot yes"


' Disable UAC secure desktop prompt 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\PromptOnSecureDesktop", &H00000000, "REG_DWORD"


' Disable New Network dialog 
RunWait "reg add HKLM\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff"


' Disable AutoUpdate of drivers from WU 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching\searchorderConfig", 0, "REG_DWORD"


' Turn off Windows Gadget Platform, Media Center, Tablet PC Components, Windows DVD Maker, and Windows SideShow 
RunWait "dism /online /Disable-Feature /FeatureName:WindowsGadgetPlatform /NoRestart" 
RunWait "dism /online /Disable-Feature /FeatureName:MediaCenter /NoRestart" 
RunWait "dism /online /Disable-Feature /FeatureName:TabletPCOC /NoRestart" 
RunWait "dism /online /Disable-Feature /FeatureName:OpticalMediaDisc /NoRestart" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Sideshow\Disabled", 1, "REG_DWORD"


' Disable IE First Run Wizard and RSS Feeds 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Internet Explorer\Main\DisableFirstRunCustomize", 1, "REG_DWORD"


' Disable the ability to clear the paging file during shutdown 
oShell.RegWrite "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SessionManager\Memory Management\ClearPageFileAtShutdown", 0, "REG_DWORD"


' Perform a disk cleanup 
' Automate by creating the reg checks corresponding to "cleanmgr /sageset:100" so we can use "sagerun:100" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Memory Dump Files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations\StateFlags0100", &H00000000, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Upgrade Discarded Files\StateFlags0100", &H00000000, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Archive Files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Queue Files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting System Archive Files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting System Queue Files\StateFlags0100", &H00000002, "REG_DWORD" 
oShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files\StateFlags0100", &H00000002, "REG_DWORD" 
RunWait "cleanmgr.exe /sagerun:100"

 

' // ============= 
' // USER SETTINGS 
' // =============

' Reduce menu show delay 
oShell.RegWrite "HKEY_CURRENT_USER\Control Panel\Desktop\MenuShowDelay", "0", "REG_SZ"


' Disable cursor blink 
oShell.RegWrite "HKEY_CURRENT_USER\Control Panel\Desktop\CursorBlinkRate", "-1", "REG_SZ" 
oShell.RegWrite "HKEY_CURRENT_USER\Control Panel\Desktop\DisableCursorBlink", &H00000001, "REG_DWORD"


' Force off-screen composition in IE 
oShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main\Force Offscreen Composition", &H00000001, "REG_DWORD"


' Disable screensavers 
oShell.RegWrite "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop\ScreenSaveActive", "0", "REG_SZ" 
oShell.RegWrite "HKEY_CURRENT_USER\Control Panel\Desktop\ScreenSaveActive", "0", "REG_SZ" 
oShell.RegWrite "HKEY_USERS\.DEFAULT\Control Panel\Desktop\ScreenSaveActive", "0", "REG_SZ"


' Don't show window contents when dragging 
oShell.RegWrite "HKEY_CURRENT_USER\Control Panel\Desktop\DragFullWindows", "0", "REG_SZ"


' Don't show window minimize/maximize animations 
oShell.RegWrite "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics\MinAnimate", "0", "REG_SZ"


' Disable font smoothing 
oShell.RegWrite "HKEY_CURRENT_USER\Control Panel\Desktop\FontSmoothing", "0", "REG_SZ"


' Disable most other visual effects 
oShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\VisualFXSetting", &H00000003, "REG_DWORD" 
oShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ListviewAlphaSelect", &H00000000, "REG_DWORD" 
oShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarAnimations", &H00000000, "REG_DWORD" 
oShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ListviewWatermark", &H00000000, "REG_DWORD" 
oShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ListviewShadow", &H00000000, "REG_DWORD" 
RegBinWrite "HKEY_CURRENT_USER\Control Panel\Desktop", "UserPreferencesMask", "90,12,01,80"


' Disable Action Center 
oShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\HideSCAHealth", &H00000001, "REG_DWORD"


' Disable IE Persistent Cache 
oShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Cache\Persistent", 0, "REG_DWORD" 
oShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Feeds\SyncStatus", 0, "REG_DWORD"


' Done 
WScript.Quit

 

 


' // ================ 
' // HELPER FUNCTIONS 
' // ================

Function Run(sFile) 
    Run = oShell.Run(sFile, 1, False) 
End Function


Function RunWait(sFile) 
    RunWait = oShell.Run(sFile, 1, True) 
End Function


Function RunWaitHidden(sFile) 
    RunWaitHidden = oShell.Run(sFile, 0, True) 
End Function


Function IsServer() 
    IsServer = False 
    On Error Resume Next 
    For Each objOS in GetObject("winmgmts:").InstancesOf ("Win32_OperatingSystem") 
        If objOS.ProductType = 1 Then IsServer = False 
        If objOS.ProductType = 2 Or ObjOS.ProductType = 3 Then IsServer = True 
    Next 
End Function


Sub RegBinWrite (key, value, data) 
    key = "[" & key & "]"

    If value <> "@" then 
        value = chr(34) & value & chr(34) 
    End if

    valString = value & "=" & "hex:" & data

    tempFile = GetTempDir() & "\regbinaryimport.reg" 
    Set txtStream = oFSO.CreateTextFile(tempFile,true) 
    txtStream.WriteLine("Windows Registry Editor Version 5.00") 
    txtStream.WriteLine(key) 
    txtStream.WriteLine(valString) 
    txtStream.Close

    oShell.Run "regedit.exe /s """ & tempFile & """", 1, true

    oFSO.DeleteFile tempFile 
End Sub


Function GetTEMPDir() 
    GetTEMPDir = oEnv("TEMP") 
    If InStr(GetTEMPDir, "%") Then 
        GetTEMPDir = oShell.ExpandEnvironmentStrings(GetTEMPDir) 
    End If 
End Function