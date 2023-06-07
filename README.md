# CrowdStrike-Hunting
CrowdStrike Event Query - Threat Hunting Queries

**Remote Administration Tool Usage**
Detections execution of files associated with remote administration/remote management tools and groups them by product and source host.
````
event_platform=win event_simpleName=ProcessRollup2 FileName IN (anydesk.exe, ateraagent.exe, syncrosetup.exe, connectwisechat-customer.exe, connectwisecontrol.client.exe, screenconnect.*.exe, screenconnect.windowsclient.exe, sragent.exe, srmanager.exe, srserver.exe, srservice.exe, za_connect.exe, zaservice.exe, zohotray.exe, tv_w32.exe, tv_w64.exe,TeamViewer_Service.exe, TeamViewer.exe, UltraViewer_Service.exe, GoToAssist_Corporate_Customer.exe, G2AC_Uninstaller.exe, G2AC_Service.exe, G2AC_LauncherCustomer.exe, G2AC_Installer_Admin.exe, G2AC_Installer.exe, G2AC_Host.exe, G2AC_FileTransfer.exe, G2AC_Comm.exe, g2ax_user_customer.exe, g2ax_uninstaller_customer.exe, g2ax_start.exe, g2ax_service.exe, g2ax_installer_customer_admin.exe, g2ax_installer_customer.exe, g2ax_customer_combined_dll_core_win32_x86_1702.exe, g2ax_customer_combined_dll_core_win32_x86_1702.exe, GoToAssistService.exe, gotomypc_3646.exe, g2tray.exe, g2quick.exe, JumpUpdater.exe, JumpConnect.exe, JumpClient.exe, remotesolverdispatcherservice.exe, RemoteSolverDispatcherService.exe, RemoteControl.exe, OrayReport.exe, SolarWinds.RunningModeUtility.exe, SolarWinds.MRC.Licensor.exe, DWMRC_St_64.exe, DWMRC9x_64.exe, DWMRC9x_32.exe, RemotePCLauncher.exe, RemotePC.exe, Supremo.exe, Supremo*.exe, RemotelyAnywhere.exe, RA_SSH.exe, RAGui.exe, LogMeInSystray.exe, LogMeInRC.exe, LogMeIn.exe, CallingCard.exe, GoToResolveProcessChecker.exe, ra64app.exe, LMI_Rescue.exe, Lmi_Rescue_srv.exe, Support-LogMeInRescue.exe, LMI_RescueRC.exe, bomgar-scc-*.exe, ConnAgnt.exe)| rex mode=sed field=FilePath "s/\\\Device\\\HarddiskVolume\d+/C:/g"
| rex mode=sed field=FilePath "s/\\\Users\\\(.+?)\\\/\\\Users\\\%USERNAME%\\\/g"
| eval Product=coalesce(case(match(FileName, "(?i)^(anydesk.exe)"), "AnyDesk", 
match(FileName, "(?i)^(ateraagent.exe|syncrosetup.exe)"), "Atera RMM", 
match(FileName, "(?i)^(connectwisechat-customer.exe|connectwisecontrol.client.exe)"), "ConnectWise Control", 
match(FileName, "(?i)^(screenconnect.|screenconnect.windowsclient.exe)"), "ScreenConnect", 
match(FileName, "(?i)^(sragent.exe|srmanager.exe|srserver.exe|srservice.exe)"), "Splashtop Remote", 
match(FileName, "(?i)^(za_connect.exe|zaservice.exe|zohotray.exe)"), "Zoho Assist",
match(FileName, "(?i)^(tv_w32.exe|tv_w64.exe|TeamViewer_Service.exe|TeamViewer.exe)"), "Team Viewer",
match(FileName, "(?i)^(UltraViewer_Service.exe)"), "Ultra Viewer",
match(FileName, "(?i)^(GoToAssist_Corporate_Customer.exe|G2AC_Uninstaller.exe|G2AC_Service.exe|G2AC_LauncherCustomer.exe|G2AC_Installer_Admin.exe|G2AC_Installer.exe|G2AC_Host.exe|G2AC_FileTransfer.exe|G2AC_Comm.exe|g2ax_user_customer.exe|g2ax_uninstaller_customer.exe|g2ax_start.exe|g2ax_service.exe|g2ax_installer_customer_admin.exe|g2ax_installer_customer.exe|g2ax_customer_combined_dll_core_win32_x86_1702.exe|g2ax_customer_combined_dll_core_win32_x86_1702.exe|GoToAssistService.exe)"), "Goto Assist",
match(FileName, "(?i)^(gotomypc_3646.exe|g2tray.exe|g2quick.exe)"), "Goto My PC",
match(FileName, "(?i)^(JumpUpdater.exe|JumpConnect.exe|JumpClient.exe)"), "Jump Desktop/AutoDesk",
match(FileName, "(?i)^(remotesolverdispatcherservice.exe|RemoteSolverDispatcherService.exe)"), "RemoteSolverDispatch",
match(FileName, "(?i)^(RemoteControl.exe)"), "RemoteControl",
match(FileName, "(?i)^(OrayReport.exe)"), "Sunlogin remote control",
match(FileName, "(?i)^(SolarWinds.RunningModeUtility.exe|SolarWinds.MRC.Licensor.exe|DWMRC_St_64.exe|DWMRC9x_64.exe|DWMRC9x_32.exe)"), "Dameware Remote",
match(FileName, "(?i)^(RemotePCLauncher.exe|RemotePC.exe)"), "Remote PC",
match(FileName, "(?i)^(Supremo.exe|Supremo (2).exe|Supremo (1).exe)"), "Supremo Remote Control",
match(FileName, "(?i)^(RemotelyAnywhere.exe|RA_SSH.exe|RAGui.exe)"), "Remotely Anywhere",
match(FileName, "(?i)^(LogMeInSystray.exe|LogMeInRC.exe|LogMeIn.exe|CallingCard.exe|GoToResolveProcessChecker.exe|ra64app.exe|LMI_Rescue.exe|Lmi_Rescue_srv.exe|Support-LogMeInRescue.exe|LMI_RescueRC.exe)"), "LogMeIn Resolver/Rescue/Calling Card",
match(FileName, "(?i)^(bomgar-scc-|ConnAgnt.exe)"), "Bomgar/BeyondTrust Remote"),"Other")
| eval productType=case(ProductType = "1","Workstation", ProductType = "2","Domain Controller", ProductType = "3","Server")
| stats values(FileName) as FileNames values(FilePath) as ModifiedFilePaths values(SHA256HashData) as Hashes values(productType) as HostType values(ComputerName) as Hosts count AS Occurrences dc(aid) AS HostCount by Product
| sort 0 + HostCount, + Occurrences
````
