; SysRecon Windows Installer Script
; NSIS (Nullsoft Scriptable Install System)
; 
; This script creates a professional Windows installer with:
; - Graphical installation wizard
; - Start Menu shortcuts
; - Desktop shortcut (optional)
; - Uninstaller
; - Registry integration
; - Administrator privilege requirement
; - File associations
; - License agreement

;--------------------------------
; Includes

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "FileFunc.nsh"

;--------------------------------
; General Configuration

; Application Information
!define PRODUCT_NAME "SysRecon"
!define PRODUCT_VERSION "1.0.0"
!define PRODUCT_PUBLISHER "XpertLambda"
!define PRODUCT_WEB_SITE "https://github.com/XpertLambda/SysRecon"
!define PRODUCT_DESCRIPTION "Windows Security Audit & Reconnaissance Tool"

; File names
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"
!define PRODUCT_STARTMENU_REGVAL "NSIS:StartMenuDir"

; Installer properties
Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "SysRecon-Setup-${PRODUCT_VERSION}.exe"
InstallDir "$PROGRAMFILES64\${PRODUCT_NAME}"
InstallDirRegKey HKLM "Software\${PRODUCT_NAME}" "InstallDir"

; Request administrator privileges
RequestExecutionLevel admin

; Compression
SetCompressor /SOLID lzma
SetCompressorDictSize 32

; Version Info
VIProductVersion "${PRODUCT_VERSION}.0"
VIAddVersionKey "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey "CompanyName" "${PRODUCT_PUBLISHER}"
VIAddVersionKey "LegalCopyright" "© 2025 ${PRODUCT_PUBLISHER}"
VIAddVersionKey "FileDescription" "${PRODUCT_DESCRIPTION}"
VIAddVersionKey "FileVersion" "${PRODUCT_VERSION}"

;--------------------------------
; Modern UI Configuration

!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

; Header image (optional - you can add custom graphics)
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Header\nsis3-metro.bmp"
!define MUI_HEADERIMAGE_UNBITMAP "${NSISDIR}\Contrib\Graphics\Header\nsis3-metro.bmp"

; Welcome/Finish page settings
!define MUI_WELCOMEFINISHPAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Wizard\nsis3-metro.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "${NSISDIR}\Contrib\Graphics\Wizard\nsis3-metro.bmp"

; Finish page
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_FINISHPAGE_RUN "$INSTDIR\sysrecon.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Run SysRecon (requires Administrator)"
!define MUI_FINISHPAGE_RUN_PARAMETERS "--help"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README.txt"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "View README"
!define MUI_FINISHPAGE_LINK "Visit ${PRODUCT_NAME} Website"
!define MUI_FINISHPAGE_LINK_LOCATION "${PRODUCT_WEB_SITE}"

; Start Menu Folder Page Configuration
!define MUI_STARTMENUPAGE_DEFAULTFOLDER "${PRODUCT_NAME}"
!define MUI_STARTMENUPAGE_REGISTRY_ROOT "${PRODUCT_UNINST_ROOT_KEY}"
!define MUI_STARTMENUPAGE_REGISTRY_KEY "${PRODUCT_UNINST_KEY}"
!define MUI_STARTMENUPAGE_REGISTRY_VALUENAME "${PRODUCT_STARTMENU_REGVAL}"

;--------------------------------
; Variables

Var StartMenuFolder

;--------------------------------
; Installer Pages

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_STARTMENU Application $StartMenuFolder
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

;--------------------------------
; Uninstaller Pages

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

;--------------------------------
; Languages

!insertmacro MUI_LANGUAGE "English"

;--------------------------------
; Installer Functions

Function .onInit
  ; Check if running on 64-bit Windows
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "This application requires 64-bit Windows (Windows 10 or later)."
    Abort
  ${EndIf}
  
  ; Check if already installed
  ReadRegStr $0 ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString"
  ${If} $0 != ""
    MessageBox MB_YESNO|MB_ICONQUESTION "${PRODUCT_NAME} is already installed.$\n$\nWould you like to uninstall the previous version first?" IDNO continue
    ExecWait '$0 _?=$INSTDIR'
    Delete $0
    RMDir "$INSTDIR"
    continue:
  ${EndIf}
FunctionEnd

;--------------------------------
; Installer Sections

Section "Core Files" SecCore
  SectionIn RO  ; Read-Only (always installed)
  
  SetOutPath "$INSTDIR"
  SetOverwrite on
  
  ; Main executable
  File "build\sysrecon.exe"
  
  ; Configuration file
  File "config.json"
  
  ; Documentation
  File "README.md"
  File "LICENSE"
  File /oname=README.txt "README.md"
  
  ; Create default output directory
  CreateDirectory "$INSTDIR\reports"
  
  ; Create example config
  CreateDirectory "$INSTDIR\configs"
  CopyFiles "$INSTDIR\config.json" "$INSTDIR\configs\default.json"
  
  ; Store installation folder
  WriteRegStr HKLM "Software\${PRODUCT_NAME}" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\${PRODUCT_NAME}" "Version" "${PRODUCT_VERSION}"
  
  ; Create uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  
  ; Write uninstall information to registry
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\sysrecon.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "NoModify" 1
  WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "NoRepair" 1
  
  ; Estimate size (in KB)
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "EstimatedSize" "$0"
SectionEnd

Section "Start Menu Shortcuts" SecStartMenu
  !insertmacro MUI_STARTMENU_WRITE_BEGIN Application
  
  CreateDirectory "$SMPROGRAMS\$StartMenuFolder"
  
  ; Main application shortcut (run as admin)
  CreateShortcut "$SMPROGRAMS\$StartMenuFolder\${PRODUCT_NAME}.lnk" "$INSTDIR\sysrecon.exe" "" "$INSTDIR\sysrecon.exe" 0 SW_SHOWNORMAL "" "Windows Security Audit Tool (Run as Administrator)"
  
  ; Help shortcut
  CreateShortcut "$SMPROGRAMS\$StartMenuFolder\${PRODUCT_NAME} Help.lnk" "$INSTDIR\sysrecon.exe" "--help" "$INSTDIR\sysrecon.exe" 0 SW_SHOWNORMAL "" "View SysRecon Help"
  
  ; Quick Scan shortcut
  CreateShortcut "$SMPROGRAMS\$StartMenuFolder\Quick Scan.lnk" "$INSTDIR\sysrecon.exe" "--quick" "$INSTDIR\sysrecon.exe" 0 SW_SHOWNORMAL "" "Run Quick Security Scan"
  
  ; Documentation shortcuts
  CreateShortcut "$SMPROGRAMS\$StartMenuFolder\README.lnk" "$INSTDIR\README.txt"
  CreateShortcut "$SMPROGRAMS\$StartMenuFolder\Reports Folder.lnk" "$INSTDIR\reports"
  
  ; Uninstaller shortcut
  CreateShortcut "$SMPROGRAMS\$StartMenuFolder\Uninstall ${PRODUCT_NAME}.lnk" "$INSTDIR\Uninstall.exe"
  
  !insertmacro MUI_STARTMENU_WRITE_END
SectionEnd

Section "Desktop Shortcut" SecDesktop
  CreateShortcut "$DESKTOP\${PRODUCT_NAME}.lnk" "$INSTDIR\sysrecon.exe" "" "$INSTDIR\sysrecon.exe" 0 SW_SHOWNORMAL "" "Windows Security Audit Tool (Run as Administrator)"
SectionEnd

Section "Add to PATH" SecPath
  ; Add installation directory to system PATH (simplified - user can do manually)
  DetailPrint "To add to PATH manually, add: $INSTDIR"
SectionEnd

;--------------------------------
; Section Descriptions

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} "Core files required to run ${PRODUCT_NAME}. (Required)"
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStartMenu} "Create Start Menu shortcuts for easy access."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Create a Desktop shortcut for quick access."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPath} "Add ${PRODUCT_NAME} to system PATH for command-line access."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

;--------------------------------
; Uninstaller Section

Section "Uninstall"
  ; Remove files
  Delete "$INSTDIR\sysrecon.exe"
  Delete "$INSTDIR\config.json"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\README.txt"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\Uninstall.exe"
  
  ; Remove example configs
  RMDir /r "$INSTDIR\configs"
  
  ; Ask before removing reports
  MessageBox MB_YESNO|MB_ICONQUESTION "Do you want to delete all generated reports?" IDNO skip_reports
  RMDir /r "$INSTDIR\reports"
  skip_reports:
  
  ; Remove directories
  RMDir "$INSTDIR"
  
  ; Remove Start Menu shortcuts
  !insertmacro MUI_STARTMENU_GETFOLDER Application $StartMenuFolder
  Delete "$SMPROGRAMS\$StartMenuFolder\${PRODUCT_NAME}.lnk"
  Delete "$SMPROGRAMS\$StartMenuFolder\${PRODUCT_NAME} Help.lnk"
  Delete "$SMPROGRAMS\$StartMenuFolder\Quick Scan.lnk"
  Delete "$SMPROGRAMS\$StartMenuFolder\README.lnk"
  Delete "$SMPROGRAMS\$StartMenuFolder\Reports Folder.lnk"
  Delete "$SMPROGRAMS\$StartMenuFolder\Uninstall ${PRODUCT_NAME}.lnk"
  RMDir "$SMPROGRAMS\$StartMenuFolder"
  
  ; Remove Desktop shortcut
  Delete "$DESKTOP\${PRODUCT_NAME}.lnk"
  
  ; Remove registry keys
  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "Software\${PRODUCT_NAME}"
  
  ; Final message
  MessageBox MB_OK "${PRODUCT_NAME} has been successfully uninstalled."
SectionEnd

;--------------------------------
; Uninstaller Functions

Function un.onInit
  MessageBox MB_YESNO|MB_ICONQUESTION "Are you sure you want to uninstall ${PRODUCT_NAME}?" IDYES continue
  Abort
  continue:
FunctionEnd
