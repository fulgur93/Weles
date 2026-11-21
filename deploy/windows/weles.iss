; WELES – Windows installer (Inno Setup 6). Built by deploy/windows/build-installer.sh (Linux, ISCC under Wine) or
; deploy/windows/publish.ps1 (Windows). Defines passed on the command line:
;   SourceDir – the published package (app\, runtime\ollama, runtime\models, THIRD-PARTY-NOTICES.txt)
;   AppVersion – version from Directory.Build.props;  WithAI – 1 when runtime\ is included;  OutputName – file name
;
; Per-user installation (no administrator rights): %LOCALAPPDATA%\Programs\WELES. User data (audits, database, logs)
; lives in %LOCALAPPDATA%\Weles and is kept on uninstall. WELES never writes to its installation directory.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef WithAI
  #define WithAI "0"
#endif
#ifndef OutputName
  #define OutputName "weles-setup-" + AppVersion + "-win-x64"
#endif

[Setup]
AppId={{470ADF6B-B466-44EB-8ABD-D03FD0D84C04}
AppName=WELES
AppVersion={#AppVersion}
AppVerName=WELES {#AppVersion}
AppPublisher=WELES
AppPublisherURL=https://github.com/fulgur93/Weles
AppComments=Attack Surface Intelligence – lokalny audyt bezpieczeństwa sieci z lokalnym AI
DefaultDirName={autopf}\WELES
DefaultGroupName=WELES
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
WizardStyle=modern
SetupIconFile=..\assets\weles.ico
UninstallDisplayIcon={app}\app\Weles.exe
UninstallDisplayName=WELES
OutputDir=..\..\artifacts
OutputBaseFilename={#OutputName}
; WELES and its AI engine are closed before files are replaced or removed.
CloseApplications=force
RestartApplications=no
#if WithAI == "1"
; The model (2.4 GB) exceeds the 2 GB limit of a single setup file: setup.exe + setup-1.bin, setup-2.bin… (keep them together).
DiskSpanning=yes
DiskSliceSize=max
Compression=lzma2/fast
#else
Compression=lzma2/max
#endif
SolidCompression=no

[Languages]
Name: "pl"; MessagesFile: "compiler:Languages\Polish.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
pl.AutostartTask=Uruchamiaj WELES po zalogowaniu (w tle, bez otwierania przeglądarki)
en.AutostartTask=Start WELES when I log in (in the background, without opening the browser)
pl.DemoShortcut=WELES – tryb demonstracyjny
en.DemoShortcut=WELES – demo mode
pl.LaunchNow=Uruchom WELES
en.LaunchNow=Start WELES
pl.DataKept=Wyniki audytów i baza danych pozostają w %LOCALAPPDATA%\Weles – usuń ten katalog ręcznie, jeśli nie są już potrzebne.
en.DataKept=Audit results and the database stay in %LOCALAPPDATA%\Weles – delete that folder manually if you no longer need them.

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "{cm:AutostartTask}"; Flags: unchecked

[Files]
Source: "{#SourceDir}\app\*"; DestDir: "{app}\app"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#SourceDir}\THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion
#if WithAI == "1"
Source: "{#SourceDir}\runtime\ollama\*"; DestDir: "{app}\runtime\ollama"; Flags: ignoreversion recursesubdirs createallsubdirs
; Model files are already compressed (GGUF) – stored as they are.
Source: "{#SourceDir}\runtime\models\*"; DestDir: "{app}\runtime\models"; Flags: ignoreversion recursesubdirs createallsubdirs nocompression
#endif

[Icons]
Name: "{autoprograms}\WELES"; Filename: "{app}\app\Weles.exe"; WorkingDir: "{app}\app"
Name: "{autoprograms}\{cm:DemoShortcut}"; Filename: "{app}\app\Weles.exe"; Parameters: "--demo"; WorkingDir: "{app}\app"
Name: "{autodesktop}\WELES"; Filename: "{app}\app\Weles.exe"; WorkingDir: "{app}\app"; Tasks: desktopicon

[Registry]
; The same value the Settings page switches (Weles.App.Hosting.Autostart) – the user can turn it off there.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "WELES"; \
  ValueData: """{app}\app\Weles.exe"" --no-browser"; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{app}\app\Weles.exe"; Description: "{cm:LaunchNow}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Only what WELES or Ollama may leave in the installation directory – never the user data in %LOCALAPPDATA%\Weles.
Type: filesandordirs; Name: "{app}\runtime\ollama\*.log"

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Value: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    { Autostart switched on later in Settings is removed as well. }
    if RegQueryStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'WELES', Value) then
      RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'WELES');
    if not UninstallSilent then
      MsgBox(CustomMessage('DataKept'), mbInformation, MB_OK);
  end;
end;
