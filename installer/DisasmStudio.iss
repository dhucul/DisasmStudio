; Inno Setup script for DisasmStudio.
; Packages the self-contained Release publish (no .NET runtime prerequisite).
;
; Build the payload first, then compile this script:
;   dotnet publish src\DisasmStudio.Wpf -c Release -r win-x64 --self-contained true -p:PublishSingleFile=false -p:DebugType=none
;   "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" installer\DisasmStudio.iss
; Output: installer\Output\DisasmStudio-Setup-<version>.exe

#define MyAppName "DisasmStudio"
#define MyAppVersion "2.10.0"
#define MyAppPublisher "David Hucul"
#define MyAppExeName "DisasmStudio.exe"
#define PublishDir "..\src\DisasmStudio.Wpf\bin\Release\net10.0-windows\win-x64\publish"
#define IconFile "..\src\DisasmStudio.Wpf\DisasmStudio.ico"

[Setup]
AppId={{A7F3C2E1-9B4D-4E6A-8C1F-2D5B7E9A1C3F}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
OutputDir=Output
OutputBaseFilename=DisasmStudio-Setup-{#MyAppVersion}
SetupIconFile={#IconFile}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; All-users (Program Files) by default; the user can choose "just me" on the privileges dialog.
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "{#PublishDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#MyAppName}}"; Flags: nowait postinstall skipifsilent
