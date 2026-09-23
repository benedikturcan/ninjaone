# Install-WingetMachine.ps1

Installiert ein oder mehrere Winget-Pakete im Machine-Scope. Ausgelegt für den Einsatz
als NinjaOne-Automation unter dem SYSTEM-Konto, funktioniert aber in jedem elevated
Kontext. Aktuelle Version: **1.4.4**.

## Voraussetzungen

- Windows 10/11 (x64 oder ARM64), Windows PowerShell 5.1 oder PowerShell 7
- Ausfuehrung elevated (SYSTEM oder Administrator) – wird vom Skript geprueft
- Funktionsfaehiges winget (App Installer >= ca. 1.4) auf dem Endpoint
  - Das Skript findet winget auch unter SYSTEM (Scan von `%ProgramFiles%\WindowsApps`)
    und prueft jeden Kandidaten per `winget --version`, bevor er verwendet wird
  - Das Skript repariert winget **nicht** selbst (bewusste Design-Entscheidung, s. u.)
- Windows Server 2022: winget wird dort von Microsoft nicht ausgeliefert und nicht
  offiziell unterstuetzt. Nachruesten ist moeglich (s. Troubleshooting), aber fuer
  Server ist ein direkter Vendor-Installer meist die robustere Wahl.

## Einrichtung in NinjaOne

Skript als PowerShell-Automation anlegen, Ausfuehrung **als System**. Erfolg wird ueber
den Exit-Code bewertet (0 = Erfolg, 1 = Fehler).

Drei Script Variables anlegen und als dynamische Skriptvariablen mappen. Die Namen
muessen exakt stimmen (das Skript liest sie ueber `$env:`):

| Variable        | Typ            | Pflicht | Beschreibung |
|-----------------|----------------|---------|--------------|
| `wingetId`      | Text           | ja      | Winget-Paket-ID, mehrere kommagetrennt. Beispiel: `Microsoft.PowerShell` oder `Microsoft.PowerShell,7zip.7zip`. Erlaubte Zeichen: Buchstaben, Ziffern, `. + _ -` |
| `wingetVersion` | Text           | nein    | Exakte Version(en), kommagetrennt. Anzahl muss bei Befuellung der Anzahl der IDs entsprechen. Leer = neueste Version |
| `architecture`  | Text/Dropdown  | nein    | Erzwungene Zielarchitektur: `x64`, `x86` oder `arm64`. Leer = Geraetearchitektur wird automatisch ermittelt (empfohlener Standard) |

## Parameter (optional, ohne Script Variables)

| Parameter                | Default | Beschreibung |
|--------------------------|---------|--------------|
| `-Id`                    | `$env:wingetId` | Paket-ID(s) |
| `-Version`               | `$env:wingetVersion` | Version(en) |
| `-Architecture`          | `$env:architecture` | Zielarchitektur |
| `-LogPath`               | auto    | Pfad der Logdatei; Default: `%TEMP%\winget-install-<Id>-<Zeitstempel>.log` (unter SYSTEM: `C:\Windows\Temp`) |
| `-ShowTimeoutSeconds`    | 120     | Timeout fuer `winget show` (Scope-Pruefung) |
| `-InstallTimeoutSeconds` | 1800    | Timeout fuer `winget install`; bei Timeout wird der gesamte Prozessbaum beendet |

## Verhalten

1. Elevation-Check, winget-Suche inkl. Funktionsprobe
2. Pro Paket: Validierung von Id/Version, `winget show` zur Machine-Scope-Pruefung
   (schlaegt das Parsen fehl, z. B. wegen lokalisierter winget-Ausgabe, wird die
   Installation trotzdem versucht und im Log als `Indeterminate` markiert)
3. `winget install --scope machine --silent`; "bereits installiert" wird ueber
   winget-Exit-Codes erkannt und zaehlt als Erfolg (`AlreadyInstalled`)
4. Kopie der passenden Startmenue-Verknuepfung auf den Public Desktop
   (Token-Matching gegen die Paket-ID; keine Kopie, wenn nichts passt)
5. Zusammenfassung pro Paket im Log, Exit-Code 0/1

Exit-Codes: **0** = alle Pakete erfolgreich (inkl. AlreadyInstalled),
**1** = mindestens ein Paket fehlgeschlagen oder fataler Fehler.

## Troubleshooting (bekannte Fehlerbilder)

**`winget candidate failed startup probe ... 0xC0000135`**
Der App Installer auf dem Geraet ist beschaedigt oder nur teilweise installiert
(STATUS_DLL_NOT_FOUND, typischerweise fehlende VCLibs/UI.Xaml-Abhaengigkeiten).
Das Skript verwirft den Kandidaten und probiert aeltere Versionsordner. Gibt es
keinen funktionierenden, bricht es ab. Reparatur einmalig elevated ausfuehren:

```powershell
Install-Module Microsoft.WinGet.Client -Force
Repair-WinGetPackageManager -AllUsers -Force -Latest
```

**`winget is not available or not functional on this device`**
Kein funktionsfaehiges winget gefunden. Gleiche Reparatur wie oben. Das Skript
repariert bewusst nicht selbst: `Add-AppxPackage` ist unter SYSTEM von Windows
blockiert (0x80073CF9), und Modul-Installationen als Nebeneffekt eines
Install-Skripts sind unerwuenscht. Die Reparatur gehoert in ein separates
Remediation-Skript.

**`Wrapped installer reported its own exit code: <n>`**
winget selbst lief sauber, der Hersteller-Installer ist gescheitert. Der Code ist
herstellerspezifisch (Beispiel Citrix Workspace: Codes 4xxxx, dokumentiert in
Citrix CTX695019). In den Installer-Logs des Herstellers nachsehen.

**ARM64-Geraete**
Bietet das winget-Manifest keinen ARM64-Installer an, laedt winget den x64-Installer
(Emulation). Manche Installer (z. B. Citrix Workspace) scheitern dann. Vorab pruefen
mit `winget show <Id>` (Installer-Bloecke ansehen); ggf. den nativen ARM64-Installer
des Herstellers separat ausrollen.

**Uneinheitliche Ergebnisse auf Bestandsgeraeten**
Manuell installierte Altversionen werden von winget teils unter anderer ID erkannt
(Beispiel: alte Citrix-Installationen als `CitrixOnlinePluginPackWeb`). winget
installiert dann ggf. "drueber" statt `AlreadyInstalled` zu melden.

## Logdatei

Zusaetzlich zur NinjaOne-Ausgabe schreibt das Skript nach
`C:\Windows\Temp\winget-install-<Id>-<Zeitstempel>.log` (unter SYSTEM).
Format: `yyyy-MM-dd HH:mm:ss [Level] Nachricht`. Fehler gehen zusaetzlich auf
stderr und erscheinen in NinjaOne rot.

## Changelog

Siehe Kopfkommentar in `Install-WingetMachine.ps1`.

## Haftungsausschluss

Bereitgestellt wie besehen (AS IS), ohne Gewaehr. Nutzung auf eigenes Risiko.
