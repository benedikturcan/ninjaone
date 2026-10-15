# NinjaOne Node Role Creation

Legt benutzerdefinierte **Node-Rollen** (node roles) in NinjaOne per Skript an - gesteuert ueber
Parameter, welche Rollen erstellt werden. Praktisch, wenn du immer wieder denselben Satz von
Server-Rollen in einem Tenant brauchst und das nicht per Hand im UI klicken willst.

Ein Skript: [`New-NinjaNodeRole.ps1`](New-NinjaNodeRole.ps1).

---

## TL;DR

- Authentifiziert sich mit einem **Session-Cookie** (`sessionKey`) aus einer angemeldeten
  Browser-Sitzung und sendet pro Rolle einen `POST /swb/s6/noderole`.
- **Der Session-Key steht NICHT im Skript.** Er kommt per Umgebungsvariable
  `NINJA_SESSION_KEY` oder per `-SessionKey` Parameter rein.
- `-Roles` bestimmt, was angelegt wird: `server-all` fuer alle oder einzelne Kurzschluessel
  (`sql,terminal`).
- `-WhatIf` fuer einen gefahrlosen Trockenlauf.

```powershell
$env:NINJA_SESSION_KEY = "<sessionKey-aus-dem-browser>"
.\New-NinjaNodeRole.ps1 -Roles server-all
```

---

## Verfuegbare Rollen

Alle unter der Parent-Rolle `WINDOWS_SERVER` (`nodeRoleParentId = 1`):

| Kurzschluessel | Angelegte Rolle |
| --- | --- |
| `datev` | Windows Server - DATEV |
| `sql` | Windows Server - SQL Server |
| `terminal` | Windows Server - Terminal Server |
| `application` | Windows Server - Application Server |
| `file` | Windows Server - File Server |
| `server-all` | alle fuenf oben |

---

## Session-Key besorgen

Der `sessionKey` ist ein **kurzlebiges Session-Cookie** aus einer angemeldeten NinjaOne-Sitzung,
kein API-Token. So kommst du dran:

1. In NinjaOne im Browser anmelden (z.B. `https://eu.ninjarmm.com`).
2. DevTools oeffnen -> **Application/Storage -> Cookies** -> den Wert von `sessionKey` kopieren
   (alternativ im **Network**-Tab bei einem beliebigen Request unter den Request-Headers).
3. Als Umgebungsvariable setzen (bleibt so aus der Befehlshistorie und aus dem Code raus):

   ```powershell
   $env:NINJA_SESSION_KEY = "<dein-sessionKey>"
   ```

Laeuft die Sitzung ab, kommt `401`/`403` zurueck - dann neu anmelden und den aktuellen Wert holen.

> Der Key gilt wie ein Passwort: nicht committen, nicht in Tickets/Chats posten.

---

## Verwendung

Alle Server-Rollen anlegen:

```powershell
.\New-NinjaNodeRole.ps1 -Roles server-all
```

Nur einzelne Rollen (kommagetrennt, Reihenfolge und Gross-/Kleinschreibung egal):

```powershell
.\New-NinjaNodeRole.ps1 -Roles sql,terminal
```

Trockenlauf - zeigt die geplanten Requests, sendet aber nichts:

```powershell
.\New-NinjaNodeRole.ps1 -Roles server-all -WhatIf
```

Session-Key einmalig fuer einen Lauf statt per Umgebungsvariable:

```powershell
.\New-NinjaNodeRole.ps1 -Roles sql -SessionKey "<dein-sessionKey>"
```

Andere Instanz als `eu` (z.B. `app`, `us2`):

```powershell
.\New-NinjaNodeRole.ps1 -Roles server-all -Region app
```

---

## Parameter

| Parameter | Pflicht | Default | Beschreibung |
| --- | --- | --- | --- |
| `-Roles` | ja | - | Eine/mehrere Rollen: `server-all` oder Kurzschluessel (`datev,sql,terminal,application,file`) |
| `-SessionKey` | nein | `$env:NINJA_SESSION_KEY` | Session-Cookie-Wert. Fehlt beides, bricht das Skript mit klarer Meldung ab |
| `-Region` | nein | `eu` | Instanz-Subdomain (`eu` -> `eu.ninjarmm.com`) |
| `-WhatIf` | nein | - | Trockenlauf, sendet keinen Request |

---

## Weitere Rollen hinzufuegen

Kein Code noetig - nur Daten ergaenzen. Oben im Skript gibt es zwei Strukturen:

- **`$RoleCatalog`** - eine Zeile pro Rolle (Key = Kurzschluessel):

  ```powershell
  rdp = @{ name = "Workstation - RDP Client"; nodeClass = "WINDOWS_WORKSTATION"; nodeRoleParentId = <ID> }
  ```

- **`$RoleGroups`** - Sammel-Keywords, die auf mehrere Rollen expandieren:

  ```powershell
  "workstation-all" = @("rdp","kiosk")
  ```

**Achtung:** jede Parent-Kategorie hat eine **eigene `nodeRoleParentId`**. `WINDOWS_SERVER` ist `1`.
Die ID fuer andere Klassen (`WINDOWS_WORKSTATION`, `MAC`, `LINUX_SERVER` ...) liest du im
**Network**-Tab ab, wenn du eine Rolle in der jeweiligen Kategorie ueber das UI anlegst (Wert
`nodeRoleParentId` im POST-Body).

---

## Hinweise

- Doppelte Angaben (z.B. `server-all,datev`) werden dedupliziert.
- Unbekannte Kurzschluessel brechen mit einer Liste der gueltigen Werte ab.
- Jede Rolle meldet Status (`[OK 201]` / `[FEHLER <code>]`), am Ende eine Zusammenfassung.
  Exit-Code `1`, falls mindestens eine Rolle fehlschlug.
- Das Skript nutzt den internen `/swb/s6/noderole`-Endpunkt (dieselbe Route, die das Web-UI
  verwendet), kein offizielles API - bei UI-Aenderungen kann sich das Verhalten aendern.
