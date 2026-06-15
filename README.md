# ServerManager

ServerManager ist ein eigenständiges Browser-RDP-Gateway. Pro Verbindung wird
eine isolierte FreeRDP-Sitzung in einem virtuellen X11-Bildschirm gestartet und
über x11vnc, WebSocket und noVNC in den Browser übertragen.

## Funktionen

- RDP direkt im Browser, ohne `.rdp`-Download
- Mehrbenutzerbetrieb mit Administrator- und Standardbenutzern
- Argon2id-Passwörter, TOTP und Passkey-Anmeldung über WebAuthn
- Benutzerbezogener, serverseitiger Verbindungsverlauf ohne RDP-Passwörter
- Serverweit gepflegte Domänen als Auswahl im RDP-Formular
- Administrative RDP-Sitzung über `/admin`
- Zwischenablage und mehrere Bildschirmauflösungen
- Zeitbegrenzung und automatische Bereinigung der Sitzungsprozesse
- HttpOnly-Cookie, SameSite-Schutz, Origin-Prüfung und CSRF-Token

## Start

```bash
git clone https://github.com/hxcde/ServerManager.git
cd ServerManager
cp .env.example .env
```

In `.env` ein langes, zufälliges `APP_PASSWORD` setzen. `APP_USERNAME` und
`APP_PASSWORD` erzeugen ausschließlich beim ersten Start den ersten
Administrator. Spätere Änderungen erfolgen in der Weboberfläche.

```bash
docker compose up -d --build
docker compose logs -f
```

Die Datenbank liegt im Docker-Volume `servermanager_data`. Dieses Volume muss
bei Updates und Backups erhalten bleiben.

## Nginx Proxy Manager

Für den Betrieb hinter Nginx Proxy Manager:

```env
BIND_ADDRESS=127.0.0.1
PUBLIC_URL=https://rdp.example.internal
```

Im Proxy Host:

- Forward Scheme `http`
- Forward Host: IP des ServerManager-Hosts
- Forward Port `8080`
- **Websockets Support** aktivieren
- gültiges TLS-Zertifikat verwenden

Passkeys benötigen HTTPS. `WEBAUTHN_ORIGIN` und `WEBAUTHN_RP_ID` werden
normalerweise aus `PUBLIC_URL` abgeleitet. Bei abweichenden Setups können sie
explizit gesetzt werden:

```env
WEBAUTHN_ORIGIN=https://rdp.example.internal
WEBAUTHN_RP_ID=rdp.example.internal
WEBAUTHN_RP_NAME=ServerManager
TOTP_ISSUER=ServerManager
```

Die WebAuthn-Origin muss exakt der im Browser verwendeten HTTPS-Adresse
entsprechen. Die RP-ID ist nur der Hostname, ohne Schema oder Port.

## Administration

Nach der Anmeldung steht Administratoren der Bereich `/admin` zur Verfügung.
Dort lassen sich Benutzer anlegen, deaktivieren, löschen, zu Administratoren
machen und mit einem neuen Passwort versehen. Außerdem werden dort die
Domänen gepflegt, die im RDP-Formular auswählbar sind.

Unter `/account` kann jeder Benutzer:

- das eigene Passwort ändern
- TOTP einrichten oder deaktivieren
- Passkeys registrieren und löschen

## Sicherheit

Die Anwendung sollte nur in einem geschützten Management-Netz betrieben
werden.

- Zugriff zusätzlich über VPN, Zero-Trust-Proxy oder IP-Allowlist begrenzen.
- Port 8080 nicht ungeschützt aus dem Internet erreichbar machen.
- Das persistente Datenvolume sichern und vor unbefugtem Zugriff schützen.
- `Zertifikat ignorieren` nur für bekannte interne Systeme aktivieren.
- RDP-Ziele per Firewall auf den Gateway-Server beschränken.

RDP-Passwörter werden nur im Request empfangen, direkt über `stdin` an FreeRDP
übergeben und danach aus dem Arbeitsspeicher-Payload entfernt. Sie werden weder
im Verlauf noch in SQLite gespeichert. TOTP-Schlüssel müssen zur Verifikation
serverseitig in der geschützten SQLite-Datenbank gespeichert werden.

## Architektur

```text
Browser -> Nginx/TLS -> aiohttp -> SQLite
                         |
                         +-> WebSocket -> x11vnc -> Xvfb/Openbox
                                                   -> FreeRDP -> Windows Server
```

Wichtige Dateien:

- `app/server.py`: HTTP, Authentifizierung, WebAuthn, TOTP und APIs
- `app/storage.py`: SQLite-Schema und persistente Daten
- `app/rdp.py`: RDP-, X11- und VNC-Prozessverwaltung
- `app/static/`: Login, RDP-Oberfläche, Konto und Administration
- `docker-compose.yml`: Laufzeit, Datenvolume und Konfiguration

## Entwicklung

Backendtests:

```bash
python -m unittest discover -s tests -v
```

## Grenzen

- Keine Sitzungsaufzeichnung
- Kein zentraler Multi-Node-Scheduler
- Feste Auflösung während einer laufenden RDP-Sitzung
- Passkeys funktionieren nur unter HTTPS oder auf `localhost`
