# ServerManager

ServerManager ist ein eigenständiger Browser-RDP-Gateway-MVP für einen Linux-Server. Er startet pro Verbindung eine isolierte FreeRDP-Sitzung in einem virtuellen X11-Bildschirm und überträgt diesen über x11vnc, WebSocket und noVNC in den Browser.

## Funktionen

- RDP direkt im Browser, ohne `.rdp`-Download
- IP/Hostname, Port, Benutzername und Domäne
- Administrative RDP-Sitzung über `/admin`
- Zwischenablage und mehrere Bildschirmauflösungen
- Parallele, voneinander getrennte Sitzungsprozesse
- Automatische Zeitbegrenzung und Prozessbereinigung
- HTTP Basic Auth vor Anwendung und WebSocket
- Keine persistente Speicherung von RDP-Passwörtern

## Installation auf dem Linux-Server

```bash
git clone https://github.com/hxcde/ServerManager.git
cd ServerManager
cp .env.example .env
```

In `.env` unbedingt ein langes, zufälliges `APP_PASSWORD` setzen. Danach:

```bash
docker compose up -d --build
docker compose logs -f
```

Der Container lauscht ausschließlich auf `127.0.0.1:8080`. Für den Zugriff aus dem Netzwerk muss Nginx mit TLS vorgeschaltet werden. Eine Vorlage liegt unter `nginx/servermanager.conf`.

## Voraussetzungen

- Linux-Server mit Docker Engine und Docker Compose
- Netzwerkzugriff des Containers auf die RDP-Zielserver
- Nginx und ein gültiges TLS-Zertifikat
- Firewall-Regeln, die den Zugriff auf die Weboberfläche beschränken

## Sicherheit

Die Anwendung ist ein administrativer MVP und sollte nur in einem geschützten Management-Netz betrieben werden.

- Niemals ohne HTTPS veröffentlichen.
- Zugriff zusätzlich über VPN, Zero-Trust-Proxy oder IP-Allowlist begrenzen.
- Ein eigenes starkes Gateway-Passwort setzen.
- `Zertifikat ignorieren` nur für bekannte interne Systeme aktivieren.
- Container nicht mit Host-Netzwerk oder privilegiert starten.
- RDP-Ziele per Firewall auf den Gateway-Server beschränken.

Das RDP-Passwort wird im Request empfangen, direkt über `stdin` an FreeRDP übergeben, danach aus dem Session-Payload entfernt und weder protokolliert noch auf einem Datenträger gespeichert.

## Architektur

```text
Browser -> Nginx/TLS -> aiohttp WebSocket-Proxy -> x11vnc
                                                -> Xvfb/Openbox
                                                -> FreeRDP -> Windows Server
```

## Grenzen des MVP

- Kein Benutzerverzeichnis und keine gespeicherten Serverprofile
- Keine Sitzungsaufzeichnung oder zentrale Audit-Datenbank
- Feste Auflösung während einer laufenden Sitzung
- Zwischenablage hängt von FreeRDP, x11vnc und Browser-Unterstützung ab
- Noch kein Kubernetes- oder Multi-Node-Scheduler
