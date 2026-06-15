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

Danach ist die Oberfläche im lokalen Netzwerk unter folgender Adresse erreichbar:

```text
http://IP-DES-LINUX-SERVERS:8080
```

Der Browser fragt nach `APP_USERNAME` und `APP_PASSWORD` aus der `.env`-Datei. `BIND_ADDRESS=0.0.0.0` erlaubt den Zugriff aus dem LAN. Sobald Nginx mit HTTPS eingerichtet ist, sollte `BIND_ADDRESS` wieder auf `127.0.0.1` gesetzt werden. Eine Nginx-Vorlage liegt unter `nginx/servermanager.conf`.

## Kein Zugriff vom PC

Auf dem Linux-Server prüfen:

```bash
docker compose ps
docker compose logs --tail=100
curl http://127.0.0.1:8080/healthz
ss -lntp | grep 8080
```

Falls UFW aktiv ist, Port 8080 nur für das eigene Management-Netz freigeben:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp
```

Danach die geänderte Bind-Adresse übernehmen:

```bash
docker compose down
docker compose up -d --build
```

Die Server-IP lässt sich beispielsweise mit `hostname -I` anzeigen.

## Voraussetzungen

- Linux-Server mit Docker Engine und Docker Compose
- Netzwerkzugriff des Containers auf die RDP-Zielserver
- Nginx und ein gültiges TLS-Zertifikat
- Firewall-Regeln, die den Zugriff auf die Weboberfläche beschränken

## Sicherheit

Die Anwendung ist ein administrativer MVP und sollte nur in einem geschützten Management-Netz betrieben werden.

- Port 8080 ohne HTTPS nur vorübergehend in einem vertrauenswürdigen LAN verwenden.
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
