# ServerManager

Eine lokale Weboberfläche zum Erzeugen direkter RDP-Verbindungen für autorisierte Windows-Server. Unterstützt IP-Adresse oder Hostname, Port, Benutzername, Domäne, Auflösung, Zwischenablage und eine administrative Sitzung.

## Nginx

```nginx
server {
    listen 80;
    server_name rdp.example.internal;

    root /var/www/servermanager;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }
}
```

Die Dateien können beispielsweise nach `/var/www/servermanager` ausgecheckt werden.

## Wichtiger technischer Hinweis

Diese statische Version erzeugt eine `.rdp`-Datei, die anschließend vom Windows-RDP-Client geöffnet wird. Ein Browser und Nginx allein können keine native RDP-Sitzung darstellen oder `mstsc.exe` auf einem entfernten Client starten.

Für eine vollständige RDP-Sitzung direkt im Browser wird zusätzlich ein Gateway wie [Apache Guacamole](https://guacamole.apache.org/) benötigt. Zugangsdaten sollten dann ausschließlich serverseitig, verschlüsselt und mit einer vorgeschalteten Authentifizierung verarbeitet werden.

## Sicherheit

- Nur für Systeme verwenden, für die eine ausdrückliche Administrationsberechtigung besteht.
- Passwörter werden von dieser Anwendung nicht verarbeitet oder gespeichert.
- Die Admin-Option fordert eine administrative RDP-Sitzung an.
