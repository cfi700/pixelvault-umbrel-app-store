# PixelVault – Umbrel Community App Store

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Verschlüsselte Foto-Webanwendung für [Umbrel](https://umbrel.com).

## Repository-Struktur

```
umbrel-app-store.yml                    ← App-Store-Manifest (ID + Name)
pixelvault-store-pixelvault/
├── umbrel-app.yml                      ← App-Listing für die Umbrel-UI
├── docker-compose.yml                  ← Wird von Umbrel zum Starten genutzt
├── Dockerfile                          ← Image-Definition
└── app/
    ├── backend/
    │   ├── server.js                   ← Express-API
    │   └── package.json
    └── frontend/
        └── index.html                  ← Single-File UI
```

## App installieren

### 1. Image bauen (auf dem Umbrel-Server)

```bash
cd ~/pixelvault-store-pixelvault
docker build -t pixelvault-store-pixelvault:0.5-beta .
```

### 2. Community App Store in Umbrel hinzufügen

1. Umbrel öffnen → **App Store** → **Community App Stores**
2. GitHub-URL dieses Repositories eintragen
3. PixelVault installieren

### 3. Erster Login

| Feld | Wert |
|------|------|
| Benutzername | `admin` |
| Passwort | `admin` |

> ⚠️ **Sofort das Admin-Passwort ändern!** (Einstellungen → Konto)

---

## Umbrel-Umgebungsvariablen

Umbrel stellt automatisch bereit:

| Variable | Beschreibung |
|----------|-------------|
| `APP_DATA_DIR` | Persistentes Datenverzeichnis (wird als `/data` gemountet) |
| `APP_SEED` | 256-bit Hex-String, wird als `ENCRYPTION_KEY` genutzt |
| `APP_PASSWORD` | Zufälliges Passwort, wird als `SESSION_SECRET` genutzt |

Der `APP_SEED` ist deterministisch vom Umbrel-Master-Seed abgeleitet –  
d.h. nach einer Neuinstallation mit demselben Seed sind alle Fotos weiterhin entschlüsselbar.

---

## Sicherheitskonzept

- **AES-256-CBC** – Originale und Thumbnails werden einzeln mit zufälligem IV verschlüsselt
- Entschlüsselung **nur im RAM**, niemals auf Disk
- **bcrypt** (12 Runden) für Passwort-Hashing
- **Download-Schutz**: Nur der Eigentümer und Admins können Originale herunterladen
- **Sichtbarkeits-Rechte**: Admin vergibt pro Benutzer, wessen Fotos er sehen darf

---

## Dateistruktur im Volume

```
/data/
├── db.json        ← Benutzer & Foto-Metadaten (kein Klartext der Bilder)
├── sessions/      ← Server-Sessions
├── photos/        ← Verschlüsselte Originale (*.enc)
└── thumbs/        ← Verschlüsselte Thumbnails (*.enc)
```

---

## Lizenz

Dieses Projekt steht unter der [MIT-Lizenz](LICENSE).
