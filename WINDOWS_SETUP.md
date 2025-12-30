# Windows Setup Anleitung - PrintOS Dashboard für Render.com

## 📂 Deine aktuelle Situation
Du bist hier: `C:\Users\fesc\Downloads\PrintOS-main\PrintOS-main\`
✅ Das ist richtig!

## 📥 Dateien die du bekommen hast:

1. `render.yaml` → Ins Root-Verzeichnis kopieren
2. `env.production` → Nach `frontend/.env.production` umbenennen und kopieren
3. `secrets.txt` → Ins Root-Verzeichnis kopieren (NICHT committen!)
4. `DEPLOYMENT.md` → Ins Root-Verzeichnis kopieren
5. `gitignore_additions.txt` → Inhalt an `.gitignore` anhängen
6. `health_check_endpoint.py` → Code ans Ende von `backend/server.py` anhängen

## 🪟 Windows PowerShell Befehle:

### 1. Dateien kopieren und umbenennen

```powershell
# Du bist bereits hier:
# PS C:\Users\fesc\Downloads\PrintOS-main\PrintOS-main>

# Prüfen ob die Dateien da sind:
ls

# Dateien die du heruntergeladen hast hierher kopieren:
# (Passe den Pfad an wo du sie gespeichert hast)
Copy-Item "C:\Users\fesc\Downloads\render.yaml" -Destination "."
Copy-Item "C:\Users\fesc\Downloads\secrets.txt" -Destination "."
Copy-Item "C:\Users\fesc\Downloads\DEPLOYMENT.md" -Destination "."

# Frontend .env.production erstellen:
Copy-Item "C:\Users\fesc\Downloads\env.production" -Destination "frontend\.env.production"
```

### 2. .gitignore aktualisieren

```powershell
# Öffne .gitignore mit Editor
notepad .gitignore

# Füge am Ende hinzu (aus gitignore_additions.txt):
# 
# # Environment files
# .env
# .env.local
# .env.production.local
# backend/.env
# frontend/.env.local
# 
# # Render
# .render
# 
# # Secrets
# secrets.txt

# Speichern und schließen
```

### 3. Health Check Endpoint hinzufügen

```powershell
# Öffne backend/server.py
notepad backend\server.py

# Scrolle ans Ende und füge hinzu (aus health_check_endpoint.py):
# 
# @app.get("/health")
# async def health_check():
#     """Health check endpoint for monitoring"""
#     try:
#         await db.command("ping")
#         return {
#             "status": "healthy",
#             "database": "connected",
#             "timestamp": datetime.now(timezone.utc).isoformat()
#         }
#     except Exception as e:
#         raise HTTPException(status_code=503, detail="Database unavailable")

# Speichern und schließen
```

### 4. secrets.txt konfigurieren

```powershell
# Öffne secrets.txt
notepad secrets.txt

# Trage deinen MongoDB Connection String ein:
# MONGO_URL=mongodb+srv://DEIN-USERNAME:DEIN-PASSWORD@cluster.mongodb.net/?retryWrites=true&w=majority

# Die JWT und ENCRYPTION Secrets sind bereits generiert! ✅
# Speichern und schließen
```

### 5. Git vorbereiten

```powershell
# Git Status prüfen
git status

# Alle Änderungen hinzufügen (außer secrets.txt - ist in .gitignore)
git add .

# Commit erstellen
git commit -m "Prepare for Render.com deployment"

# Zu GitHub pushen
git push origin main
```

## ✅ Checkliste - Hast du alles?

Nach dem Setup sollte dein Projektordner so aussehen:

```
PrintOS-main/
├── backend/
│   ├── server.py (mit /health endpoint am Ende)
│   └── requirements.txt
├── frontend/
│   ├── .env.production (NEU!)
│   ├── package.json
│   └── src/
├── render.yaml (NEU!)
├── secrets.txt (NEU! - nicht in Git)
├── DEPLOYMENT.md (NEU!)
├── .gitignore (aktualisiert)
└── README.md
```

## 🔍 Prüfen ob alles funktioniert:

```powershell
# 1. Prüfe ob render.yaml existiert
Test-Path .\render.yaml
# Output: True ✅

# 2. Prüfe ob frontend/.env.production existiert
Test-Path .\frontend\.env.production
# Output: True ✅

# 3. Prüfe ob secrets.txt existiert
Test-Path .\secrets.txt
# Output: True ✅

# 4. Zeige secrets.txt Inhalt (zum Prüfen)
Get-Content .\secrets.txt
```

## 🚀 Nächste Schritte:

1. ✅ MongoDB Atlas einrichten (siehe MongoDB_Atlas_Setup_Anleitung.md)
2. ✅ MongoDB Connection String in secrets.txt eintragen
3. ✅ Code zu GitHub pushen
4. ✅ Auf Render.com deployen (siehe DEPLOYMENT.md oder QUICK_START.md)

## 💡 Alternativ: Visual Studio Code verwenden

Wenn du VS Code hast, ist es einfacher:

```powershell
# Projekt in VS Code öffnen
code .

# Dann:
# 1. Dateien per Drag & Drop ins Projekt ziehen
# 2. Mit integriertem Terminal arbeiten
# 3. Git Integration nutzen
```

## 🆘 Probleme?

### "Access Denied" Fehler?
```powershell
# PowerShell als Administrator ausführen
# Rechtsklick auf PowerShell → "Als Administrator ausführen"
```

### Git nicht gefunden?
```powershell
# Git installieren von: https://git-scm.com/download/win
# Dann Terminal neu starten
```

### Python nicht gefunden?
```powershell
# Python installieren von: https://www.python.org/downloads/
# Bei Installation: "Add Python to PATH" aktivieren!
```

## 📞 Weitere Hilfe

- QUICK_START.md → Schnellanleitung für Deployment
- Render_Deployment_Guide.md → Ausführliche Anleitung
- DEPLOYMENT.md → Checkliste für Render.com

---

**Du schaffst das! 🚀**

Windows ist manchmal etwas umständlicher, aber die Schritte oben sollten funktionieren!
