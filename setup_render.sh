#!/bin/bash
# PrintOS Dashboard - Render.com Deployment Setup Script
# Dieses Script bereitet dein Projekt für Render.com vor

set -e  # Exit on error

echo "🚀 PrintOS Dashboard - Render.com Setup"
echo "========================================"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -d "backend" ] || [ ! -d "frontend" ]; then
    echo -e "${RED}❌ Error: backend/ oder frontend/ Verzeichnis nicht gefunden${NC}"
    echo "Bitte führe dieses Script im Root-Verzeichnis des PrintOS Projekts aus"
    exit 1
fi

echo -e "${GREEN}✓${NC} Verzeichnisstruktur OK"
echo ""

# Generate secrets
echo "🔐 Generiere sichere Secrets..."
JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
ENCRYPTION_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
echo -e "${GREEN}✓${NC} Secrets generiert"
echo ""

# Create render.yaml
echo "📝 Erstelle render.yaml..."
cat > render.yaml << 'EOF'
services:
  # Backend Service (FastAPI)
  - type: web
    name: printos-backend
    env: python
    region: frankfurt
    buildCommand: pip install -r backend/requirements.txt
    startCommand: cd backend && uvicorn server:app --host 0.0.0.0 --port $PORT
    healthCheckPath: /health
    envVars:
      - key: PYTHON_VERSION
        value: 3.11.0
      - key: MONGO_URL
        sync: false  # Manuell über Render UI setzen
      - key: DB_NAME
        value: printos_dashboard
      - key: JWT_SECRET_KEY
        generateValue: true
      - key: ENCRYPTION_SECRET
        generateValue: true
      - key: HP_PRINTOS_BASE_URL
        value: https://printos.api.hp.com/printbeat

  # Frontend Service (React)
  - type: web
    name: printos-frontend
    env: static
    region: frankfurt
    buildCommand: cd frontend && yarn install && yarn build
    staticPublishPath: ./frontend/build
    routes:
      - type: rewrite
        source: /*
        destination: /index.html
    envVars:
      - key: NODE_VERSION
        value: 18
      - key: REACT_APP_API_URL
        value: https://printos-backend.onrender.com
EOF
echo -e "${GREEN}✓${NC} render.yaml erstellt"
echo ""

# Create frontend .env.production
echo "📝 Erstelle frontend/.env.production..."
cat > frontend/.env.production << 'EOF'
# Production Environment Variables
REACT_APP_API_URL=https://printos-backend.onrender.com
EOF
echo -e "${GREEN}✓${NC} frontend/.env.production erstellt"
echo ""

# Create backend health check endpoint (if not exists)
if ! grep -q "@app.get(\"/health\")" backend/server.py; then
    echo "📝 Füge Health Check Endpoint hinzu..."
    cat >> backend/server.py << 'EOF'

# Health check endpoint for Render.com
@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    try:
        # Test MongoDB connection
        await db.command("ping")
        return {
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail="Database unavailable")
EOF
    echo -e "${GREEN}✓${NC} Health Check Endpoint hinzugefügt"
else
    echo -e "${YELLOW}ℹ${NC} Health Check Endpoint existiert bereits"
fi
echo ""

# Update .gitignore
echo "📝 Aktualisiere .gitignore..."
cat >> .gitignore << 'EOF'

# Environment files
.env
.env.local
.env.production.local
backend/.env
frontend/.env.local

# Render
.render

# Secrets
secrets.txt
EOF
echo -e "${GREEN}✓${NC} .gitignore aktualisiert"
echo ""

# Create secrets file for reference
echo "📝 Erstelle secrets.txt (NICHT committen!)..."
cat > secrets.txt << EOF
# PrintOS Dashboard Secrets
# NICHT in Git committen!
# Diese Werte in Render.com Environment Variables eintragen

JWT_SECRET_KEY=$JWT_SECRET
ENCRYPTION_SECRET=$ENCRYPTION_SECRET

# MongoDB Atlas Connection String (anpassen!)
MONGO_URL=mongodb+srv://username:password@cluster.mongodb.net/?retryWrites=true&w=majority
DB_NAME=printos_dashboard

# Optional: SMTP Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=deine@email.com
SMTP_PASSWORD=app-specific-password
SMTP_FROM_EMAIL=deine@email.com
EOF
echo -e "${GREEN}✓${NC} secrets.txt erstellt"
echo ""

# Create deployment checklist
echo "📝 Erstelle DEPLOYMENT.md..."
cat > DEPLOYMENT.md << 'EOF'
# Deployment Checklist für Render.com

## Vor dem Deployment

- [ ] MongoDB Atlas eingerichtet und Connection String erhalten
- [ ] GitHub Repository erstellt und Code gepusht
- [ ] Render.com Account erstellt und GitHub verbunden

## Backend Deployment

1. Render Dashboard → "New +" → "Web Service"
2. Repository auswählen
3. Konfiguration:
   - Name: `printos-backend`
   - Region: `Frankfurt`
   - Root Directory: `backend`
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `uvicorn server:app --host 0.0.0.0 --port $PORT`

4. Environment Variables setzen (siehe secrets.txt):
   - MONGO_URL
   - DB_NAME
   - JWT_SECRET_KEY
   - ENCRYPTION_SECRET
   - PYTHON_VERSION=3.11.0

5. "Create Web Service" klicken

## Frontend Deployment

1. Render Dashboard → "New +" → "Static Site"
2. Dasselbe Repository auswählen
3. Konfiguration:
   - Name: `printos-frontend`
   - Region: `Frankfurt`
   - Root Directory: `frontend`
   - Build Command: `yarn install && yarn build`
   - Publish Directory: `build`

4. Environment Variables:
   - NODE_VERSION=18
   - REACT_APP_API_URL=https://printos-backend.onrender.com

5. "Create Static Site" klicken

## Nach dem Deployment

- [ ] Backend Health Check: https://printos-backend.onrender.com/health
- [ ] Backend Swagger Docs: https://printos-backend.onrender.com/docs
- [ ] Frontend funktioniert: https://printos-frontend.onrender.com
- [ ] Login/Registration testen
- [ ] MongoDB Verbindung prüfen

## CORS Update notwendig?

Falls CORS Fehler auftreten, in `backend/server.py` anpassen:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://printos-frontend.onrender.com",
        "http://localhost:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## Monitoring (Optional)

- [ ] UptimeRobot einrichten für Backend Ping
- [ ] Custom Domain konfigurieren (falls gewünscht)
- [ ] SSL Zertifikat prüfen (automatisch von Render)
EOF
echo -e "${GREEN}✓${NC} DEPLOYMENT.md erstellt"
echo ""

echo "=========================================="
echo -e "${GREEN}✅ Setup abgeschlossen!${NC}"
echo ""
echo "📋 Nächste Schritte:"
echo ""
echo "1. Secrets sicher speichern:"
echo "   ${YELLOW}cat secrets.txt${NC}"
echo "   (Diese Werte brauchst du für Render Environment Variables)"
echo ""
echo "2. MongoDB Atlas Connection String in secrets.txt eintragen"
echo ""
echo "3. Code zu GitHub pushen:"
echo "   ${YELLOW}git add .${NC}"
echo "   ${YELLOW}git commit -m 'Prepare for Render deployment'${NC}"
echo "   ${YELLOW}git push origin main${NC}"
echo ""
echo "4. Render.com Deployment (siehe DEPLOYMENT.md):"
echo "   - Backend deployen"
echo "   - Frontend deployen"
echo ""
echo "5. Optional: CORS in backend/server.py anpassen"
echo ""
echo "📖 Vollständige Anleitung: Render_Deployment_Guide.md"
echo ""
echo -e "${YELLOW}⚠️  WICHTIG: secrets.txt NICHT committen!${NC}"
echo "   (Ist bereits in .gitignore)"
echo ""
