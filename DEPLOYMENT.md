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
