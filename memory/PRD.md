# HP PrintOS Indigo Performance & Billing Dashboard - PRD

## Original Problem Statement
Professionelle Web-Applikation zur Überwachung und Abrechnungsprüfung (Clicks) für drei HP Indigo Druckmaschinen. Die App dient als "Single Source of Truth" für Produktionsdaten der HP PrintOS API und Rechnungsstellung basierend auf EPM/OneShot-Logik.

## Architecture
- **Frontend**: React 19 + Tailwind CSS + Shadcn/UI + Recharts
- **Backend**: FastAPI (Python)
- **Database**: MongoDB (print_jobs, printvolume_cache, import_log, sync_log)
- **External API**: HP PrintOS API mit HMAC-SHA256 Authentifizierung

## User Personas
1. **Druckerei-Manager**: Überwacht Gesamtproduktion über alle Maschinen
2. **Produktionsleiter**: Analysiert einzelne Maschinen-Performance
3. **Abrechnungs-Team**: Verifiziert Clicks für Rechnungsstellung

## Core Requirements (Static)
- [x] Real-time Status für 3 HP Indigo Pressen (7K, 7900, 9129)
- [x] Click-Kategorisierung (1 Color, 2 Colors, EPM, Multicolor)
- [x] OneShot/MultiShot Unterscheidung
- [x] Job-Sync von HP PrintOS API (Rate Limit: 2 req/min)
- [x] CSV Export für Abrechnungsdaten
- [x] PrintVolume API Caching (24h TTL)
- [x] Jahr-zu-Jahr Vergleich (YoY)

## Implemented Features (December 2024)

### Core Features
- **Dashboard**: Status-Karten (Jobs, Impressionen, Erfolgsrate), Produktionsverlauf-Chart
- **Clicks Report**: Pie-Chart für Kategorien, OneShot/MultiShot Toggle, Trend-Chart, CSV Export
- **Jobs Liste**: Paginierte Tabelle mit Suche, Status-Filter, Kategorie-Filter
- **Daten Import**: JSON-Import mit Drag-and-Drop, Import-Historie
- **Device Selector**: Globaler Filter für alle Seiten
- **HP PrintOS Integration**: HMAC-SHA256 Auth, Jobs API Sync, Background Sync

### New Features (30.12.2025)
- **PrintVolume API Cache**: 
  - MongoDB Collection `printvolume_cache` mit 24h TTL
  - Reduziert API-Aufrufe dramatisch (1655ms → 49ms bei Cache-Hit)
  - Automatische Cache-Invalidierung nach TTL
  - Manuelle Cache-Verwaltung über /api/cache/status und /api/cache/clear

- **Jahr-zu-Jahr Vergleich (YoY)**:
  - Neuer Toggle im Clicks Report Header
  - Vergleicht aktuellen Zeitraum mit Vorjahreszeitraum
  - Zeigt absolute und prozentuale Veränderung
  - Monatliches Liniendiagramm für visuellen Vergleich

## API Endpoints

### Existing
- GET /api/devices - Liste aller Geräte
- GET /api/stats/overview - Statistik-Übersicht
- GET /api/jobs - Paginierte Job-Liste mit Filtern
- POST /api/jobs/sync - Job-Synchronisation
- GET /api/clicks/report - Click-Kategorien Breakdown
- GET /api/clicks/trend - Trend-Daten
- GET /api/clicks/export - CSV Download
- POST /api/sync/start, /api/sync/stop, GET /api/sync/status

### New (30.12.2025)
- GET /api/clicks/yoy - Jahr-zu-Jahr Vergleich Daten
- GET /api/clicks/yoy/trend - Monatliche YoY Trend-Daten
- GET /api/cache/status - Cache-Statistiken
- DELETE /api/cache/clear - Cache leeren

## Database Schema

### print_jobs
- marker, press_id, job_name, status, submit_time
- total_impressions, one_shot_impressions
- is_oneshot, is_epm, click_category
- inks, substrates

### printvolume_cache (NEW)
- cache_key: String (device_from_to_resolution)
- device_id, from_date, to_date, resolution
- data: Object (API response)
- cached_at: DateTime

### import_log, sync_log
- timestamp, status, details

## Prioritized Backlog

### P0 (Critical) - DONE
- [x] Dashboard mit Live-Daten
- [x] Clicks Report mit Kategorien
- [x] Jobs Liste mit Filtern
- [x] PrintVolume API Cache
- [x] Jahr-zu-Jahr Vergleich

### P1 (High)
- [ ] Filter für "Problem-Jobs" (>3 Fehler, >5 Druckversuche)
- [ ] Auto-Refresh für Echtzeit-Daten (alle 60 Sekunden)
- [ ] Multi-Device Sync parallel

### P2 (Medium)  
- [ ] Email/UI-Benachrichtigungen bei kritischen Fehlern
- [ ] Wartungs-Modul
- [ ] Export als Excel zusätzlich zu CSV

### P3 (Low)
- [ ] Dashboard Widgets konfigurierbar
- [ ] User Authentication

## Next Tasks
1. Filter für "Problem-Jobs" implementieren
2. Auto-Refresh für Dashboard-Daten
3. Wartungsstatus-Benachrichtigungen

## Technical Notes
- Cache TTL: 24 Stunden (CACHE_TTL_HOURS = 24)
- API Rate Limit: 2 requests/minute für Jobs API
- Hybrid Data Strategy: Jobs API für < 14 Tage, PrintVolume API für > 14 Tage
