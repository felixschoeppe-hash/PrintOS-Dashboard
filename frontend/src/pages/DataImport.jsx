import { useState, useCallback, useEffect } from "react";
import axios from "axios";
import { toast } from "sonner";
import { 
  Upload, 
  FileJson, 
  CheckCircle2, 
  XCircle,
  AlertCircle,
  Loader2,
  Database,
  History,
  Clock,
  Download,
  Terminal,
  ChevronDown,
  ChevronUp,
  FileCode,
  Play,
  Info
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";

const API_URL = `${process.env.REACT_APP_BACKEND_URL}/api`;

// URL to the Python script for download
const PYTHON_SCRIPT_URL = "https://customer-assets.emergentagent.com/job_780f423f-33d7-4575-8f0c-1dd9c8d51e1e/artifacts/38ttw7v7_complete_job_analytics_30sec_OFFICIAL_interactive.py";

export default function DataImport() {
  const [file, setFile] = useState(null);
  const [importing, setImporting] = useState(false);
  const [progress, setProgress] = useState(0);
  const [result, setResult] = useState(null);
  const [preview, setPreview] = useState(null);
  const [dragActive, setDragActive] = useState(false);
  const [importHistory, setImportHistory] = useState([]);
  const [syncHistory, setSyncHistory] = useState([]);
  const [guideOpen, setGuideOpen] = useState(true);

  useEffect(() => {
    fetchHistory();
  }, []);

  const fetchHistory = async () => {
    try {
      const [importRes, syncRes] = await Promise.all([
        axios.get(`${API_URL}/import/log?limit=10`),
        axios.get(`${API_URL}/sync/log?limit=10`)
      ]);
      setImportHistory(importRes.data.logs || []);
      setSyncHistory(syncRes.data.logs || []);
    } catch (error) {
      console.log("Error fetching history:", error);
    }
  };

  const handleDrag = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  }, []);

  const processFile = async (selectedFile) => {
    if (!selectedFile) return;
    
    if (!selectedFile.name.endsWith('.json')) {
      toast.error("Bitte nur JSON-Dateien hochladen");
      return;
    }

    setFile(selectedFile);
    setResult(null);

    try {
      const text = await selectedFile.text();
      const data = JSON.parse(text);
      
      const jobs = Array.isArray(data) ? data : [data];
      
      setPreview({
        fileName: selectedFile.name,
        fileSize: (selectedFile.size / 1024).toFixed(2) + " KB",
        jobCount: jobs.length,
        sampleJob: jobs[0]
      });
    } catch (error) {
      toast.error("Fehler beim Lesen der JSON-Datei");
      setFile(null);
    }
  };

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  }, []);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0]);
    }
  };

  const handleImport = async () => {
    if (!file) return;

    setImporting(true);
    setProgress(0);
    setResult(null);

    try {
      const text = await file.text();
      const data = JSON.parse(text);
      const jobs = Array.isArray(data) ? data : [data];

      const progressInterval = setInterval(() => {
        setProgress(prev => Math.min(prev + 10, 90));
      }, 200);

      const response = await axios.post(`${API_URL}/jobs/import`, { jobs });

      clearInterval(progressInterval);
      setProgress(100);

      setResult({
        success: true,
        imported: response.data.imported,
        updated: response.data.updated,
        skipped: response.data.skipped,
        errors: response.data.errors
      });

      toast.success(`${response.data.imported} Jobs importiert`);
      
      // Refresh history
      fetchHistory();
    } catch (error) {
      console.error("Import error:", error);
      setResult({
        success: false,
        error: error.response?.data?.detail || error.message
      });
      toast.error("Import fehlgeschlagen");
    } finally {
      setImporting(false);
    }
  };

  const resetImport = () => {
    setFile(null);
    setPreview(null);
    setResult(null);
    setProgress(0);
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return "-";
    const date = new Date(dateStr);
    return date.toLocaleString('de-DE', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const handleDownloadScript = () => {
    // Create a temporary link to download the file
    const link = document.createElement('a');
    link.href = PYTHON_SCRIPT_URL;
    link.download = 'hp_printbeat_job_exporter.py';
    link.target = '_blank';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast.success("Download gestartet");
  };

  return (
    <div className="space-y-6 animate-slide-up" data-testid="data-import-page">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <Database className="w-8 h-8 text-cyan-500" />
          Daten Import
        </h1>
        <p className="text-slate-400 mt-1">
          Job-Daten aus der HP PrintBeat API exportieren und importieren
        </p>
      </div>

      {/* Python Script Download & Guide */}
      <Card className="industrial-card border-amber-500/30" data-testid="script-guide">
        <Collapsible open={guideOpen} onOpenChange={setGuideOpen}>
          <CardHeader className="cursor-pointer" onClick={() => setGuideOpen(!guideOpen)}>
            <CollapsibleTrigger asChild>
              <div className="flex items-center justify-between">
                <CardTitle className="text-lg font-semibold text-white flex items-center gap-2">
                  <FileCode className="w-5 h-5 text-amber-500" />
                  HP PrintBeat Job Exporter
                  <Badge variant="outline" className="ml-2 bg-amber-500/10 text-amber-400 border-amber-500/30">
                    Python Tool
                  </Badge>
                </CardTitle>
                {guideOpen ? (
                  <ChevronUp className="w-5 h-5 text-slate-400" />
                ) : (
                  <ChevronDown className="w-5 h-5 text-slate-400" />
                )}
              </div>
            </CollapsibleTrigger>
            <CardDescription className="text-slate-400 mt-1">
              Dieses Python-Skript lädt Job-Daten direkt von der HP PrintBeat API und speichert sie als JSON
            </CardDescription>
          </CardHeader>
          
          <CollapsibleContent>
            <CardContent className="space-y-6">
              {/* Download Button */}
              <div className="flex items-center gap-4">
                <Button
                  onClick={handleDownloadScript}
                  className="bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold"
                  data-testid="download-script-btn"
                >
                  <Download className="w-4 h-4 mr-2" />
                  Python-Skript herunterladen
                </Button>
                <span className="text-slate-500 text-sm">
                  hp_printbeat_job_exporter.py (~15 KB)
                </span>
              </div>

              {/* Quick Guide */}
              <div className="space-y-4">
                <h4 className="text-white font-medium flex items-center gap-2">
                  <Info className="w-4 h-4 text-cyan-500" />
                  Kurzanleitung
                </h4>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Step 1 */}
                  <div className="bg-slate-800/50 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="w-6 h-6 rounded-full bg-cyan-500 text-slate-950 text-sm font-bold flex items-center justify-center">1</span>
                      <span className="text-white font-medium">Voraussetzungen</span>
                    </div>
                    <ul className="text-slate-400 text-sm space-y-1 ml-8">
                      <li>• Python 3.x installiert</li>
                      <li>• <code className="bg-slate-700 px-1 rounded">pip install requests</code></li>
                      <li>• HP PrintBeat API Credentials (aus Einstellungen)</li>
                    </ul>
                  </div>

                  {/* Step 2 */}
                  <div className="bg-slate-800/50 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="w-6 h-6 rounded-full bg-cyan-500 text-slate-950 text-sm font-bold flex items-center justify-center">2</span>
                      <span className="text-white font-medium">Skript ausführen</span>
                    </div>
                    <div className="bg-slate-900 rounded p-2 ml-8">
                      <code className="text-cyan-400 text-sm font-mono">
                        python hp_printbeat_job_exporter.py
                      </code>
                    </div>
                  </div>

                  {/* Step 3 */}
                  <div className="bg-slate-800/50 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="w-6 h-6 rounded-full bg-cyan-500 text-slate-950 text-sm font-bold flex items-center justify-center">3</span>
                      <span className="text-white font-medium">Credentials eingeben</span>
                    </div>
                    <ul className="text-slate-400 text-sm space-y-1 ml-8">
                      <li>• <strong className="text-slate-300">API Key:</strong> Jobs API Key</li>
                      <li>• <strong className="text-slate-300">API Secret:</strong> Jobs API Secret</li>
                      <li>• <strong className="text-slate-300">Device ID:</strong> z.B. 47200413</li>
                    </ul>
                  </div>

                  {/* Step 4 */}
                  <div className="bg-slate-800/50 rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="w-6 h-6 rounded-full bg-cyan-500 text-slate-950 text-sm font-bold flex items-center justify-center">4</span>
                      <span className="text-white font-medium">JSON importieren</span>
                    </div>
                    <ul className="text-slate-400 text-sm space-y-1 ml-8">
                      <li>• Exportierte <code className="bg-slate-700 px-1 rounded">all_jobs_*.json</code></li>
                      <li>• Per Drag & Drop unten hochladen</li>
                      <li>• Jobs werden automatisch kategorisiert</li>
                    </ul>
                  </div>
                </div>

                {/* Important Notes */}
                <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
                  <h5 className="text-amber-400 font-medium mb-2 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4" />
                    Wichtige Hinweise
                  </h5>
                  <ul className="text-slate-400 text-sm space-y-1">
                    <li>• <strong className="text-slate-300">Rate Limit:</strong> Das Skript respektiert HP's Limit von 2 Anfragen/Minute (30 Sek. Pause)</li>
                    <li>• <strong className="text-slate-300">Laufzeit:</strong> Export von 5000 Jobs dauert ca. 25-30 Minuten</li>
                    <li>• <strong className="text-slate-300">Ausgabe:</strong> Zwei JSON-Dateien werden erstellt: <code className="bg-slate-700 px-1 rounded">all_jobs_*.json</code> und <code className="bg-slate-700 px-1 rounded">summary_*.json</code></li>
                    <li>• <strong className="text-slate-300">Umgebungsvariablen:</strong> Optional können <code className="bg-slate-700 px-1 rounded">HP_PRINTBEAT_KEY</code>, <code className="bg-slate-700 px-1 rounded">HP_PRINTBEAT_SECRET</code>, <code className="bg-slate-700 px-1 rounded">HP_DEVICE_ID</code> gesetzt werden</li>
                  </ul>
                </div>
              </div>
            </CardContent>
          </CollapsibleContent>
        </Collapsible>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Upload Area */}
        <Card className="industrial-card">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-white">
              JSON-Datei hochladen
            </CardTitle>
            <CardDescription className="text-slate-400">
              Unterstützt JSON-Dateien mit einzelnen Jobs oder Job-Arrays
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div
              className={`
                border-2 border-dashed rounded-lg p-8 text-center transition-colors
                ${dragActive 
                  ? "border-cyan-500 bg-cyan-500/10" 
                  : "border-slate-700 hover:border-slate-600"
                }
                ${file ? "border-teal-500 bg-teal-500/10" : ""}
              `}
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              data-testid="drop-zone"
            >
              {file ? (
                <div className="space-y-4">
                  <FileJson className="w-12 h-12 mx-auto text-teal-500" />
                  <div>
                    <p className="text-white font-medium">{file.name}</p>
                    <p className="text-slate-400 text-sm">{preview?.fileSize}</p>
                  </div>
                  <Button 
                    variant="outline" 
                    onClick={resetImport}
                    className="border-slate-700 text-slate-300"
                  >
                    Andere Datei wählen
                  </Button>
                </div>
              ) : (
                <div className="space-y-4">
                  <Upload className="w-12 h-12 mx-auto text-slate-500" />
                  <div>
                    <p className="text-white">
                      Datei hierher ziehen oder{" "}
                      <label className="text-cyan-400 cursor-pointer hover:underline">
                        durchsuchen
                        <input
                          type="file"
                          accept=".json"
                          onChange={handleFileChange}
                          className="hidden"
                          data-testid="file-input"
                        />
                      </label>
                    </p>
                    <p className="text-slate-500 text-sm mt-1">
                      Nur .json Dateien (z.B. all_jobs_*.json)
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* Preview */}
            {preview && (
              <div className="mt-6 space-y-4">
                <h3 className="text-white font-medium">Vorschau</h3>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div className="bg-slate-800 p-3 rounded">
                    <p className="text-slate-400">Anzahl Jobs</p>
                    <p className="text-white font-mono text-lg">{preview.jobCount}</p>
                  </div>
                  <div className="bg-slate-800 p-3 rounded">
                    <p className="text-slate-400">Beispiel Presse</p>
                    <p className="text-white font-mono text-lg">
                      {preview.sampleJob?.pressSerialNumber || "-"}
                    </p>
                  </div>
                </div>
                
                {preview.sampleJob && (
                  <div className="bg-slate-800 p-3 rounded">
                    <p className="text-slate-400 text-sm mb-2">Erster Job:</p>
                    <p className="text-white font-mono text-sm truncate">
                      {preview.sampleJob.jobName}
                    </p>
                    <p className="text-slate-400 text-xs mt-1">
                      {preview.sampleJob.jobProgress} • {preview.sampleJob.impressions} Impressionen
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Import Button */}
            {file && !result && (
              <Button
                onClick={handleImport}
                disabled={importing}
                className="w-full mt-6 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold"
                data-testid="import-button"
              >
                {importing ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Importiere...
                  </>
                ) : (
                  <>
                    <Upload className="w-4 h-4 mr-2" />
                    {preview?.jobCount} Jobs importieren
                  </>
                )}
              </Button>
            )}

            {/* Progress */}
            {importing && (
              <div className="mt-4">
                <Progress value={progress} className="h-2" />
                <p className="text-slate-400 text-sm mt-2 text-center">{progress}%</p>
              </div>
            )}

            {/* Result */}
            {result && (
              <div className="mt-6 space-y-4">
                {result.success ? (
                  <>
                    <div className="flex items-center gap-3 text-teal-400">
                      <CheckCircle2 className="w-8 h-8" />
                      <span className="text-xl font-semibold">Import erfolgreich</span>
                    </div>
                    <div className="grid grid-cols-3 gap-4 mt-4">
                      <div className="bg-teal-500/10 p-4 rounded text-center">
                        <p className="text-3xl font-bold text-teal-400 font-mono">
                          {result.imported}
                        </p>
                        <p className="text-slate-400 text-sm">Importiert</p>
                      </div>
                      <div className="bg-amber-500/10 p-4 rounded text-center">
                        <p className="text-3xl font-bold text-amber-400 font-mono">
                          {result.updated}
                        </p>
                        <p className="text-slate-400 text-sm">Aktualisiert</p>
                      </div>
                      <div className="bg-slate-500/10 p-4 rounded text-center">
                        <p className="text-3xl font-bold text-slate-400 font-mono">
                          {result.skipped}
                        </p>
                        <p className="text-slate-400 text-sm">Übersprungen</p>
                      </div>
                    </div>
                    {result.errors > 0 && (
                      <div className="flex items-center gap-2 text-rose-400 mt-4">
                        <AlertCircle className="w-4 h-4" />
                        <span>{result.errors} Fehler</span>
                      </div>
                    )}
                    <Button
                      onClick={resetImport}
                      className="w-full mt-4 bg-slate-800 hover:bg-slate-700 text-white"
                    >
                      Weitere Datei importieren
                    </Button>
                  </>
                ) : (
                  <>
                    <div className="flex items-center gap-3 text-rose-400">
                      <XCircle className="w-8 h-8" />
                      <span className="text-xl font-semibold">Import fehlgeschlagen</span>
                    </div>
                    <p className="text-slate-400 mt-4">{result.error}</p>
                    <Button
                      onClick={resetImport}
                      className="w-full mt-4 bg-slate-800 hover:bg-slate-700 text-white"
                    >
                      Erneut versuchen
                    </Button>
                  </>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* History & Info */}
        <div className="space-y-6">
          {/* Import History */}
          <Card className="industrial-card">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-white flex items-center gap-2">
                <History className="w-5 h-5 text-cyan-500" />
                Import-Historie
              </CardTitle>
            </CardHeader>
            <CardContent>
              {importHistory.length > 0 ? (
                <div className="space-y-3 max-h-48 overflow-auto">
                  {importHistory.map((log, idx) => (
                    <div key={idx} className="flex items-center justify-between bg-slate-800 p-3 rounded">
                      <div>
                        <p className="text-white text-sm font-mono">
                          {log.imported} importiert, {log.updated} aktualisiert
                        </p>
                        <p className="text-slate-400 text-xs flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {formatDate(log.timestamp)}
                        </p>
                      </div>
                      <Badge variant="outline" className="bg-teal-500/10 text-teal-400 border-teal-500/30">
                        {log.total_jobs} Jobs
                      </Badge>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500 text-sm">Noch keine Importe durchgeführt</p>
              )}
            </CardContent>
          </Card>

          {/* Sync History */}
          <Card className="industrial-card">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-white flex items-center gap-2">
                <History className="w-5 h-5 text-purple-500" />
                Sync-Log
              </CardTitle>
            </CardHeader>
            <CardContent>
              {syncHistory.length > 0 ? (
                <div className="space-y-3 max-h-48 overflow-auto">
                  {syncHistory.map((log, idx) => (
                    <div key={idx} className="flex items-center justify-between bg-slate-800 p-3 rounded">
                      <div>
                        <p className="text-white text-sm">
                          <span className="font-mono">{log.device_name || log.device_id}</span>
                          {log.error && <span className="text-rose-400 ml-2">Fehler</span>}
                        </p>
                        <p className="text-slate-400 text-xs flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {formatDate(log.timestamp)}
                        </p>
                      </div>
                      <Badge 
                        variant="outline" 
                        className={log.error 
                          ? "bg-rose-500/10 text-rose-400 border-rose-500/30"
                          : "bg-purple-500/10 text-purple-400 border-purple-500/30"
                        }
                      >
                        {log.jobs_synced} Jobs
                      </Badge>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-500 text-sm">Noch keine Syncs durchgeführt</p>
              )}
            </CardContent>
          </Card>

          {/* JSON Format Info */}
          <Card className="industrial-card">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-white">
                Erwartetes JSON Format
              </CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="bg-slate-800 p-4 rounded text-xs text-slate-300 overflow-auto max-h-48">
{`{
  "pressSerialNumber": "47200413",
  "jobName": "example.pdf",
  "marker": 624433260,
  "impressions": 100,
  "oneShotImpressions": 100,
  "jobProgress": "PRINTED",
  "jobSubmitTime": "2025-09-22...",
  "inks": [
    {"color": "Yellow", ...}
  ]
}`}
              </pre>
              <div className="text-xs text-slate-500 mt-3 space-y-1">
                <p>• Einzelner Job oder Array von Jobs</p>
                <p>• <code className="bg-slate-700 px-1 rounded">marker</code> wird als eindeutige ID verwendet</p>
                <p>• Click-Kategorien werden automatisch berechnet</p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
