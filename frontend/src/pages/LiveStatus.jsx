import { useState, useEffect } from "react";
import axios from "axios";
import { toast } from "sonner";
import { 
  Radio, 
  Printer, 
  Layers,
  FileText,
  Clock,
  Zap,
  RefreshCw
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

const API_URL = `${process.env.REACT_APP_BACKEND_URL}/api`;

const DEVICE_NAMES = {
  "47200413": "7K",
  "47100144": "7900",
  "47100122": "9129",
  "all": "Alle Pressen"
};

const DEVICE_MODELS = {
  "47200413": "HP Indigo 7K",
  "47100144": "HP Indigo 7900",
  "47100122": "HP Indigo 9129"
};

export default function LiveStatus({ selectedDevice }) {
  const [realtimeData, setRealtimeData] = useState({});
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState(null);

  useEffect(() => {
    fetchRealtimeData();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(() => {
      fetchRealtimeData();
    }, 30000);
    
    return () => clearInterval(interval);
  }, [selectedDevice]);

  const fetchRealtimeData = async () => {
    setLoading(true);
    try {
      const devices = selectedDevice === "all" 
        ? ["47200413", "47100144", "47100122"]
        : [selectedDevice];
      
      const results = {};
      for (const devId of devices) {
        try {
          const res = await axios.get(`${API_URL}/devices/${devId}/status`);
          const data = res.data?.data?.data?.[0];
          const todayFromJobs = res.data?.today_from_jobs || {};
          
          if (data) {
            results[devId] = {
              pressState: data.pressState || "UNKNOWN",
              printedJobs: data.printedJobs || todayFromJobs.jobs || 0,
              // Use impressions/sheets from Jobs API (more accurate)
              sheets: todayFromJobs.sheets || data.sheets || 0,
              impressions: todayFromJobs.impressions || data.impressions || 0,
              impressionsPerHour: data.impressionsPerHour || 0,
              lastTimeStateChanged: data.lastTimeStateChanged,
              currentJobName: data.currentJobName || "-",
              operatorMessage: data.operatorMessage || "-",
              printMode: data.printMode || "-",
              substrateWidth: data.substrateWidth || 0,
              speed: data.speed || 0
            };
          } else {
            // Use today_from_jobs even if realtime data is missing
            results[devId] = {
              pressState: "DISCONNECTED",
              printedJobs: todayFromJobs.jobs || 0,
              sheets: todayFromJobs.sheets || 0,
              impressions: todayFromJobs.impressions || 0,
              impressionsPerHour: 0,
              error: true
            };
          }
        } catch (e) {
          console.log(`Failed to get realtime for ${devId}`);
          results[devId] = {
            pressState: "DISCONNECTED",
            printedJobs: 0,
            sheets: 0,
            impressions: 0,
            impressionsPerHour: 0,
            error: true
          };
        }
      }
      setRealtimeData(results);
      setLastUpdate(new Date());
    } catch (error) {
      toast.error("Fehler beim Laden der Live-Daten");
    } finally {
      setLoading(false);
    }
  };

  const formatNumber = (num) => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + "M";
    if (num >= 1000) return (num / 1000).toFixed(1) + "K";
    return num?.toLocaleString("de-DE") || "0";
  };

  const getStatusColor = (state) => {
    switch (state) {
      case "PRINTING": return "teal";
      case "READY": return "cyan";
      case "IDLE": return "amber";
      case "DISCONNECTED": return "slate";
      default: return "amber";
    }
  };

  const getStatusBg = (state) => {
    switch (state) {
      case "PRINTING": return "bg-teal-500";
      case "READY": return "bg-cyan-500";
      case "IDLE": return "bg-amber-500";
      default: return "bg-slate-500";
    }
  };

  return (
    <div className="space-y-6 animate-slide-up" data-testid="live-status-page">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Radio className="w-8 h-8 text-teal-500 animate-pulse" />
            Live Status
          </h1>
          <p className="text-slate-400 mt-1">
            {DEVICE_NAMES[selectedDevice]} - Echtzeit-Überwachung
          </p>
        </div>
        <div className="flex items-center gap-4">
          {lastUpdate && (
            <span className="text-sm text-slate-400">
              Zuletzt aktualisiert: {lastUpdate.toLocaleTimeString("de-DE")}
            </span>
          )}
          <Button
            onClick={fetchRealtimeData}
            disabled={loading}
            className="bg-teal-500 hover:bg-teal-400 text-slate-950 font-semibold"
            data-testid="refresh-live-button"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? "animate-spin" : ""}`} />
            Aktualisieren
          </Button>
        </div>
      </div>

      {/* Device Cards */}
      <div className={`grid gap-6 ${selectedDevice === "all" ? "grid-cols-1 lg:grid-cols-3" : "grid-cols-1"}`}>
        {Object.entries(realtimeData).map(([devId, data]) => {
          const statusColor = getStatusColor(data.pressState);
          
          return (
            <Card 
              key={devId} 
              className={`industrial-card border-${statusColor}-500/30 ${selectedDevice !== "all" ? "max-w-2xl" : ""}`}
              data-testid={`live-card-${devId}`}
            >
              <CardHeader className="pb-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className={`w-3 h-3 rounded-full ${getStatusBg(data.pressState)} ${data.pressState === "PRINTING" ? "animate-pulse" : ""}`} />
                    <div>
                      <CardTitle className="text-xl font-bold text-white">
                        {DEVICE_NAMES[devId]}
                      </CardTitle>
                      <p className="text-sm text-slate-400">{DEVICE_MODELS[devId]}</p>
                    </div>
                  </div>
                  <Badge 
                    variant="outline" 
                    className={`bg-${statusColor}-500/10 text-${statusColor}-400 border-${statusColor}-500/30 text-sm px-3 py-1`}
                  >
                    {data.pressState}
                  </Badge>
                </div>
              </CardHeader>
              
              <CardContent className="space-y-6">
                {/* Main Stats */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-slate-800/50 rounded-lg p-4 text-center">
                    <Layers className="w-5 h-5 text-cyan-500 mx-auto mb-2" />
                    <p className="text-2xl font-bold text-white font-mono">
                      {formatNumber(data.impressions)}
                    </p>
                    <p className="text-xs text-slate-400 mt-1">Impressions Heute</p>
                  </div>
                  
                  <div className="bg-slate-800/50 rounded-lg p-4 text-center">
                    <FileText className="w-5 h-5 text-teal-500 mx-auto mb-2" />
                    <p className="text-2xl font-bold text-white font-mono">
                      {formatNumber(data.sheets)}
                    </p>
                    <p className="text-xs text-slate-400 mt-1">Sheets Heute</p>
                  </div>
                  
                  <div className="bg-slate-800/50 rounded-lg p-4 text-center">
                    <Printer className="w-5 h-5 text-violet-500 mx-auto mb-2" />
                    <p className="text-2xl font-bold text-white font-mono">
                      {data.printedJobs}
                    </p>
                    <p className="text-xs text-slate-400 mt-1">Jobs Heute</p>
                  </div>
                  
                  <div className="bg-slate-800/50 rounded-lg p-4 text-center">
                    <Zap className="w-5 h-5 text-amber-500 mx-auto mb-2" />
                    <p className="text-2xl font-bold text-white font-mono">
                      {formatNumber(data.impressionsPerHour)}
                    </p>
                    <p className="text-xs text-slate-400 mt-1">Imp./Stunde</p>
                  </div>
                </div>

                {/* Additional Info */}
                {selectedDevice !== "all" && (
                  <div className="border-t border-slate-700 pt-4">
                    <h4 className="text-sm font-semibold text-slate-300 mb-3">Details</h4>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Aktueller Job:</span>
                        <span className="text-white font-mono">{data.currentJobName}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Druckmodus:</span>
                        <span className="text-white font-mono">{data.printMode}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Geschwindigkeit:</span>
                        <span className="text-white font-mono">{data.speed} Imp./h</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Substratbreite:</span>
                        <span className="text-white font-mono">{data.substrateWidth} mm</span>
                      </div>
                    </div>
                    
                    {data.operatorMessage && data.operatorMessage !== "-" && (
                      <div className="mt-4 bg-amber-500/10 border border-amber-500/30 rounded p-3">
                        <p className="text-amber-400 text-sm">
                          <strong>Operator Message:</strong> {data.operatorMessage}
                        </p>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Auto-Refresh Info */}
      <div className="text-center text-sm text-slate-500">
        <Clock className="w-4 h-4 inline mr-2" />
        Automatische Aktualisierung alle 30 Sekunden
      </div>
    </div>
  );
}
