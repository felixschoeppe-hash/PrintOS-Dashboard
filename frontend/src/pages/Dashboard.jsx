import { useState, useEffect, useRef } from "react";
import axios from "axios";
import { toast } from "sonner";
import { format } from "date-fns";
import { 
  Activity, 
  Printer, 
  FileCheck, 
  AlertCircle,
  TrendingUp,
  RefreshCw,
  Play,
  Square,
  Radio,
  Layers
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { DateRangePicker } from "@/components/DateRangePicker";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from "recharts";

const API_URL = `${'https://printos-backend.onrender.com'}/api`;

const DEVICE_NAMES = {
  "47200413": "7K",
  "47100144": "7900", 
  "47100122": "9129",
  "all": "Alle Pressen"
};

export default function Dashboard({ selectedDevice }) {
  const [stats, setStats] = useState(null);
  const [performance, setPerformance] = useState([]);
  const [loading, setLoading] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [dateRange, setDateRange] = useState({ from: null, to: null });
  const [bgSyncRunning, setBgSyncRunning] = useState(false);
  const [recentSyncs, setRecentSyncs] = useState([]);
  const lastSyncCountRef = useRef(0);

  useEffect(() => {
    fetchData();
    checkSyncStatus();
    
    // Poll for sync status updates when background sync is running
    const interval = setInterval(() => {
      if (bgSyncRunning) {
        checkSyncStatus();
      }
    }, 10000); // Check every 10 seconds
    
    return () => clearInterval(interval);
  }, [selectedDevice, dateRange, bgSyncRunning]);

  const checkSyncStatus = async () => {
    try {
      const res = await axios.get(`${API_URL}/sync/status`);
      setBgSyncRunning(res.data.running);
      
      const logs = res.data.recent_logs || [];
      setRecentSyncs(logs.slice(0, 3));
      
      // Show notification for new syncs
      if (logs.length > 0 && lastSyncCountRef.current > 0) {
        const latestSync = logs[0];
        const currentTimestamp = new Date(latestSync.timestamp).getTime();
        const lastTimestamp = lastSyncCountRef.current;
        
        if (currentTimestamp > lastTimestamp && latestSync.jobs_synced > 0) {
          toast.success(`${latestSync.device_name}: ${latestSync.jobs_synced} neue Jobs synchronisiert`, {
            duration: 3000,
          });
          // Refresh data after new sync
          fetchData();
        }
      }
      
      if (logs.length > 0) {
        lastSyncCountRef.current = new Date(logs[0].timestamp).getTime();
      }
    } catch (error) {
      console.log("Sync status check failed");
    }
  };

  const toggleBackgroundSync = async () => {
    try {
      if (bgSyncRunning) {
        await axios.post(`${API_URL}/sync/stop`);
        toast.success("Background Sync gestoppt");
        setBgSyncRunning(false);
      } else {
        await axios.post(`${API_URL}/sync/start`);
        toast.success("Background Sync gestartet - Alle 35 Sek. werden neue Jobs synchronisiert");
        setBgSyncRunning(true);
        lastSyncCountRef.current = Date.now();
      }
    } catch (error) {
      toast.error("Fehler beim Umschalten des Background Sync");
    }
  };

  const fetchData = async () => {
    setLoading(true);
    try {
      const params = { device_id: selectedDevice };
      
      // Add date range params if set
      if (dateRange.from) {
        params.from_date = format(dateRange.from, "yyyy-MM-dd");
      }
      if (dateRange.to) {
        params.to_date = format(dateRange.to, "yyyy-MM-dd");
      }

      const statsRes = await axios.get(`${API_URL}/stats/overview`, { params });
      setStats(statsRes.data);
      
      // Fetch trend data for chart
      try {
        const trendRes = await axios.get(`${API_URL}/clicks/trend`, { params });
        if (trendRes.data && trendRes.data.length > 0) {
          const chartData = trendRes.data.map(item => ({
            date: item.date,
            impressions: (item["1 Color"] || 0) + (item["2 Colors"] || 0) + 
                        (item["EPM"] || 0) + (item["Multicolor"] || 0)
          }));
          setPerformance(chartData);
        } else {
          setPerformance([]);
        }
      } catch (trendError) {
        console.log("Trend data unavailable");
        setPerformance([]);
      }
    } catch (error) {
      console.error("Error fetching dashboard data:", error);
      setStats({
        total_jobs: 0,
        total_impressions: 0,
        total_sheets: 0,
        printed_jobs: 0,
        aborted_jobs: 0,
        success_rate: 0
      });
    } finally {
      setLoading(false);
    }
  };

  const handleSync = async () => {
    setSyncing(true);
    try {
      const deviceToSync = selectedDevice === "all" ? "47100122" : selectedDevice;
      const res = await axios.post(`${API_URL}/jobs/sync`, null, { 
        params: { device_id: deviceToSync } 
      });
      toast.success(`${res.data.jobs_synced} Jobs synchronisiert`);
      fetchData();
    } catch (error) {
      if (error.response?.status === 429) {
        toast.error("Rate Limit erreicht. Bitte 30 Sekunden warten.");
      } else {
        toast.error("Sync fehlgeschlagen: " + (error.response?.data?.detail || error.message));
      }
    } finally {
      setSyncing(false);
    }
  };

  const formatNumber = (num) => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + "M";
    if (num >= 1000) return (num / 1000).toFixed(1) + "K";
    return num?.toLocaleString() || "0";
  };

  return (
    <div className="space-y-6 animate-slide-up" data-testid="dashboard-page">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white">
            Dashboard
          </h1>
          <p className="text-slate-400 mt-1">
            {DEVICE_NAMES[selectedDevice]} - Produktionsübersicht
          </p>
        </div>
        <div className="flex items-center gap-4">
          <DateRangePicker 
            dateRange={dateRange}
            onDateRangeChange={setDateRange}
          />
          
          {/* Background Sync Toggle */}
          <Button
            onClick={toggleBackgroundSync}
            variant="outline"
            className={`border-slate-700 ${bgSyncRunning ? 'text-teal-400 border-teal-500/50' : 'text-slate-300'}`}
            data-testid="bg-sync-toggle"
          >
            {bgSyncRunning ? (
              <>
                <Square className="w-4 h-4 mr-2" />
                Auto-Sync An
              </>
            ) : (
              <>
                <Play className="w-4 h-4 mr-2" />
                Auto-Sync
              </>
            )}
          </Button>
          
          <Button
            onClick={handleSync}
            disabled={syncing}
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold"
            data-testid="sync-button"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${syncing ? "animate-spin" : ""}`} />
            {syncing ? "Synchronisiere..." : "Jobs Sync"}
          </Button>
        </div>
      </div>

      {/* Background Sync Status Banner */}
      {bgSyncRunning && recentSyncs.length > 0 && (
        <div className="bg-teal-500/10 border border-teal-500/30 rounded-lg p-4" data-testid="sync-status-banner">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Radio className="w-5 h-5 text-teal-500 animate-pulse" />
              <span className="text-teal-400 font-medium">Auto-Sync aktiv</span>
            </div>
            <div className="flex items-center gap-2">
              {recentSyncs.slice(0, 3).map((sync, idx) => (
                <Badge 
                  key={idx}
                  variant="outline" 
                  className="bg-slate-800/50 text-slate-300 border-slate-600"
                >
                  {sync.device_name}: {sync.jobs_synced} Jobs
                </Badge>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
        <Card className="industrial-card metric-card" data-testid="card-total-jobs">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-slate-400">
              Gesamt Jobs
            </CardTitle>
            <FileCheck className="h-5 w-5 text-cyan-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-white font-mono">
              {loading ? "..." : formatNumber(stats?.total_jobs)}
            </div>
            <p className="text-xs text-slate-500 mt-1">
              {dateRange.from ? "im Zeitraum" : "aus der Datenbank"}
            </p>
          </CardContent>
        </Card>

        <Card className="industrial-card metric-card" data-testid="card-total-impressions">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-slate-400">
              Impressionen
            </CardTitle>
            <Printer className="h-5 w-5 text-teal-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-white font-mono">
              {loading ? "..." : formatNumber(stats?.total_impressions)}
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Gesamtproduktion
            </p>
          </CardContent>
        </Card>

        <Card className="industrial-card metric-card" data-testid="card-total-sheets">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-slate-400">
              Sheets
            </CardTitle>
            <Layers className="h-5 w-5 text-violet-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-white font-mono">
              {loading ? "..." : formatNumber(stats?.total_sheets || 0)}
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Gedruckte Blätter
            </p>
          </CardContent>
        </Card>

        <Card className="industrial-card metric-card" data-testid="card-success-rate">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-slate-400">
              Erfolgsrate
            </CardTitle>
            <TrendingUp className="h-5 w-5 text-teal-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-teal-400 font-mono">
              {loading ? "..." : `${stats?.success_rate || 0}%`}
            </div>
            <p className="text-xs text-slate-500 mt-1">
              {stats?.printed_jobs || 0} erfolgreich
            </p>
          </CardContent>
        </Card>

        <Card className="industrial-card metric-card" data-testid="card-aborted">
          <CardHeader className="flex flex-row items-center justify-between pb-2">
            <CardTitle className="text-sm font-medium text-slate-400">
              Abgebrochen
            </CardTitle>
            <AlertCircle className="h-5 w-5 text-rose-500" />
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-rose-400 font-mono">
              {loading ? "..." : formatNumber(stats?.aborted_jobs)}
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Fehlgeschlagene Jobs
            </p>
          </CardContent>
        </Card>
      </div>

      {/* Production Chart */}
      <Card className="industrial-card" data-testid="production-chart">
        <CardHeader>
          <CardTitle className="text-lg font-semibold text-white flex items-center gap-2">
            <Activity className="w-5 h-5 text-cyan-500" />
            Produktionsverlauf
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-80">
            {performance.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={performance}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis 
                    dataKey="date" 
                    stroke="#64748b"
                    tick={{ fill: '#94a3b8', fontSize: 12 }}
                    tickFormatter={(value) => value?.substring(5) || value}
                  />
                  <YAxis 
                    stroke="#64748b"
                    tick={{ fill: '#94a3b8', fontSize: 12 }}
                    tickFormatter={(value) => formatNumber(value)}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      border: '1px solid #334155',
                      borderRadius: '4px'
                    }}
                    labelStyle={{ color: '#94a3b8' }}
                  />
                  <Legend />
                  <Bar dataKey="impressions" fill="#06b6d4" name="Impressionen" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-slate-500">
                <div className="text-center">
                  <Activity className="w-12 h-12 mx-auto mb-4 opacity-50" />
                  <p>Keine Produktionsdaten verfügbar</p>
                  <p className="text-sm mt-2">Klicke auf "Jobs Sync" um Daten zu laden</p>
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
