import { useState, useEffect } from "react";
import axios from "axios";
import { toast } from "sonner";
import { 
  Activity, 
  AlertTriangle,
  RefreshCw,
  CheckCircle,
  XCircle,
  RotateCcw
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { DateRangePicker } from "@/components/DateRangePicker";
import { format } from "date-fns";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  BarChart,
  Bar
} from "recharts";

const API_URL = `${'https://printos-backend.onrender.com'}/api`;

const DEVICE_NAMES = {
  "47200413": "7K",
  "47100144": "7900",
  "47100122": "9129",
  "all": "Alle Pressen"
};

export default function AvailabilityAnalysis({ selectedDevice }) {
  const [analysisData, setAnalysisData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [dateRange, setDateRange] = useState({ from: null, to: null });

  useEffect(() => {
    fetchAnalysisData();
  }, [selectedDevice, dateRange]);

  const fetchAnalysisData = async () => {
    setLoading(true);
    try {
      const params = { device_id: selectedDevice };
      
      if (dateRange.from) {
        params.from_date = format(dateRange.from, "yyyy-MM-dd");
      }
      if (dateRange.to) {
        params.to_date = format(dateRange.to, "yyyy-MM-dd");
      }

      const res = await axios.get(`${API_URL}/analysis/availability`, { params });
      setAnalysisData(res.data);
    } catch (error) {
      console.error("Error fetching analysis data:", error);
      toast.error("Fehler beim Laden der Analysedaten");
      setAnalysisData(null);
    } finally {
      setLoading(false);
    }
  };

  const formatDate = (dateStr) => {
    if (!dateStr) return "";
    return dateStr.substring(5); // MM-DD
  };

  const getAvailabilityColor = (value) => {
    if (value >= 90) return "text-emerald-400";
    if (value >= 75) return "text-amber-400";
    return "text-rose-400";
  };

  return (
    <div className="space-y-6 animate-slide-up" data-testid="availability-analysis-page">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Activity className="w-8 h-8 text-emerald-500" />
            Availability Analysis
          </h1>
          <p className="text-slate-400 mt-1">
            {DEVICE_NAMES[selectedDevice]} - Verfügbarkeits- und Fehleranalyse
          </p>
        </div>
        <div className="flex items-center gap-4">
          <DateRangePicker 
            dateRange={dateRange}
            onDateRangeChange={setDateRange}
          />
          <Button
            onClick={fetchAnalysisData}
            disabled={loading}
            className="bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-semibold"
            data-testid="refresh-analysis-button"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? "animate-spin" : ""}`} />
            Aktualisieren
          </Button>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <RefreshCw className="w-8 h-8 text-slate-400 animate-spin" />
        </div>
      ) : analysisData ? (
        <>
          {/* Availability Analysis Section */}
          <Card className="industrial-card border-emerald-500/30" data-testid="availability-section">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-white flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-emerald-500" />
                🟢 Availability Analysis - Verfügbarkeit über Zeit
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                {/* Average Availability */}
                <div className="bg-slate-800/50 rounded-lg p-6 text-center">
                  <p className="text-slate-400 text-sm mb-2">Ø Verfügbarkeit</p>
                  <p className={`text-5xl font-bold font-mono ${getAvailabilityColor(analysisData.availability?.average)}`}>
                    {analysisData.availability?.average || 0}%
                  </p>
                </div>
                
                {/* Availability Trend Chart */}
                <div className="lg:col-span-3 h-64">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={analysisData.availability?.trend || []}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis 
                        dataKey="date" 
                        stroke="#64748b"
                        tick={{ fill: '#94a3b8', fontSize: 12 }}
                        tickFormatter={formatDate}
                      />
                      <YAxis 
                        stroke="#64748b"
                        tick={{ fill: '#94a3b8', fontSize: 12 }}
                        domain={[0, 100]}
                        tickFormatter={(v) => `${v}%`}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          border: '1px solid #334155',
                          borderRadius: '4px'
                        }}
                        formatter={(value) => [`${value}%`, "Verfügbarkeit"]}
                      />
                      <Line 
                        type="monotone" 
                        dataKey="value" 
                        stroke="#10b981" 
                        strokeWidth={3}
                        dot={{ fill: '#10b981', strokeWidth: 2 }}
                        activeDot={{ r: 6, fill: '#10b981' }}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Technical Issues Analysis Section */}
          <Card className="industrial-card border-amber-500/30" data-testid="technical-issues-section">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-white flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-amber-500" />
                ⚠️ Technical Issues Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Failure Rate Stats */}
                <div className="space-y-4">
                  <h4 className="text-slate-300 font-medium">Failure Rate / 1M Impressions (Tag)</h4>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-slate-800/50 rounded-lg p-4 text-center">
                      <p className="text-slate-400 text-xs mb-1">Ø Durchschnitt</p>
                      <p className="text-2xl font-bold text-amber-400 font-mono">
                        {analysisData.technicalIssues?.failureRate?.average || 0}
                      </p>
                    </div>
                    <div className="bg-slate-800/50 rounded-lg p-4 text-center">
                      <p className="text-slate-400 text-xs mb-1">Maximum</p>
                      <p className="text-2xl font-bold text-rose-400 font-mono">
                        {analysisData.technicalIssues?.failureRate?.max || 0}
                      </p>
                    </div>
                  </div>
                </div>
                
                {/* Paper Jam Rate Stats */}
                <div className="space-y-4">
                  <h4 className="text-slate-300 font-medium">Paper Jam Rate / 1M Sheets (Tag)</h4>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-slate-800/50 rounded-lg p-4 text-center">
                      <p className="text-slate-400 text-xs mb-1">Ø Durchschnitt</p>
                      <p className="text-2xl font-bold text-amber-400 font-mono">
                        {analysisData.technicalIssues?.paperJamRate?.average || 0}
                      </p>
                    </div>
                    <div className="bg-slate-800/50 rounded-lg p-4 text-center">
                      <p className="text-slate-400 text-xs mb-1">Maximum</p>
                      <p className="text-2xl font-bold text-rose-400 font-mono">
                        {analysisData.technicalIssues?.paperJamRate?.max || 0}
                      </p>
                    </div>
                  </div>
                </div>
              </div>

              {/* Daily Chart */}
              <div className="mt-6 h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={analysisData.technicalIssues?.dailyData || []}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                    <XAxis 
                      dataKey="date" 
                      stroke="#64748b"
                      tick={{ fill: '#94a3b8', fontSize: 12 }}
                      tickFormatter={formatDate}
                    />
                    <YAxis 
                      stroke="#64748b"
                      tick={{ fill: '#94a3b8', fontSize: 12 }}
                    />
                    <Tooltip
                      contentStyle={{
                        backgroundColor: '#0f172a',
                        border: '1px solid #334155',
                        borderRadius: '4px'
                      }}
                    />
                    <Legend />
                    <Bar dataKey="failures" fill="#f59e0b" name="Failures / 1M" />
                    <Bar dataKey="jams" fill="#ef4444" name="Paper Jams / 1M" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          {/* Restarts Analysis Section */}
          <Card className="industrial-card border-cyan-500/30" data-testid="restarts-section">
            <CardHeader>
              <CardTitle className="text-lg font-semibold text-white flex items-center gap-2">
                <RotateCcw className="w-5 h-5 text-cyan-500" />
                🔄 Restarts Analysis
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
                {/* Restart Stats */}
                <div className="space-y-4">
                  <div className="bg-slate-800/50 rounded-lg p-4 text-center">
                    <p className="text-slate-400 text-xs mb-1">Ø Restart Rate</p>
                    <p className="text-3xl font-bold text-cyan-400 font-mono">
                      {analysisData.restarts?.averageRate || 0}
                    </p>
                    <p className="text-slate-500 text-xs">pro Tag</p>
                  </div>
                  <div className="bg-slate-800/50 rounded-lg p-4 text-center">
                    <p className="text-slate-400 text-xs mb-1">Max Rate</p>
                    <p className="text-3xl font-bold text-rose-400 font-mono">
                      {analysisData.restarts?.maxRate || 0}
                    </p>
                    <p className="text-slate-500 text-xs">pro Tag</p>
                  </div>
                </div>
                
                {/* Restarts Chart */}
                <div className="lg:col-span-3 h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={analysisData.restarts?.dailyData || []}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis 
                        dataKey="date" 
                        stroke="#64748b"
                        tick={{ fill: '#94a3b8', fontSize: 12 }}
                        tickFormatter={formatDate}
                      />
                      <YAxis 
                        stroke="#64748b"
                        tick={{ fill: '#94a3b8', fontSize: 12 }}
                      />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0f172a',
                          border: '1px solid #334155',
                          borderRadius: '4px'
                        }}
                      />
                      <Bar dataKey="restarts" fill="#06b6d4" name="Restarts" />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>
            </CardContent>
          </Card>
        </>
      ) : (
        <div className="text-center text-slate-400 py-12">
          Keine Analysedaten verfügbar
        </div>
      )}
    </div>
  );
}
