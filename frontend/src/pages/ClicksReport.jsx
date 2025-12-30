import { useState, useEffect } from "react";
import axios from "axios";
import { toast } from "sonner";
import { format } from "date-fns";
import { 
  Receipt, 
  Download,
  Layers,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Minus,
  CalendarRange
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { DateRangePicker } from "@/components/DateRangePicker";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from "recharts";
import { useDevices } from "@/hooks/useDevices";

const API_URL = `${'https://printos-backend.onrender.com'}/api`;

const COLORS = {
  "1 Color": "#06b6d4",
  "2 Colors": "#d946ef",
  "EPM": "#8b5cf6",
  "Multicolor": "#f8fafc",
  "Unknown": "#64748b"
};



export default function ClicksReport({ selectedDevice }) {
  const { deviceNames } = useDevices();
  const [report, setReport] = useState(null);
  const [trend, setTrend] = useState([]);
  const [yoyData, setYoyData] = useState(null);
  const [yoyTrend, setYoyTrend] = useState(null);
  const [showYoY, setShowYoY] = useState(false);
  const [isOneShot, setIsOneShot] = useState(false);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [dateRange, setDateRange] = useState({ from: null, to: null });
  const [resolution, setResolution] = useState("day");

  useEffect(() => {
    fetchData();
  }, [selectedDevice, isOneShot, dateRange, resolution]);

  useEffect(() => {
    if (showYoY) {
      fetchYoYData();
    }
  }, [showYoY, selectedDevice, dateRange]);

  const fetchData = async () => {
    setLoading(true);
    try {
      const params = { 
        device_id: selectedDevice,
        is_oneshot: isOneShot ? true : undefined,
        resolution
      };
      
      if (dateRange.from) {
        params.from_date = format(dateRange.from, "yyyy-MM-dd");
      }
      if (dateRange.to) {
        params.to_date = format(dateRange.to, "yyyy-MM-dd");
      }

      const [reportRes, trendRes] = await Promise.all([
        axios.get(`${API_URL}/clicks/report`, { params }),
        axios.get(`${API_URL}/clicks/trend`, { params })
      ]);
      
      setReport(reportRes.data);
      setTrend(trendRes.data);
    } catch (error) {
      console.error("Error fetching clicks data:", error);
      toast.error("Fehler beim Laden der Clicks-Daten");
    } finally {
      setLoading(false);
    }
  };

  const fetchYoYData = async () => {
    try {
      const params = { device_id: selectedDevice };
      
      if (dateRange.from) {
        params.from_date = format(dateRange.from, "yyyy-MM-dd");
      }
      if (dateRange.to) {
        params.to_date = format(dateRange.to, "yyyy-MM-dd");
      }

      const [yoyRes, yoyTrendRes] = await Promise.all([
        axios.get(`${API_URL}/clicks/yoy`, { params }),
        axios.get(`${API_URL}/clicks/yoy/trend`, { params })
      ]);
      
      setYoyData(yoyRes.data);
      setYoyTrend(yoyTrendRes.data);
    } catch (error) {
      console.error("Error fetching YoY data:", error);
      toast.error("Fehler beim Laden der Jahresvergleich-Daten");
    }
  };

  const handleRefresh = async (force = false) => {
    setRefreshing(true);
    try {
      const params = { 
        device_id: selectedDevice,
        force: force  // Force fetch from API even if data exists
      };
      
      if (dateRange.from) {
        params.from_date = format(dateRange.from, "yyyy-MM-dd");
      }
      if (dateRange.to) {
        params.to_date = format(dateRange.to, "yyyy-MM-dd");
      }

      const res = await axios.post(`${API_URL}/data/refresh`, null, { params });
      
      if (res.data.total_synced > 0) {
        toast.success(`${res.data.total_synced} neue Jobs von der API geladen`);
      } else {
        // Check if any device had data synced
        const synced = res.data.results?.filter(r => r.status === "synced");
        if (synced?.length > 0) {
          toast.info("API abgefragt, keine neuen Jobs gefunden");
        } else {
          toast.info(res.data.message || "Keine neuen Daten verfügbar");
        }
      }
      
      // Reload data after refresh
      await fetchData();
    } catch (error) {
      if (error.response?.status === 429) {
        toast.error("API Rate Limit erreicht. Bitte 30 Sekunden warten.");
      } else {
        toast.error("Fehler beim Aktualisieren: " + (error.response?.data?.detail || error.message));
      }
    } finally {
      setRefreshing(false);
    }
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      const params = { 
        device_id: selectedDevice,
        is_oneshot: isOneShot ? true : undefined
      };
      
      if (dateRange.from) {
        params.from_date = format(dateRange.from, "yyyy-MM-dd");
      }
      if (dateRange.to) {
        params.to_date = format(dateRange.to, "yyyy-MM-dd");
      }

      const response = await axios.get(`${API_URL}/clicks/export`, {
        params,
        responseType: 'blob'
      });
      
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `clicks_report_${new Date().toISOString().split('T')[0]}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      
      toast.success("Export erfolgreich");
    } catch (error) {
      toast.error("Export fehlgeschlagen");
    } finally {
      setExporting(false);
    }
  };

  const formatNumber = (num) => {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + "M";
    if (num >= 1000) return (num / 1000).toFixed(1) + "K";
    return num?.toLocaleString() || "0";
  };

  const formatTrendDate = (value) => {
    if (!value) return "";
    if (resolution === "year") {
      return value; // Just the year: 2025
    }
    if (resolution === "month") {
      const [year, month] = value.split("-");
      const months = ["Jan", "Feb", "Mär", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez"];
      return `${months[parseInt(month) - 1]} ${year.slice(2)}`;
    }
    return value.substring(5); // Day: MM-DD
  };

  const pieData = report?.categories?.filter(c => c.impressions > 0) || [];

  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-slate-900 border border-slate-700 p-3 rounded">
          <p className="text-slate-300 text-sm">{payload[0].name}</p>
          <p className="text-white font-mono font-bold">
            {formatNumber(payload[0].value)} Impressionen
          </p>
        </div>
      );
    }
    return null;
  };

  const getResolutionLabel = () => {
    switch (resolution) {
      case "year": return "Jährlich";
      case "month": return "Monatlich";
      default: return "Täglich";
    }
  };

  const getDataSourceLabel = () => {
    if (report?.data_source === "printvolume") {
      return "HP PrintVolume API";
    }
    return "HP Jobs API";
  };

  return (
    <div className="space-y-6 animate-slide-up" data-testid="clicks-report-page">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <Receipt className="w-8 h-8 text-cyan-500" />
            Clicks Report
          </h1>
          <p className="text-slate-400 mt-1">
            {deviceNames[selectedDevice]} - Abrechnungsübersicht (SRA3 Format)
            <span className="ml-2 text-xs bg-slate-800 px-2 py-1 rounded">
              Quelle: {getDataSourceLabel()}
            </span>
          </p>
        </div>
        
        <div className="flex items-center gap-3 flex-wrap">
          <DateRangePicker 
            dateRange={dateRange}
            onDateRangeChange={setDateRange}
          />
          
          {/* Resolution Selector */}
          <Select value={resolution} onValueChange={setResolution}>
            <SelectTrigger 
              className="w-[130px] bg-slate-800 border-slate-700 text-white"
              data-testid="resolution-selector"
            >
              <SelectValue placeholder="Auflösung" />
            </SelectTrigger>
            <SelectContent className="bg-slate-800 border-slate-700">
              <SelectItem value="day" className="text-white">Täglich</SelectItem>
              <SelectItem value="month" className="text-white">Monatlich</SelectItem>
              <SelectItem value="year" className="text-white">Jährlich</SelectItem>
            </SelectContent>
          </Select>
          
          {/* OneShot/MultiShot Toggle */}
          <div className="flex items-center gap-3 bg-slate-800 px-4 py-2 rounded-sm border border-slate-700">
            <Label 
              htmlFor="shot-toggle" 
              className={`text-sm ${!isOneShot ? 'text-cyan-400' : 'text-slate-400'}`}
            >
              MultiShot
            </Label>
            <Switch
              id="shot-toggle"
              checked={isOneShot}
              onCheckedChange={setIsOneShot}
              data-testid="oneshot-toggle"
            />
            <Label 
              htmlFor="shot-toggle" 
              className={`text-sm ${isOneShot ? 'text-cyan-400' : 'text-slate-400'}`}
            >
              OneShot
            </Label>
          </div>
          
          {/* YoY Toggle */}
          <div className="flex items-center gap-3 bg-slate-800 px-4 py-2 rounded-sm border border-slate-700">
            <CalendarRange className="w-4 h-4 text-slate-400" />
            <Label 
              htmlFor="yoy-toggle" 
              className={`text-sm ${showYoY ? 'text-amber-400' : 'text-slate-400'}`}
            >
              Jahr-zu-Jahr
            </Label>
            <Switch
              id="yoy-toggle"
              checked={showYoY}
              onCheckedChange={setShowYoY}
              data-testid="yoy-toggle"
            />
          </div>
          
          {/* Refresh Button */}
          <Button
            onClick={handleRefresh}
            disabled={refreshing}
            variant="outline"
            className="border-slate-700 text-slate-300 hover:bg-slate-800 hover:text-white"
            data-testid="refresh-button"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? "animate-spin" : ""}`} />
            {refreshing ? "Lade..." : "Aktualisieren"}
          </Button>
          
          <Button
            onClick={handleExport}
            disabled={exporting}
            className="bg-teal-500 hover:bg-teal-400 text-slate-950 font-semibold"
            data-testid="export-button"
          >
            <Download className="w-4 h-4 mr-2" />
            {exporting ? "Exportiere..." : "CSV Export"}
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-4">
        <Card className="industrial-card" data-testid="card-1color">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-cyan-500"></div>
              <span className="text-slate-400 text-sm">1 Color</span>
            </div>
            <div className="text-2xl font-bold text-white font-mono mt-2">
              {loading ? "..." : formatNumber(report?.one_color)}
            </div>
          </CardContent>
        </Card>

        <Card className="industrial-card" data-testid="card-2colors">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-fuchsia-500"></div>
              <span className="text-slate-400 text-sm">2 Colors</span>
            </div>
            <div className="text-2xl font-bold text-white font-mono mt-2">
              {loading ? "..." : formatNumber(report?.two_colors)}
            </div>
          </CardContent>
        </Card>

        <Card className="industrial-card" data-testid="card-epm">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-violet-500"></div>
              <span className="text-slate-400 text-sm">EPM</span>
            </div>
            <div className="text-2xl font-bold text-white font-mono mt-2">
              {loading ? "..." : formatNumber(report?.epm)}
            </div>
          </CardContent>
        </Card>

        <Card className="industrial-card" data-testid="card-multicolor">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <div className="w-3 h-3 rounded-full bg-white"></div>
              <span className="text-slate-400 text-sm">Multicolor</span>
            </div>
            <div className="text-2xl font-bold text-white font-mono mt-2">
              {loading ? "..." : formatNumber(report?.multicolor)}
            </div>
          </CardContent>
        </Card>

        <Card className="industrial-card border-cyan-500/30" data-testid="card-total">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Layers className="w-4 h-4 text-cyan-500" />
              <span className="text-slate-400 text-sm">Impressions</span>
            </div>
            <div className="text-2xl font-bold text-cyan-400 font-mono mt-2">
              {loading ? "..." : formatNumber(report?.total_impressions)}
            </div>
          </CardContent>
        </Card>

        <Card className="industrial-card border-violet-500/30" data-testid="card-sheets">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Layers className="w-4 h-4 text-violet-500" />
              <span className="text-slate-400 text-sm">Sheets</span>
            </div>
            <div className="text-2xl font-bold text-violet-400 font-mono mt-2">
              {loading ? "..." : formatNumber(report?.total_sheets || 0)}
            </div>
          </CardContent>
        </Card>

        <Card className="industrial-card border-teal-500/30" data-testid="card-jobs">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <Receipt className="w-4 h-4 text-teal-500" />
              <span className="text-slate-400 text-sm">Aufträge</span>
            </div>
            <div className="text-2xl font-bold text-teal-400 font-mono mt-2">
              {loading ? "..." : formatNumber(report?.total_jobs || 0)}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* No Data Message */}
      {!loading && report?.total_impressions === 0 && (
        <Card className="industrial-card border-amber-500/30">
          <CardContent className="py-8 text-center">
            <p className="text-amber-400 mb-4">
              Keine Daten für den ausgewählten Zeitraum gefunden
            </p>
            <Button
              onClick={() => handleRefresh(true)}
              disabled={refreshing}
              className="bg-amber-500 hover:bg-amber-400 text-slate-950"
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${refreshing ? "animate-spin" : ""}`} />
              Neue Daten von API laden
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Pie Chart */}
        <Card className="industrial-card" data-testid="pie-chart">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-white">
              Click-Kategorien Verteilung
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="h-80">
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={100}
                      paddingAngle={2}
                      dataKey="impressions"
                      nameKey="name"
                      label={({ name, percent }) => `${name} (${(percent * 100).toFixed(0)}%)`}
                      labelLine={{ stroke: '#64748b' }}
                    >
                      {pieData.map((entry, index) => (
                        <Cell 
                          key={`cell-${index}`} 
                          fill={COLORS[entry.name] || COLORS.Unknown}
                          stroke="#0f172a"
                          strokeWidth={2}
                        />
                      ))}
                    </Pie>
                    <Tooltip content={<CustomTooltip />} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-full text-slate-500">
                  <p>Keine Daten verfügbar</p>
                </div>
              )}
            </div>
          </CardContent>
        </Card>

        {/* OneShot vs MultiShot */}
        <Card className="industrial-card" data-testid="shot-comparison">
          <CardHeader>
            <CardTitle className="text-lg font-semibold text-white">
              OneShot vs MultiShot
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-6 pt-4">
              <div>
                <div className="flex justify-between mb-2">
                  <span className="text-slate-400">MultiShot</span>
                  <span className="text-white font-mono">
                    {formatNumber(report?.multishot_total || 0)}
                  </span>
                </div>
                <div className="h-4 bg-slate-800 rounded-sm overflow-hidden">
                  <div 
                    className="h-full bg-cyan-500 transition-all duration-500"
                    style={{ 
                      width: `${((report?.multishot_total || 0) / Math.max((report?.total_impressions || 1), 1)) * 100}%` 
                    }}
                  />
                </div>
              </div>
              
              <div>
                <div className="flex justify-between mb-2">
                  <span className="text-slate-400">OneShot</span>
                  <span className="text-white font-mono">
                    {formatNumber(report?.oneshot_total || 0)}
                  </span>
                </div>
                <div className="h-4 bg-slate-800 rounded-sm overflow-hidden">
                  <div 
                    className="h-full bg-teal-500 transition-all duration-500"
                    style={{ 
                      width: `${((report?.oneshot_total || 0) / Math.max((report?.total_impressions || 1), 1)) * 100}%` 
                    }}
                  />
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Trend Chart */}
      <Card className="industrial-card" data-testid="trend-chart">
        <CardHeader>
          <CardTitle className="text-lg font-semibold text-white">
            Trend nach Kategorie ({getResolutionLabel()})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="h-80">
            {trend.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={trend}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                  <XAxis 
                    dataKey="date" 
                    stroke="#64748b"
                    tick={{ fill: '#94a3b8', fontSize: 12 }}
                    tickFormatter={formatTrendDate}
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
                  />
                  <Legend />
                  <Bar dataKey="1 Color" stackId="a" fill="#06b6d4" name="1 Color" />
                  <Bar dataKey="2 Colors" stackId="a" fill="#d946ef" name="2 Colors" />
                  <Bar dataKey="EPM" stackId="a" fill="#8b5cf6" name="EPM" />
                  <Bar dataKey="Multicolor" stackId="a" fill="#f8fafc" name="Multicolor" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-slate-500">
                <p>Keine Trenddaten verfügbar</p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Year-over-Year Comparison Section */}
      {showYoY && (
        <div className="space-y-6 pt-4 border-t border-slate-700" data-testid="yoy-section">
          <h2 className="text-xl font-semibold text-white flex items-center gap-2">
            <CalendarRange className="w-5 h-5 text-amber-500" />
            Jahr-zu-Jahr Vergleich
          </h2>
          
          {/* YoY Summary Cards */}
          {yoyData && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Current Year */}
              <Card className="industrial-card" data-testid="yoy-current">
                <CardContent className="pt-6">
                  <div className="text-sm text-slate-400 mb-1">
                    Aktueller Zeitraum ({yoyData.current_period.from} - {yoyData.current_period.to})
                  </div>
                  <div className="text-3xl font-bold text-white font-mono">
                    {formatNumber(yoyData.current_period.total_impressions)}
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    Quelle: {yoyData.current_period.source === "printvolume" ? "HP PrintVolume API" : "HP Jobs API"}
                  </div>
                </CardContent>
              </Card>

              {/* Previous Year */}
              <Card className="industrial-card" data-testid="yoy-previous">
                <CardContent className="pt-6">
                  <div className="text-sm text-slate-400 mb-1">
                    Vorjahr ({yoyData.previous_period.from} - {yoyData.previous_period.to})
                  </div>
                  <div className="text-3xl font-bold text-slate-400 font-mono">
                    {formatNumber(yoyData.previous_period.total_impressions)}
                  </div>
                  <div className="text-xs text-slate-500 mt-1">
                    Quelle: {yoyData.previous_period.source === "printvolume" ? "HP PrintVolume API" : "HP Jobs API"}
                  </div>
                </CardContent>
              </Card>

              {/* Change */}
              <Card className={`industrial-card ${
                yoyData.trend === "up" ? "border-emerald-500/30" : 
                yoyData.trend === "down" ? "border-rose-500/30" : "border-slate-700"
              }`} data-testid="yoy-change">
                <CardContent className="pt-6">
                  <div className="text-sm text-slate-400 mb-1">Veränderung</div>
                  <div className={`text-3xl font-bold font-mono flex items-center gap-2 ${
                    yoyData.trend === "up" ? "text-emerald-400" : 
                    yoyData.trend === "down" ? "text-rose-400" : "text-slate-400"
                  }`}>
                    {yoyData.trend === "up" && <TrendingUp className="w-6 h-6" />}
                    {yoyData.trend === "down" && <TrendingDown className="w-6 h-6" />}
                    {yoyData.trend === "stable" && <Minus className="w-6 h-6" />}
                    {yoyData.change_percent > 0 ? "+" : ""}{yoyData.change_percent}%
                  </div>
                  <div className="text-sm text-slate-500 mt-1 font-mono">
                    {yoyData.change_absolute > 0 ? "+" : ""}{formatNumber(yoyData.change_absolute)} Impressionen
                  </div>
                </CardContent>
              </Card>
            </div>
          )}

          {/* YoY Trend Chart */}
          {yoyTrend && (
            <Card className="industrial-card" data-testid="yoy-trend-chart">
              <CardHeader>
                <CardTitle className="text-lg font-semibold text-white">
                  Monatlicher Vergleich: {yoyTrend.current_year} vs {yoyTrend.previous_year}
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="h-80">
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={yoyTrend.trend}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                      <XAxis 
                        dataKey="month" 
                        stroke="#64748b"
                        tick={{ fill: '#94a3b8', fontSize: 12 }}
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
                        formatter={(value) => [formatNumber(value), ""]}
                      />
                      <Legend />
                      <Line 
                        type="monotone" 
                        dataKey="current_year" 
                        stroke="#06b6d4" 
                        strokeWidth={3}
                        name={`${yoyTrend.current_year}`}
                        dot={{ fill: '#06b6d4', strokeWidth: 2 }}
                        activeDot={{ r: 6, fill: '#06b6d4' }}
                      />
                      <Line 
                        type="monotone" 
                        dataKey="previous_year" 
                        stroke="#64748b" 
                        strokeWidth={2}
                        strokeDasharray="5 5"
                        name={`${yoyTrend.previous_year}`}
                        dot={{ fill: '#64748b', strokeWidth: 2 }}
                        activeDot={{ r: 6, fill: '#64748b' }}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
