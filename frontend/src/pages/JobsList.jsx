import { useState, useEffect, useCallback } from "react";
import axios from "axios";
import { toast } from "sonner";
import { format } from "date-fns";
import { 
  FileText, 
  Search,
  AlertTriangle,
  ChevronLeft,
  ChevronRight
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { DateRangePicker } from "@/components/DateRangePicker";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const API_URL = `${process.env.REACT_APP_BACKEND_URL}/api`;

const DEVICE_NAMES = {
  "47200413": "7K",
  "47100144": "7900",
  "47100122": "9129",
  "all": "Alle Pressen"
};

const STATUS_STYLES = {
  "PRINTED": "bg-teal-500/10 text-teal-400 border-teal-500/30",
  "ABORTED": "bg-rose-500/10 text-rose-400 border-rose-500/30",
  "UNKNOWN": "bg-slate-500/10 text-slate-400 border-slate-500/30"
};

const CATEGORY_STYLES = {
  "1 Color": "bg-cyan-500/10 text-cyan-400 border-cyan-500/30",
  "2 Colors": "bg-fuchsia-500/10 text-fuchsia-400 border-fuchsia-500/30",
  "EPM": "bg-violet-500/10 text-violet-400 border-violet-500/30",
  "Multicolor": "bg-white/10 text-white border-white/30",
  "Unknown": "bg-slate-500/10 text-slate-400 border-slate-500/30"
};

export default function JobsList({ selectedDevice }) {
  const [jobs, setJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [problemJobs, setProblemJobs] = useState(false);
  const [statusFilter, setStatusFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [dateRange, setDateRange] = useState({ from: null, to: null });

  const fetchJobs = useCallback(async () => {
    setLoading(true);
    try {
      const params = {
        device_id: selectedDevice,
        page,
        limit: 25
      };
      
      if (search) params.search = search;
      if (problemJobs) params.problem_jobs = true;
      if (statusFilter !== "all") params.status = statusFilter;
      if (categoryFilter !== "all") params.click_category = categoryFilter;
      
      // Add date range params
      if (dateRange.from) {
        params.from_date = format(dateRange.from, "yyyy-MM-dd");
      }
      if (dateRange.to) {
        params.to_date = format(dateRange.to, "yyyy-MM-dd");
      }

      const res = await axios.get(`${API_URL}/jobs`, { params });
      setJobs(res.data.jobs || []);
      setTotalPages(res.data.pages || 1);
      setTotal(res.data.total || 0);
    } catch (error) {
      console.error("Error fetching jobs:", error);
      toast.error("Fehler beim Laden der Jobs");
    } finally {
      setLoading(false);
    }
  }, [selectedDevice, page, search, problemJobs, statusFilter, categoryFilter, dateRange]);

  useEffect(() => {
    fetchJobs();
  }, [fetchJobs]);

  useEffect(() => {
    setPage(1);
  }, [selectedDevice, search, problemJobs, statusFilter, categoryFilter, dateRange]);

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

  const formatNumber = (num) => {
    return num?.toLocaleString('de-DE') || "0";
  };

  return (
    <div className="space-y-6 animate-slide-up" data-testid="jobs-list-page">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center gap-3">
            <FileText className="w-8 h-8 text-cyan-500" />
            Jobs Liste
          </h1>
          <p className="text-slate-400 mt-1">
            {DEVICE_NAMES[selectedDevice]} - {total} Jobs gefunden
          </p>
        </div>
        
        {/* Date Range Picker */}
        <DateRangePicker 
          dateRange={dateRange}
          onDateRangeChange={setDateRange}
        />
      </div>

      {/* Filters */}
      <Card className="industrial-card" data-testid="filters-card">
        <CardContent className="pt-6">
          <div className="flex flex-wrap items-center gap-4">
            {/* Search */}
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <Input
                placeholder="Job-Name suchen..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10 bg-slate-800 border-slate-700 text-white"
                data-testid="search-input"
              />
            </div>

            {/* Status Filter */}
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger 
                className="w-[150px] bg-slate-800 border-slate-700 text-white"
                data-testid="status-filter"
              >
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent className="bg-slate-800 border-slate-700">
                <SelectItem value="all" className="text-white">Alle Status</SelectItem>
                <SelectItem value="PRINTED" className="text-teal-400">Gedruckt</SelectItem>
                <SelectItem value="ABORTED" className="text-rose-400">Abgebrochen</SelectItem>
              </SelectContent>
            </Select>

            {/* Category Filter */}
            <Select value={categoryFilter} onValueChange={setCategoryFilter}>
              <SelectTrigger 
                className="w-[150px] bg-slate-800 border-slate-700 text-white"
                data-testid="category-filter"
              >
                <SelectValue placeholder="Kategorie" />
              </SelectTrigger>
              <SelectContent className="bg-slate-800 border-slate-700">
                <SelectItem value="all" className="text-white">Alle Kategorien</SelectItem>
                <SelectItem value="1 Color" className="text-cyan-400">1 Color</SelectItem>
                <SelectItem value="2 Colors" className="text-fuchsia-400">2 Colors</SelectItem>
                <SelectItem value="EPM" className="text-violet-400">EPM</SelectItem>
                <SelectItem value="Multicolor" className="text-white">Multicolor</SelectItem>
              </SelectContent>
            </Select>

            {/* Problem Jobs Toggle */}
            <div className="flex items-center gap-2 bg-slate-800 px-4 py-2 rounded-sm border border-slate-700">
              <AlertTriangle className="w-4 h-4 text-amber-500" />
              <Label htmlFor="problem-toggle" className="text-slate-400 text-sm">
                Problem-Jobs
              </Label>
              <Switch
                id="problem-toggle"
                checked={problemJobs}
                onCheckedChange={setProblemJobs}
                data-testid="problem-jobs-toggle"
              />
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Jobs Table */}
      <Card className="industrial-card" data-testid="jobs-table-card">
        <CardContent className="p-0">
          <div className="rounded-md border border-slate-800 overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="bg-slate-900 hover:bg-slate-900">
                  <TableHead className="text-slate-400 font-mono text-xs uppercase tracking-wider">
                    Job Name
                  </TableHead>
                  <TableHead className="text-slate-400 font-mono text-xs uppercase tracking-wider">
                    Presse
                  </TableHead>
                  <TableHead className="text-slate-400 font-mono text-xs uppercase tracking-wider">
                    Datum
                  </TableHead>
                  <TableHead className="text-slate-400 font-mono text-xs uppercase tracking-wider">
                    Status
                  </TableHead>
                  <TableHead className="text-slate-400 font-mono text-xs uppercase tracking-wider">
                    Kategorie
                  </TableHead>
                  <TableHead className="text-slate-400 font-mono text-xs uppercase tracking-wider text-right">
                    Impressionen
                  </TableHead>
                  <TableHead className="text-slate-400 font-mono text-xs uppercase tracking-wider text-center">
                    OneShot
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-12">
                      <div className="text-slate-400">Lade Jobs...</div>
                    </TableCell>
                  </TableRow>
                ) : jobs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-12">
                      <div className="text-slate-400">
                        <FileText className="w-12 h-12 mx-auto mb-4 opacity-50" />
                        <p>Keine Jobs gefunden</p>
                        <p className="text-sm mt-2">Passe die Filter an oder synchronisiere neue Jobs</p>
                      </div>
                    </TableCell>
                  </TableRow>
                ) : (
                  jobs.map((job, index) => (
                    <TableRow 
                      key={job.marker || index} 
                      className="job-row border-b border-slate-800/50"
                      data-testid={`job-row-${index}`}
                    >
                      <TableCell className="font-medium text-white max-w-[200px] truncate">
                        {job.job_name || "-"}
                      </TableCell>
                      <TableCell className="text-slate-300 font-mono">
                        {DEVICE_NAMES[job.press_id] || job.press_id}
                      </TableCell>
                      <TableCell className="text-slate-300 font-mono text-sm">
                        {formatDate(job.submit_time)}
                      </TableCell>
                      <TableCell>
                        <Badge 
                          variant="outline" 
                          className={STATUS_STYLES[job.status] || STATUS_STYLES.UNKNOWN}
                        >
                          {job.status}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge 
                          variant="outline" 
                          className={CATEGORY_STYLES[job.click_category] || CATEGORY_STYLES.Unknown}
                        >
                          {job.click_category}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right font-mono text-white">
                        {formatNumber(job.total_impressions)}
                      </TableCell>
                      <TableCell className="text-center">
                        {job.is_oneshot ? (
                          <span className="text-teal-400">✓</span>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between p-4 border-t border-slate-800">
              <div className="text-sm text-slate-400">
                Seite {page} von {totalPages}
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="border-slate-700 text-slate-300 hover:bg-slate-800"
                  data-testid="prev-page"
                >
                  <ChevronLeft className="w-4 h-4" />
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  disabled={page === totalPages}
                  className="border-slate-700 text-slate-300 hover:bg-slate-800"
                  data-testid="next-page"
                >
                  <ChevronRight className="w-4 h-4" />
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
