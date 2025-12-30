import { useState, useEffect } from "react";
import axios from "axios";
import { toast } from "sonner";
import { 
  Settings as SettingsIcon,
  Key,
  Save,
  TestTube,
  Trash2,
  Eye,
  EyeOff,
  CheckCircle,
  XCircle,
  Loader2,
  Plus,
  Printer,
  RefreshCw,
  Mail,
  Server
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import {
  Alert,
  AlertDescription,
} from "@/components/ui/alert";

const API_URL = `${process.env.REACT_APP_BACKEND_URL}/api`;

export default function Settings() {
  // Credentials state
  const [credentials, setCredentials] = useState({
    jobs_key: "",
    jobs_secret: "",
    historic_key: "",
    historic_secret: ""
  });
  const [credStatus, setCredStatus] = useState(null);
  const [showSecrets, setShowSecrets] = useState({
    jobs_secret: false,
    historic_secret: false,
    smtp_password: false
  });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResults, setTestResults] = useState(null);

  // Devices state
  const [devices, setDevices] = useState([]);
  const [newDevice, setNewDevice] = useState({ device_id: "", name: "", model: "" });

  // SMTP state
  const [smtpConfig, setSmtpConfig] = useState({
    host: "",
    port: 587,
    username: "",
    password: "",
    from_email: "",
    use_tls: true
  });
  const [smtpStatus, setSmtpStatus] = useState(null);
  const [savingSmtp, setSavingSmtp] = useState(false);
  const [testingSmtp, setTestingSmtp] = useState(false);
  const [smtpTestResult, setSmtpTestResult] = useState(null);
  const [addingDevice, setAddingDevice] = useState(false);

  useEffect(() => {
    fetchCredentialsStatus();
    fetchDevices();
    fetchSmtpStatus();
  }, []);

  const fetchCredentialsStatus = async () => {
    try {
      const res = await axios.get(`${API_URL}/settings/credentials/status`);
      setCredStatus(res.data);
    } catch (error) {
      console.error("Error fetching credentials status:", error);
    }
  };

  const fetchSmtpStatus = async () => {
    try {
      const res = await axios.get(`${API_URL}/settings/smtp/status`);
      setSmtpStatus(res.data);
      if (res.data.configured) {
        setSmtpConfig(prev => ({
          ...prev,
          host: res.data.host,
          port: res.data.port,
          from_email: res.data.from_email,
          use_tls: res.data.use_tls
        }));
      }
    } catch (error) {
      console.error("Error fetching SMTP status:", error);
    }
  };

  const fetchDevices = async () => {
    try {
      const res = await axios.get(`${API_URL}/settings/devices`);
      setDevices(res.data.device_list || []);
    } catch (error) {
      console.error("Error fetching devices:", error);
    }
  };

  const handleSaveCredentials = async () => {
    // Validate all fields are filled
    if (!credentials.jobs_key || !credentials.jobs_secret || 
        !credentials.historic_key || !credentials.historic_secret) {
      toast.error("Bitte alle Felder ausfüllen");
      return;
    }

    setSaving(true);
    try {
      await axios.post(`${API_URL}/settings/credentials`, credentials);
      toast.success("API-Credentials erfolgreich gespeichert!");
      fetchCredentialsStatus();
      // Clear form after saving
      setCredentials({
        jobs_key: "",
        jobs_secret: "",
        historic_key: "",
        historic_secret: ""
      });
      setTestResults(null);
    } catch (error) {
      toast.error("Fehler beim Speichern: " + (error.response?.data?.detail || error.message));
    } finally {
      setSaving(false);
    }
  };

  const handleTestCredentials = async () => {
    if (!credentials.jobs_key || !credentials.jobs_secret || 
        !credentials.historic_key || !credentials.historic_secret) {
      toast.error("Bitte alle Felder ausfüllen für den Test");
      return;
    }

    setTesting(true);
    setTestResults(null);
    try {
      const res = await axios.post(`${API_URL}/settings/credentials/test`, credentials);
      setTestResults(res.data);
      
      if (res.data.overall_success) {
        toast.success("Alle API-Verbindungen erfolgreich!");
      } else {
        toast.error("Einige API-Verbindungen fehlgeschlagen");
      }
    } catch (error) {
      toast.error("Testfehler: " + (error.response?.data?.detail || error.message));
      setTestResults({
        overall_success: false,
        error: error.message
      });
    } finally {
      setTesting(false);
    }
  };

  const handleDeleteCredentials = async () => {
    if (!confirm("Sind Sie sicher, dass Sie die gespeicherten Credentials löschen möchten?")) {
      return;
    }

    try {
      await axios.delete(`${API_URL}/settings/credentials`);
      toast.success("Credentials gelöscht");
      fetchCredentialsStatus();
      setTestResults(null);
    } catch (error) {
      toast.error("Fehler beim Löschen");
    }
  };

  // SMTP Functions
  const handleSaveSmtp = async () => {
    if (!smtpConfig.host || !smtpConfig.username || !smtpConfig.password || !smtpConfig.from_email) {
      toast.error("Bitte alle SMTP-Felder ausfüllen");
      return;
    }

    setSavingSmtp(true);
    try {
      await axios.post(`${API_URL}/settings/smtp`, smtpConfig);
      toast.success("SMTP-Konfiguration gespeichert!");
      fetchSmtpStatus();
      setSmtpConfig(prev => ({ ...prev, password: "" }));
      setSmtpTestResult(null);
    } catch (error) {
      toast.error("Fehler beim Speichern: " + (error.response?.data?.detail || error.message));
    } finally {
      setSavingSmtp(false);
    }
  };

  const handleTestSmtp = async () => {
    if (!smtpConfig.host || !smtpConfig.username || !smtpConfig.password || !smtpConfig.from_email) {
      toast.error("Bitte alle SMTP-Felder ausfüllen für den Test");
      return;
    }

    setTestingSmtp(true);
    setSmtpTestResult(null);
    try {
      const res = await axios.post(`${API_URL}/settings/smtp/test`, smtpConfig);
      setSmtpTestResult(res.data);
      
      if (res.data.status === "success") {
        toast.success("Test-E-Mail erfolgreich gesendet!");
      } else {
        toast.error("SMTP-Test fehlgeschlagen");
      }
    } catch (error) {
      toast.error("Testfehler: " + (error.response?.data?.detail || error.message));
      setSmtpTestResult({ status: "error", message: error.message });
    } finally {
      setTestingSmtp(false);
    }
  };

  const handleDeleteSmtp = async () => {
    if (!confirm("SMTP-Konfiguration wirklich löschen?")) return;

    try {
      await axios.delete(`${API_URL}/settings/smtp`);
      toast.success("SMTP-Konfiguration gelöscht");
      setSmtpStatus(null);
      setSmtpConfig({
        host: "",
        port: 587,
        username: "",
        password: "",
        from_email: "",
        use_tls: true
      });
    } catch (error) {
      toast.error("Fehler beim Löschen");
    }
  };

  const handleAddDevice = async () => {
    if (!newDevice.device_id || !newDevice.name || !newDevice.model) {
      toast.error("Bitte alle Gerätefelder ausfüllen");
      return;
    }

    setAddingDevice(true);
    try {
      await axios.post(`${API_URL}/settings/devices/add`, newDevice);
      toast.success("Gerät hinzugefügt!");
      fetchDevices();
      setNewDevice({ device_id: "", name: "", model: "" });
    } catch (error) {
      toast.error("Fehler beim Hinzufügen: " + (error.response?.data?.detail || error.message));
    } finally {
      setAddingDevice(false);
    }
  };

  const handleDeleteDevice = async (deviceId) => {
    if (!confirm(`Gerät ${deviceId} wirklich löschen?`)) {
      return;
    }

    try {
      await axios.delete(`${API_URL}/settings/devices/${deviceId}`);
      toast.success("Gerät gelöscht");
      fetchDevices();
    } catch (error) {
      toast.error("Fehler beim Löschen");
    }
  };

  const toggleSecretVisibility = (field) => {
    setShowSecrets(prev => ({ ...prev, [field]: !prev[field] }));
  };

  return (
    <div className="space-y-6 animate-slide-up" data-testid="settings-page">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-white flex items-center gap-3">
          <SettingsIcon className="w-8 h-8 text-slate-400" />
          Einstellungen
        </h1>
        <p className="text-slate-400 mt-1">
          API-Credentials und Gerätekonfiguration
        </p>
      </div>

      {/* API Credentials Section */}
      <Card className="industrial-card" data-testid="credentials-section">
        <CardHeader>
          <CardTitle className="text-lg font-semibold text-white flex items-center gap-2">
            <Key className="w-5 h-5 text-amber-500" />
            HP PrintOS API Credentials
          </CardTitle>
          <CardDescription className="text-slate-400">
            Geben Sie Ihre HP PrintOS API-Schlüssel ein. Diese werden verschlüsselt in der Datenbank gespeichert.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Current Status */}
          {credStatus && (
            <div className="bg-slate-800/50 rounded-lg p-4 mb-6">
              <div className="flex items-center justify-between">
                <span className="text-slate-300">Status:</span>
                <Badge variant={credStatus.configured ? "default" : "destructive"}>
                  {credStatus.configured ? "Konfiguriert" : "Nicht konfiguriert"}
                </Badge>
              </div>
              {credStatus.configured && (
                <div className="mt-3 space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Jobs API Key:</span>
                    <span className="text-slate-300 font-mono">{credStatus.jobs_api?.key_preview}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">PrintBeat API Key:</span>
                    <span className="text-slate-300 font-mono">{credStatus.historic_api?.key_preview}</span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Jobs API */}
          <div className="space-y-4">
            <h4 className="text-sm font-medium text-cyan-400 uppercase tracking-wide">
              Jobs API (für Druckaufträge)
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="jobs_key" className="text-slate-300">API Key</Label>
                <Input
                  id="jobs_key"
                  type="text"
                  placeholder="z.B. tmb329urp600328f7ppb4n8qpogr06kq"
                  value={credentials.jobs_key}
                  onChange={(e) => setCredentials(prev => ({ ...prev, jobs_key: e.target.value }))}
                  className="bg-slate-800 border-slate-700 text-white font-mono"
                  data-testid="jobs-key-input"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="jobs_secret" className="text-slate-300">API Secret</Label>
                <div className="relative">
                  <Input
                    id="jobs_secret"
                    type={showSecrets.jobs_secret ? "text" : "password"}
                    placeholder="••••••••••••••••"
                    value={credentials.jobs_secret}
                    onChange={(e) => setCredentials(prev => ({ ...prev, jobs_secret: e.target.value }))}
                    className="bg-slate-800 border-slate-700 text-white font-mono pr-10"
                    data-testid="jobs-secret-input"
                  />
                  <button
                    type="button"
                    onClick={() => toggleSecretVisibility("jobs_secret")}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                  >
                    {showSecrets.jobs_secret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* PrintBeat API */}
          <div className="space-y-4">
            <h4 className="text-sm font-medium text-teal-400 uppercase tracking-wide">
              PrintBeat API (für PrintVolume, Failures, etc.)
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="historic_key" className="text-slate-300">API Key</Label>
                <Input
                  id="historic_key"
                  type="text"
                  placeholder="z.B. i6r6p72q62il0194k8ssi53ron4pkror"
                  value={credentials.historic_key}
                  onChange={(e) => setCredentials(prev => ({ ...prev, historic_key: e.target.value }))}
                  className="bg-slate-800 border-slate-700 text-white font-mono"
                  data-testid="historic-key-input"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="historic_secret" className="text-slate-300">API Secret</Label>
                <div className="relative">
                  <Input
                    id="historic_secret"
                    type={showSecrets.historic_secret ? "text" : "password"}
                    placeholder="••••••••••••••••"
                    value={credentials.historic_secret}
                    onChange={(e) => setCredentials(prev => ({ ...prev, historic_secret: e.target.value }))}
                    className="bg-slate-800 border-slate-700 text-white font-mono pr-10"
                    data-testid="historic-secret-input"
                  />
                  <button
                    type="button"
                    onClick={() => toggleSecretVisibility("historic_secret")}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                  >
                    {showSecrets.historic_secret ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Test Results */}
          {testResults && (
            <Alert className={testResults.overall_success ? "border-emerald-500/50 bg-emerald-500/10" : "border-rose-500/50 bg-rose-500/10"}>
              <AlertDescription>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    {testResults.jobs_api?.success ? (
                      <CheckCircle className="w-4 h-4 text-emerald-500" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-500" />
                    )}
                    <span className={testResults.jobs_api?.success ? "text-emerald-400" : "text-rose-400"}>
                      Jobs API: {testResults.jobs_api?.success ? "OK" : testResults.jobs_api?.message}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    {testResults.historic_api?.success ? (
                      <CheckCircle className="w-4 h-4 text-emerald-500" />
                    ) : (
                      <XCircle className="w-4 h-4 text-rose-500" />
                    )}
                    <span className={testResults.historic_api?.success ? "text-emerald-400" : "text-rose-400"}>
                      PrintBeat API: {testResults.historic_api?.success ? "OK" : testResults.historic_api?.message}
                    </span>
                  </div>
                </div>
              </AlertDescription>
            </Alert>
          )}

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-3 pt-4 border-t border-slate-700">
            <Button
              onClick={handleTestCredentials}
              disabled={testing}
              variant="outline"
              className="border-slate-600 text-slate-300 hover:text-white"
              data-testid="test-credentials-btn"
            >
              {testing ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <TestTube className="w-4 h-4 mr-2" />
              )}
              Verbindung testen
            </Button>
            
            <Button
              onClick={handleSaveCredentials}
              disabled={saving}
              className="bg-teal-500 hover:bg-teal-400 text-slate-950"
              data-testid="save-credentials-btn"
            >
              {saving ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Save className="w-4 h-4 mr-2" />
              )}
              Speichern
            </Button>

            {credStatus?.configured && (
              <Button
                onClick={handleDeleteCredentials}
                variant="destructive"
                className="ml-auto"
                data-testid="delete-credentials-btn"
              >
                <Trash2 className="w-4 h-4 mr-2" />
                Löschen
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Device Configuration Section */}
      <Card className="industrial-card" data-testid="devices-section">
        <CardHeader>
          <CardTitle className="text-lg font-semibold text-white flex items-center gap-2">
            <Printer className="w-5 h-5 text-cyan-500" />
            Druckmaschinen Konfiguration
          </CardTitle>
          <CardDescription className="text-slate-400">
            Verwalten Sie die HP Indigo Druckmaschinen, die überwacht werden sollen.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Current Devices */}
          <div className="space-y-3">
            {devices.map((device) => (
              <div 
                key={device.id} 
                className="flex items-center justify-between bg-slate-800/50 rounded-lg p-4"
              >
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-full bg-cyan-500/20 flex items-center justify-center">
                    <Printer className="w-5 h-5 text-cyan-500" />
                  </div>
                  <div>
                    <div className="text-white font-medium">{device.name}</div>
                    <div className="text-slate-400 text-sm">{device.model}</div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-slate-500 font-mono text-sm">{device.id}</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleDeleteDevice(device.id)}
                    className="text-slate-400 hover:text-rose-400"
                  >
                    <Trash2 className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            ))}
          </div>

          {/* Add New Device */}
          <div className="border-t border-slate-700 pt-6">
            <h4 className="text-sm font-medium text-slate-300 mb-4">Neue Druckmaschine hinzufügen</h4>
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="space-y-2">
                <Label className="text-slate-400">Device ID</Label>
                <Input
                  placeholder="z.B. 47200413"
                  value={newDevice.device_id}
                  onChange={(e) => setNewDevice(prev => ({ ...prev, device_id: e.target.value }))}
                  className="bg-slate-800 border-slate-700 text-white font-mono"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-slate-400">Name</Label>
                <Input
                  placeholder="z.B. 7K"
                  value={newDevice.name}
                  onChange={(e) => setNewDevice(prev => ({ ...prev, name: e.target.value }))}
                  className="bg-slate-800 border-slate-700 text-white"
                />
              </div>
              <div className="space-y-2">
                <Label className="text-slate-400">Modell</Label>
                <Input
                  placeholder="z.B. HP Indigo 7K"
                  value={newDevice.model}
                  onChange={(e) => setNewDevice(prev => ({ ...prev, model: e.target.value }))}
                  className="bg-slate-800 border-slate-700 text-white"
                />
              </div>
              <div className="flex items-end">
                <Button
                  onClick={handleAddDevice}
                  disabled={addingDevice}
                  className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950"
                >
                  {addingDevice ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Plus className="w-4 h-4 mr-2" />
                  )}
                  Hinzufügen
                </Button>
              </div>
            </div>
          </div>

          {/* Reload Button */}
          <div className="flex justify-end pt-4">
            <Button
              onClick={fetchDevices}
              variant="outline"
              className="border-slate-600 text-slate-300"
            >
              <RefreshCw className="w-4 h-4 mr-2" />
              Aktualisieren
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* SMTP Configuration Section */}
      <Card className="industrial-card" data-testid="smtp-section">
        <CardHeader>
          <CardTitle className="text-lg font-semibold text-white flex items-center gap-2">
            <Mail className="w-5 h-5 text-purple-500" />
            E-Mail Server (SMTP)
          </CardTitle>
          <CardDescription className="text-slate-400">
            Konfigurieren Sie den SMTP-Server für "Passwort vergessen" E-Mails
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Current Status */}
          {smtpStatus && (
            <div className="bg-slate-800/50 rounded-lg p-4 mb-6">
              <div className="flex items-center justify-between">
                <span className="text-slate-300">Status:</span>
                <Badge variant={smtpStatus.configured ? "default" : "destructive"}>
                  {smtpStatus.configured ? "Konfiguriert" : "Nicht konfiguriert"}
                </Badge>
              </div>
              {smtpStatus.configured && (
                <div className="mt-3 space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Server:</span>
                    <span className="text-slate-300 font-mono">{smtpStatus.host}:{smtpStatus.port}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Absender:</span>
                    <span className="text-slate-300">{smtpStatus.from_email}</span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* SMTP Form */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="smtp_host" className="text-slate-300">SMTP Server</Label>
              <div className="relative">
                <Server className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                <Input
                  id="smtp_host"
                  type="text"
                  placeholder="smtp.example.com"
                  value={smtpConfig.host}
                  onChange={(e) => setSmtpConfig(prev => ({ ...prev, host: e.target.value }))}
                  className="bg-slate-800 border-slate-700 text-white pl-10"
                  data-testid="smtp-host-input"
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="smtp_port" className="text-slate-300">Port</Label>
              <Input
                id="smtp_port"
                type="number"
                placeholder="587"
                value={smtpConfig.port}
                onChange={(e) => setSmtpConfig(prev => ({ ...prev, port: parseInt(e.target.value) || 587 }))}
                className="bg-slate-800 border-slate-700 text-white"
                data-testid="smtp-port-input"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="smtp_username" className="text-slate-300">Benutzername</Label>
              <Input
                id="smtp_username"
                type="text"
                placeholder="user@example.com"
                value={smtpConfig.username}
                onChange={(e) => setSmtpConfig(prev => ({ ...prev, username: e.target.value }))}
                className="bg-slate-800 border-slate-700 text-white"
                data-testid="smtp-username-input"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="smtp_password" className="text-slate-300">Passwort</Label>
              <div className="relative">
                <Input
                  id="smtp_password"
                  type={showSecrets.smtp_password ? "text" : "password"}
                  placeholder="••••••••"
                  value={smtpConfig.password}
                  onChange={(e) => setSmtpConfig(prev => ({ ...prev, password: e.target.value }))}
                  className="bg-slate-800 border-slate-700 text-white pr-10"
                  data-testid="smtp-password-input"
                />
                <button
                  type="button"
                  onClick={() => setShowSecrets(prev => ({ ...prev, smtp_password: !prev.smtp_password }))}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                >
                  {showSecrets.smtp_password ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label htmlFor="smtp_from" className="text-slate-300">Absender E-Mail</Label>
              <Input
                id="smtp_from"
                type="email"
                placeholder="noreply@example.com"
                value={smtpConfig.from_email}
                onChange={(e) => setSmtpConfig(prev => ({ ...prev, from_email: e.target.value }))}
                className="bg-slate-800 border-slate-700 text-white"
                data-testid="smtp-from-input"
              />
            </div>
            <div className="space-y-2">
              <Label className="text-slate-300">Verschlüsselung</Label>
              <div className="flex items-center gap-3 h-10">
                <Switch
                  id="smtp_tls"
                  checked={smtpConfig.use_tls}
                  onCheckedChange={(checked) => setSmtpConfig(prev => ({ ...prev, use_tls: checked }))}
                />
                <Label htmlFor="smtp_tls" className="text-slate-400">
                  TLS/STARTTLS verwenden
                </Label>
              </div>
            </div>
          </div>

          {/* Test Result */}
          {smtpTestResult && (
            <Alert className={smtpTestResult.status === "success" ? "border-emerald-500/50 bg-emerald-500/10" : "border-rose-500/50 bg-rose-500/10"}>
              <AlertDescription>
                <div className="flex items-center gap-2">
                  {smtpTestResult.status === "success" ? (
                    <CheckCircle className="w-4 h-4 text-emerald-500" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-500" />
                  )}
                  <span className={smtpTestResult.status === "success" ? "text-emerald-400" : "text-rose-400"}>
                    {smtpTestResult.message}
                  </span>
                </div>
              </AlertDescription>
            </Alert>
          )}

          {/* Action Buttons */}
          <div className="flex flex-wrap gap-3 pt-4 border-t border-slate-700">
            <Button
              onClick={handleTestSmtp}
              disabled={testingSmtp}
              variant="outline"
              className="border-slate-600 text-slate-300 hover:text-white"
              data-testid="test-smtp-btn"
            >
              {testingSmtp ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <TestTube className="w-4 h-4 mr-2" />
              )}
              Test-E-Mail senden
            </Button>
            
            <Button
              onClick={handleSaveSmtp}
              disabled={savingSmtp}
              className="bg-purple-500 hover:bg-purple-400 text-white"
              data-testid="save-smtp-btn"
            >
              {savingSmtp ? (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              ) : (
                <Save className="w-4 h-4 mr-2" />
              )}
              Speichern
            </Button>

            {smtpStatus?.configured && (
              <Button
                onClick={handleDeleteSmtp}
                variant="destructive"
                className="ml-auto"
                data-testid="delete-smtp-btn"
              >
                <Trash2 className="w-4 h-4 mr-2" />
                Löschen
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
