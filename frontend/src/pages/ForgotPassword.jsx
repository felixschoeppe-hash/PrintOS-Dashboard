import { useState } from "react";
import axios from "axios";
import { toast } from "sonner";
import { 
  Mail, 
  Lock, 
  Eye, 
  EyeOff, 
  Loader2,
  ArrowLeft,
  CheckCircle,
  Key,
  Printer
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const API_URL = `${process.env.REACT_APP_BACKEND_URL}/api`;

export default function ForgotPassword() {
  const [step, setStep] = useState(1); // 1: email, 2: code, 3: new password, 4: success
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  
  const [formData, setFormData] = useState({
    email: "",
    code: "",
    token: "",
    newPassword: "",
    confirmPassword: ""
  });

  const handleRequestReset = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      await axios.post(`${API_URL}/auth/password-reset/request`, {
        email: formData.email,
        origin_url: window.location.origin  // Send current origin for reset link
      });
      toast.success("Reset-Code wurde gesendet (falls E-Mail existiert)");
      setStep(2);
    } catch (error) {
      toast.error("Fehler beim Anfordern des Reset-Codes");
    } finally {
      setLoading(false);
    }
  };

  const handleVerifyCode = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const res = await axios.post(`${API_URL}/auth/password-reset/verify`, null, {
        params: {
          email: formData.email,
          code: formData.code
        }
      });
      
      setFormData(prev => ({ ...prev, token: res.data.token }));
      setStep(3);
    } catch (error) {
      toast.error(error.response?.data?.detail || "Ungültiger Code");
    } finally {
      setLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();
    
    if (formData.newPassword !== formData.confirmPassword) {
      toast.error("Passwörter stimmen nicht überein");
      return;
    }

    setLoading(true);

    try {
      await axios.post(`${API_URL}/auth/password-reset/complete`, {
        token: formData.token,
        new_password: formData.newPassword
      });
      
      toast.success("Passwort erfolgreich geändert!");
      setStep(4);
    } catch (error) {
      toast.error(error.response?.data?.detail || "Fehler beim Ändern des Passworts");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo/Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-cyan-500/20 mb-4">
            <Printer className="w-8 h-8 text-cyan-500" />
          </div>
          <h1 className="text-3xl font-bold text-white">HP PrintOS Dashboard</h1>
        </div>

        <Card className="industrial-card border-slate-700">
          <CardHeader className="text-center">
            <CardTitle className="text-xl font-semibold text-white flex items-center justify-center gap-2">
              {step === 4 ? (
                <>
                  <CheckCircle className="w-5 h-5 text-teal-500" />
                  Passwort geändert
                </>
              ) : (
                <>
                  <Key className="w-5 h-5 text-amber-500" />
                  Passwort zurücksetzen
                </>
              )}
            </CardTitle>
            <CardDescription className="text-slate-400">
              {step === 1 && "Geben Sie Ihre E-Mail-Adresse ein"}
              {step === 2 && "Geben Sie den 6-stelligen Code aus der E-Mail ein"}
              {step === 3 && "Wählen Sie ein neues Passwort"}
              {step === 4 && "Ihr Passwort wurde erfolgreich geändert"}
            </CardDescription>
          </CardHeader>
          
          <CardContent>
            {/* Step 1: Email */}
            {step === 1 && (
              <form onSubmit={handleRequestReset} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email" className="text-slate-300">E-Mail-Adresse</Label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <Input
                      id="email"
                      type="email"
                      placeholder="email@example.com"
                      value={formData.email}
                      onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
                      className="bg-slate-800 border-slate-700 text-white pl-10"
                      required
                      data-testid="reset-email-input"
                    />
                  </div>
                </div>

                <Button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold"
                  data-testid="request-reset-btn"
                >
                  {loading ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Mail className="w-4 h-4 mr-2" />
                  )}
                  Reset-Code anfordern
                </Button>
              </form>
            )}

            {/* Step 2: Code Verification */}
            {step === 2 && (
              <form onSubmit={handleVerifyCode} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="code" className="text-slate-300">6-stelliger Code</Label>
                  <Input
                    id="code"
                    type="text"
                    placeholder="123456"
                    value={formData.code}
                    onChange={(e) => setFormData(prev => ({ ...prev, code: e.target.value.replace(/\D/g, '').slice(0, 6) }))}
                    className="bg-slate-800 border-slate-700 text-white text-center text-2xl tracking-widest font-mono"
                    maxLength={6}
                    required
                    data-testid="reset-code-input"
                  />
                  <p className="text-xs text-slate-500">
                    Der Code wurde an {formData.email} gesendet
                  </p>
                </div>

                <Button
                  type="submit"
                  disabled={loading || formData.code.length !== 6}
                  className="w-full bg-amber-500 hover:bg-amber-400 text-slate-950 font-semibold"
                  data-testid="verify-code-btn"
                >
                  {loading ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <CheckCircle className="w-4 h-4 mr-2" />
                  )}
                  Code bestätigen
                </Button>

                <button
                  type="button"
                  onClick={() => setStep(1)}
                  className="w-full text-slate-400 hover:text-white text-sm"
                >
                  Anderen E-Mail-Adresse verwenden
                </button>
              </form>
            )}

            {/* Step 3: New Password */}
            {step === 3 && (
              <form onSubmit={handleResetPassword} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="newPassword" className="text-slate-300">Neues Passwort</Label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <Input
                      id="newPassword"
                      type={showPassword ? "text" : "password"}
                      placeholder="••••••••"
                      value={formData.newPassword}
                      onChange={(e) => setFormData(prev => ({ ...prev, newPassword: e.target.value }))}
                      className="bg-slate-800 border-slate-700 text-white pl-10 pr-10"
                      required
                      minLength={6}
                      data-testid="new-password-input"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="confirmPassword" className="text-slate-300">Passwort bestätigen</Label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                    <Input
                      id="confirmPassword"
                      type={showPassword ? "text" : "password"}
                      placeholder="••••••••"
                      value={formData.confirmPassword}
                      onChange={(e) => setFormData(prev => ({ ...prev, confirmPassword: e.target.value }))}
                      className="bg-slate-800 border-slate-700 text-white pl-10"
                      required
                      minLength={6}
                      data-testid="confirm-password-input"
                    />
                  </div>
                </div>

                <Button
                  type="submit"
                  disabled={loading}
                  className="w-full bg-teal-500 hover:bg-teal-400 text-slate-950 font-semibold"
                  data-testid="save-password-btn"
                >
                  {loading ? (
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Lock className="w-4 h-4 mr-2" />
                  )}
                  Passwort ändern
                </Button>
              </form>
            )}

            {/* Step 4: Success */}
            {step === 4 && (
              <div className="text-center space-y-4">
                <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-teal-500/20 mx-auto">
                  <CheckCircle className="w-8 h-8 text-teal-500" />
                </div>
                <p className="text-slate-300">
                  Sie können sich jetzt mit Ihrem neuen Passwort anmelden.
                </p>
                <a href="/" className="block">
                  <Button className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold">
                    Zur Anmeldung
                  </Button>
                </a>
              </div>
            )}

            {/* Back to Login */}
            {step !== 4 && (
              <div className="mt-6 text-center">
                <a 
                  href="/" 
                  className="text-slate-400 hover:text-white text-sm inline-flex items-center gap-1"
                >
                  <ArrowLeft className="w-4 h-4" />
                  Zurück zur Anmeldung
                </a>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
