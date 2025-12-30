import { useState, useEffect } from "react";
import axios from "axios";
import { toast } from "sonner";
import { 
  LogIn, 
  User, 
  Lock, 
  Eye, 
  EyeOff, 
  Loader2,
  UserPlus,
  Printer
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const API_URL = 'https://printos-backend.onrender.com/api';

export default function Login({ onLogin }) {
  const [mode, setMode] = useState("login"); // "login" or "register"
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [requiresSetup, setRequiresSetup] = useState(false);
  
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: ""
  });

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    try {
      const res = await axios.get(`${API_URL}/auth/check`);
      if (res.data.requires_setup) {
        setRequiresSetup(true);
        setMode("register");
      }
    } catch (error) {
      console.log("Auth check failed");
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      if (mode === "register") {
        // Register new user
        await axios.post(`${API_URL}/auth/register`, {
          username: formData.username,
          email: formData.email,
          password: formData.password
        });
        toast.success("Registrierung erfolgreich! Bitte melden Sie sich an.");
        setMode("login");
        setRequiresSetup(false);
      } else {
        // Login
        const res = await axios.post(`${API_URL}/auth/login`, {
          username: formData.username,
          password: formData.password
        });
        
        // Store token and user info
        localStorage.setItem("token", res.data.access_token);
        localStorage.setItem("user", JSON.stringify(res.data.user));
        
        toast.success(`Willkommen, ${res.data.user.username}!`);
        onLogin(res.data.user);
      }
    } catch (error) {
      toast.error(error.response?.data?.detail || "Anmeldung fehlgeschlagen");
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
          <p className="text-slate-400 mt-2">Indigo Performance & Billing</p>
        </div>

        <Card className="industrial-card border-slate-700">
          <CardHeader className="text-center">
            <CardTitle className="text-xl font-semibold text-white flex items-center justify-center gap-2">
              {mode === "login" ? (
                <>
                  <LogIn className="w-5 h-5 text-cyan-500" />
                  Anmelden
                </>
              ) : (
                <>
                  <UserPlus className="w-5 h-5 text-teal-500" />
                  {requiresSetup ? "Administrator erstellen" : "Registrieren"}
                </>
              )}
            </CardTitle>
            {requiresSetup && mode === "register" && (
              <CardDescription className="text-amber-400">
                Erstellen Sie den ersten Administrator-Account
              </CardDescription>
            )}
          </CardHeader>
          
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Username */}
              <div className="space-y-2">
                <Label htmlFor="username" className="text-slate-300">Benutzername</Label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                  <Input
                    id="username"
                    type="text"
                    placeholder="Benutzername"
                    value={formData.username}
                    onChange={(e) => setFormData(prev => ({ ...prev, username: e.target.value }))}
                    className="bg-slate-800 border-slate-700 text-white pl-10"
                    required
                    data-testid="username-input"
                  />
                </div>
              </div>

              {/* Email (only for registration) */}
              {mode === "register" && (
                <div className="space-y-2">
                  <Label htmlFor="email" className="text-slate-300">E-Mail</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="email@example.com"
                    value={formData.email}
                    onChange={(e) => setFormData(prev => ({ ...prev, email: e.target.value }))}
                    className="bg-slate-800 border-slate-700 text-white"
                    required
                    data-testid="email-input"
                  />
                </div>
              )}

              {/* Password */}
              <div className="space-y-2">
                <Label htmlFor="password" className="text-slate-300">Passwort</Label>
                <div className="relative">
                  <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                  <Input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="••••••••"
                    value={formData.password}
                    onChange={(e) => setFormData(prev => ({ ...prev, password: e.target.value }))}
                    className="bg-slate-800 border-slate-700 text-white pl-10 pr-10"
                    required
                    minLength={6}
                    data-testid="password-input"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                {mode === "register" && (
                  <p className="text-xs text-slate-500">Mindestens 6 Zeichen</p>
                )}
              </div>

              {/* Submit Button */}
              <Button
                type="submit"
                disabled={loading}
                className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold"
                data-testid="submit-btn"
              >
                {loading ? (
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                ) : mode === "login" ? (
                  <LogIn className="w-4 h-4 mr-2" />
                ) : (
                  <UserPlus className="w-4 h-4 mr-2" />
                )}
                {mode === "login" ? "Anmelden" : "Registrieren"}
              </Button>
            </form>

            {/* Mode Toggle */}
            {!requiresSetup && (
              <div className="mt-6 text-center">
                {mode === "login" ? (
                  <>
                    <p className="text-slate-400 text-sm">
                      Noch kein Konto?{" "}
                      <button
                        onClick={() => setMode("register")}
                        className="text-cyan-400 hover:underline"
                      >
                        Registrieren
                      </button>
                    </p>
                    <p className="text-slate-500 text-sm mt-2">
                      <a href="/forgot-password" className="text-slate-400 hover:text-white hover:underline">
                        Passwort vergessen?
                      </a>
                    </p>
                  </>
                ) : (
                  <p className="text-slate-400 text-sm">
                    Bereits registriert?{" "}
                    <button
                      onClick={() => setMode("login")}
                      className="text-cyan-400 hover:underline"
                    >
                      Anmelden
                    </button>
                  </p>
                )}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Footer */}
        <p className="text-center text-slate-600 text-sm mt-6">
          HP PrintOS Dashboard © 2025
        </p>
      </div>
    </div>
  );
}
