import { useState, useEffect } from "react";
import "@/App.css";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Toaster } from "@/components/ui/sonner";
import axios from "axios";

// Pages
import Dashboard from "@/pages/Dashboard";
import LiveStatus from "@/pages/LiveStatus";
import ClicksReport from "@/pages/ClicksReport";
import JobsList from "@/pages/JobsList";
import DataImport from "@/pages/DataImport";
import AvailabilityAnalysis from "@/pages/AvailabilityAnalysis";
import Settings from "@/pages/Settings";
import Login from "@/pages/Login";
import ForgotPassword from "@/pages/ForgotPassword";

// Components
import Sidebar from "@/components/Sidebar";

// Configure axios to include auth token
axios.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Handle 401 responses
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem("token");
      localStorage.removeItem("user");
      window.location.href = "/";
    }
    return Promise.reject(error);
  }
);

function App() {
  const [selectedDevice, setSelectedDevice] = useState("all");
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for existing auth
    const token = localStorage.getItem("token");
    const storedUser = localStorage.getItem("user");
    
    if (token && storedUser) {
      try {
        setUser(JSON.parse(storedUser));
      } catch (e) {
        localStorage.removeItem("token");
        localStorage.removeItem("user");
      }
    }
    setLoading(false);
  }, []);

  const handleLogin = (userData) => {
    setUser(userData);
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    setUser(null);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-cyan-500">Laden...</div>
      </div>
    );
  }

  return (
    <div className="App min-h-screen bg-slate-950">
      <BrowserRouter>
        {!user ? (
          <Routes>
            <Route path="/forgot-password" element={<ForgotPassword />} />
            <Route path="/reset-password" element={<ForgotPassword />} />
            <Route path="*" element={<Login onLogin={handleLogin} />} />
          </Routes>
        ) : (
          <div className="flex min-h-screen">
            <Sidebar 
              selectedDevice={selectedDevice} 
              setSelectedDevice={setSelectedDevice}
              user={user}
              onLogout={handleLogout}
            />
            <main className="flex-1 ml-64 p-6 overflow-auto">
              <div className="max-w-[1600px] mx-auto">
                <Routes>
                  <Route 
                    path="/" 
                    element={<Dashboard selectedDevice={selectedDevice} />} 
                  />
                  <Route 
                    path="/live" 
                    element={<LiveStatus selectedDevice={selectedDevice} />} 
                  />
                  <Route 
                    path="/clicks" 
                    element={<ClicksReport selectedDevice={selectedDevice} />} 
                  />
                  <Route 
                    path="/jobs" 
                    element={<JobsList selectedDevice={selectedDevice} />} 
                  />
                  <Route 
                    path="/import" 
                    element={<DataImport />} 
                  />
                  <Route 
                    path="/availability" 
                    element={<AvailabilityAnalysis selectedDevice={selectedDevice} />} 
                  />
                  <Route 
                    path="/settings" 
                    element={<Settings />} 
                  />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
              </div>
            </main>
          </div>
        )}
      </BrowserRouter>
      <Toaster position="bottom-right" theme="dark" />
    </div>
  );
}

export default App;
