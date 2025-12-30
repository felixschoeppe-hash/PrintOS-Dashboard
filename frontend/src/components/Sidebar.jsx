import { NavLink } from "react-router-dom";
import { 
  LayoutDashboard, 
  Receipt, 
  FileText, 
  Printer,
  Upload,
  Radio,
  Activity,
  Settings,
  LogOut,
  User
} from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import { useDevices } from "@/hooks/useDevices";

const navItems = [
  { path: "/", label: "Dashboard", icon: LayoutDashboard },
  { path: "/live", label: "Live Status", icon: Radio },
  { path: "/clicks", label: "Clicks Report", icon: Receipt },
  { path: "/availability", label: "Availability", icon: Activity },
  { path: "/jobs", label: "Jobs Liste", icon: FileText },
  { path: "/import", label: "Daten Import", icon: Upload },
  { path: "/settings", label: "Einstellungen", icon: Settings },
];

export default function Sidebar({ selectedDevice, setSelectedDevice, user, onLogout }) {
  const { devices } = useDevices();

  // Kombiniere "Alle Pressen" mit API-Geräten
  const allDevices = [
  { id: "all", name: "Alle Pressen", model: "Aggregiert" },  // ← "id" statt "device_id"
    ...devices
  ];

  return (
    <aside 
      className="fixed left-0 top-0 h-screen w-64 bg-slate-900 border-r border-slate-800 flex flex-col z-50"
      data-testid="sidebar"
    >
      {/* Logo */}
      <div className="p-6 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded bg-cyan-500 flex items-center justify-center">
            <Printer className="w-6 h-6 text-slate-950" />
          </div>
          <div>
            <h1 className="font-bold text-lg text-white font-sans">PrintOS</h1>
            <p className="text-xs text-slate-400">Dashboard</p>
          </div>
        </div>
      </div>

      {/* User Info */}
      {user && (
        <div className="px-4 py-3 border-b border-slate-800 bg-slate-800/50">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-full bg-cyan-500/20 flex items-center justify-center">
              <User className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-white truncate">{user.username}</p>
              <p className="text-xs text-slate-400 truncate">{user.email}</p>
            </div>
          </div>
        </div>
      )}

      {/* Device Selector */}
<div className="p-4 border-b border-slate-800">
  <label className="text-xs text-slate-400 uppercase tracking-wider mb-2 block">
    Gerät auswählen
  </label>
  <Select 
    value={selectedDevice} 
    onValueChange={setSelectedDevice}
  >
    <SelectTrigger 
      className="w-full bg-slate-800 border-slate-700 text-white"
      data-testid="device-selector"
    >
      <SelectValue />
    </SelectTrigger>
    <SelectContent className="bg-slate-800 border-slate-700">
      {allDevices.map((device) => (
        <SelectItem
          key={device.id}
          value={device.id}
          className="text-white hover:bg-slate-700 focus:bg-slate-700"
        >
          {device.name}
        </SelectItem>
      ))}
    </SelectContent>
  </Select>
</div>

      {/* Navigation */}
      <nav className="flex-1 p-4 overflow-auto">
        <ul className="space-y-2">
          {navItems.map((item) => (
            <li key={item.path}>
              <NavLink
                to={item.path}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-4 py-3 rounded-sm transition-all duration-200 ${
                    isActive
                      ? "bg-cyan-500/10 text-cyan-400 border-l-2 border-cyan-500"
                      : "text-slate-400 hover:text-white hover:bg-slate-800"
                  }`
                }
                data-testid={`nav-${item.label.toLowerCase().replace(' ', '-')}`}
              >
                <item.icon className="w-5 h-5" />
                <span className="font-medium">{item.label}</span>
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      {/* Footer with Logout */}
      <div className="p-4 border-t border-slate-800 space-y-3">
        <Button
          variant="ghost"
          className="w-full justify-start text-slate-400 hover:text-rose-400 hover:bg-rose-500/10"
          onClick={onLogout}
          data-testid="logout-btn"
        >
          <LogOut className="w-4 h-4 mr-3" />
          Abmelden
        </Button>
        <div className="text-xs text-slate-500">
          <p>HP PrintOS Integration</p>
          <p className="text-cyan-500 font-mono">v1.0.0</p>
        </div>
      </div>
    </aside>
  );
}
