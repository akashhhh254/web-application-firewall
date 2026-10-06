import React, { useState } from "react";
import { Shield, LayoutDashboard, FileText, Sliders, Terminal, Settings, Menu, X } from "lucide-react";

export type PageTab = "dashboard" | "logs" | "rules" | "testing" | "settings" | "blocked";

interface NavbarProps {
  currentTab: PageTab;
  setCurrentTab: (tab: PageTab) => void;
  totalLogsCount: number;
  activeRulesCount: number;
  wafMode: "BLOCKING" | "MONITORING";
}

export const Navbar: React.FC<NavbarProps> = ({
  currentTab,
  setCurrentTab,
  totalLogsCount,
  activeRulesCount,
  wafMode
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems = [
    { id: "dashboard" as const, label: "Dashboard", icon: LayoutDashboard },
    { id: "logs" as const, label: "Security Logs", icon: FileText, badge: totalLogsCount },
    { id: "rules" as const, label: "Rules", icon: Sliders, badge: activeRulesCount },
    { id: "testing" as const, label: "Testing", icon: Terminal },
    { id: "settings" as const, label: "Settings", icon: Settings }
  ];

  const handleSelectTab = (tab: PageTab) => {
    setCurrentTab(tab);
    setMobileMenuOpen(false);
  };

  return (
    <header className="bg-[#0b192c] border-b border-[#1e3e62] sticky top-0 z-40 shadow-sm">
      <div className="max-w-6xl mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-14 sm:h-15 py-2">
          {/* Logo & Product Title */}
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-md bg-[#1e3e62] border border-[#2b5484] flex items-center justify-center text-white shadow-sm shrink-0">
              <Shield className="w-4 h-4 text-sky-300" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-sm sm:text-base text-white tracking-tight">
                  Web Application Firewall
                </span>
                <span className="hidden md:inline-block text-[10px] font-mono text-sky-200 bg-[#162f4e] px-1.5 py-0.5 rounded border border-[#1e3e62]">
                  L7 WAF
                </span>
              </div>
            </div>
          </div>

          {/* Desktop Navigation Links */}
          <nav className="hidden md:flex items-center gap-1 sm:gap-1.5">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleSelectTab(item.id)}
                  className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer ${
                    isActive
                      ? "bg-white text-[#0b192c] shadow-sm font-semibold"
                      : "text-slate-300 hover:text-white hover:bg-[#162f4e]"
                  }`}
                >
                  <Icon className={`w-3.5 h-3.5 ${isActive ? "text-[#0b192c]" : "text-sky-300"}`} />
                  <span>{item.label}</span>
                  {item.badge !== undefined && (
                    <span
                      className={`px-1.5 py-0.2 rounded text-[10px] font-mono ${
                        isActive
                          ? "bg-slate-100 text-[#0b192c] font-bold"
                          : "bg-[#162f4e] text-slate-300 border border-[#1e3e62]"
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Mobile Menu Hamburger Button */}
          <div className="flex items-center gap-2 md:hidden">
            <span className="text-[11px] font-mono text-sky-200 bg-[#162f4e] px-2 py-0.5 rounded border border-[#1e3e62] capitalize">
              {currentTab}
            </span>
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-1.5 rounded-md text-slate-300 hover:text-white hover:bg-[#162f4e] border border-[#1e3e62] transition"
              aria-label="Toggle navigation menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Dropdown Navigation Menu */}
        {mobileMenuOpen && (
          <nav className="md:hidden py-3 border-t border-[#1e3e62] space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleSelectTab(item.id)}
                  className={`w-full px-3 py-2 rounded-md text-xs font-medium transition-colors flex items-center justify-between cursor-pointer ${
                    isActive
                      ? "bg-white text-[#0b192c] font-semibold"
                      : "text-slate-200 hover:text-white hover:bg-[#162f4e]"
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`w-4 h-4 ${isActive ? "text-[#0b192c]" : "text-sky-300"}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge !== undefined && (
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                        isActive
                          ? "bg-slate-200 text-[#0b192c] font-bold"
                          : "bg-[#162f4e] text-slate-300 border border-[#1e3e62]"
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        )}
      </div>

      {/* Operational Status Sub-Banner */}
      <div className="bg-[#081322] border-t border-[#13273f] px-4 py-1.5 text-[11px] font-mono text-slate-300">
        <div className="max-w-6xl mx-auto flex flex-wrap items-center justify-between gap-1">
          <div className="flex items-center gap-2">
            <span
              className={`w-2 h-2 rounded-full shrink-0 ${
                wafMode === "BLOCKING" ? "bg-emerald-400" : "bg-amber-400"
              }`}
            />
            <span>
              Engine: <strong className="text-white">Active</strong> &bull; Mode:{" "}
              <strong className={wafMode === "BLOCKING" ? "text-emerald-400" : "text-amber-300"}>
                {wafMode}
              </strong>
            </span>
          </div>
          <span className="text-slate-400 text-[10px] sm:text-[11px]">
            Active Rules: <strong className="text-white">{activeRulesCount}</strong> / 14
          </span>
        </div>
      </div>
    </header>
  );
};
