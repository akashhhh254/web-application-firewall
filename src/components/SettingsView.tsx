import React from "react";
import { Settings, Trash2, RotateCcw, Download } from "lucide-react";
import { SecurityRule, SecurityLog } from "../wafEngine";

interface SettingsViewProps {
  wafMode: "BLOCKING" | "MONITORING";
  setWafMode: (mode: "BLOCKING" | "MONITORING") => void;
  rules: SecurityRule[];
  logs: SecurityLog[];
  onResetRules: () => void;
  onClearLogs: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  wafMode,
  setWafMode,
  rules,
  logs,
  onResetRules,
  onClearLogs
}) => {
  const exportLogsAsJson = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(logs, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `waf_security_logs_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      <div>
        <h1 className="text-xl font-bold text-[#0b192c] tracking-tight">System Settings</h1>
        <p className="text-xs text-slate-500">
          Operational configurations and maintenance controls for the local firewall.
        </p>
      </div>

      {/* Operational Mode Card */}
      <div className="p-5 rounded-lg bg-white border border-slate-200 shadow-sm space-y-4">
        <div>
          <h2 className="text-xs font-bold text-[#0b192c] uppercase font-mono tracking-wider">
            WAF Operational Mode
          </h2>
          <p className="text-xs text-slate-500 mt-1">
            Choose how the firewall engine reacts upon matching a threat signature.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1">
          {/* Blocking Mode */}
          <button
            type="button"
            onClick={() => setWafMode("BLOCKING")}
            className={`p-4 rounded-lg border text-left transition cursor-pointer ${
              wafMode === "BLOCKING"
                ? "bg-slate-50 border-[#1e3e62] text-[#0b192c] shadow-xs"
                : "bg-white border-slate-200 text-slate-600 hover:bg-slate-50"
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-bold text-[#0b192c] font-sans">Blocking Mode (Active Defense)</span>
              {wafMode === "BLOCKING" && (
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 ring-2 ring-emerald-200"></span>
              )}
            </div>
            <p className="text-[11px] text-slate-500 leading-relaxed font-sans">
              Intercepts malicious requests, halts processing immediately, and returns an HTTP 403 Forbidden page.
            </p>
          </button>

          {/* Monitoring Mode */}
          <button
            type="button"
            onClick={() => setWafMode("MONITORING")}
            className={`p-4 rounded-lg border text-left transition cursor-pointer ${
              wafMode === "MONITORING"
                ? "bg-slate-50 border-amber-500 text-[#0b192c] shadow-xs"
                : "bg-white border-slate-200 text-slate-600 hover:bg-slate-50"
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-bold text-[#0b192c] font-sans">Monitoring Mode (Passive Log)</span>
              {wafMode === "MONITORING" && (
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500 ring-2 ring-amber-200"></span>
              )}
            </div>
            <p className="text-[11px] text-slate-500 leading-relaxed font-sans">
              Logs all triggered signatures to the audit database, but permits requests through without blocking.
            </p>
          </button>
        </div>
      </div>

      {/* Bypass Whitelist */}
      <div className="p-5 rounded-lg bg-white border border-slate-200 shadow-sm space-y-3">
        <h2 className="text-xs font-bold text-[#0b192c] uppercase font-mono tracking-wider">
          Asset Bypass Whitelist
        </h2>
        <p className="text-xs text-slate-500">
          Static asset directories that bypass inspection to avoid inspection latency.
        </p>

        <div className="flex flex-wrap gap-2 pt-1">
          <span className="px-2.5 py-1 rounded bg-slate-50 border border-slate-200 text-xs font-mono text-slate-700 font-semibold">
            /static/
          </span>
          <span className="px-2.5 py-1 rounded bg-slate-50 border border-slate-200 text-xs font-mono text-slate-700 font-semibold">
            /favicon.ico
          </span>
        </div>
      </div>

      {/* Environment & Metadata */}
      <div className="p-5 rounded-lg bg-white border border-slate-200 shadow-sm space-y-3">
        <h2 className="text-xs font-bold text-[#0b192c] uppercase font-mono tracking-wider">
          Environment &amp; Specifications
        </h2>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono pt-1">
          <div className="p-3 rounded-md bg-slate-50 border border-slate-200 space-y-0.5">
            <span className="text-slate-500 text-[11px] block font-sans font-medium">Database Location</span>
            <span className="text-slate-900 font-semibold">database/waf_security.db (SQLite)</span>
          </div>

          <div className="p-3 rounded-md bg-slate-50 border border-slate-200 space-y-0.5">
            <span className="text-slate-500 text-[11px] block font-sans font-medium">Audit Log File</span>
            <span className="text-slate-900 font-semibold">waf_audit.log (Append-only)</span>
          </div>

          <div className="p-3 rounded-md bg-slate-50 border border-slate-200 space-y-0.5">
            <span className="text-slate-500 text-[11px] block font-sans font-medium">Threat Signatures</span>
            <span className="text-slate-900 font-semibold">14 Active Signatures (SQLi, XSS, Path Traversal)</span>
          </div>

          <div className="p-3 rounded-md bg-slate-50 border border-slate-200 space-y-0.5">
            <span className="text-slate-500 text-[11px] block font-sans font-medium">Inspection Point</span>
            <span className="text-slate-900 font-semibold">Layer 7 (HTTP URI, Query, Body, Headers)</span>
          </div>
        </div>
      </div>

      {/* Maintenance Controls */}
      <div className="p-5 rounded-lg bg-white border border-slate-200 shadow-sm space-y-4">
        <h2 className="text-xs font-bold text-[#0b192c] uppercase font-mono tracking-wider">
          Data Maintenance
        </h2>

        <div className="flex flex-wrap items-center gap-2.5 pt-1">
          <button
            onClick={exportLogsAsJson}
            disabled={logs.length === 0}
            className="px-3.5 py-1.5 rounded-md text-xs font-sans font-medium bg-[#0b192c] hover:bg-[#1e3e62] disabled:opacity-40 text-white shadow-xs transition flex items-center gap-1.5 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5 text-sky-300" />
            <span>Export Logs (JSON)</span>
          </button>

          <button
            onClick={() => {
              if (window.confirm("Are you sure you want to clear all security logs?")) {
                onClearLogs();
              }
            }}
            disabled={logs.length === 0}
            className="px-3.5 py-1.5 rounded-md text-xs font-sans font-medium bg-white hover:bg-rose-50 text-slate-700 hover:text-rose-700 border border-slate-200 hover:border-rose-200 disabled:opacity-40 shadow-xs transition flex items-center gap-1.5 cursor-pointer"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear Log History</span>
          </button>

          <button
            onClick={() => {
              if (window.confirm("Reset all detection rules back to system default signatures?")) {
                onResetRules();
              }
            }}
            className="px-3.5 py-1.5 rounded-md text-xs font-sans font-medium bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 shadow-xs transition flex items-center gap-1.5 cursor-pointer"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Rules to Defaults</span>
          </button>
        </div>
      </div>
    </div>
  );
};
