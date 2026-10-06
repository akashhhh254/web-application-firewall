import React from "react";
import { ShieldAlert, ShieldCheck, AlertTriangle, ArrowRight, Activity, Terminal } from "lucide-react";
import { SecurityLog } from "../wafEngine";

interface DashboardViewProps {
  logs: SecurityLog[];
  onViewAllLogs: () => void;
  onGoToTesting: () => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  logs,
  onViewAllLogs,
  onGoToTesting
}) => {
  const totalRequests = logs.length;
  const allowedRequests = logs.filter((l) => l.action === "ALLOWED").length;
  const blockedRequests = logs.filter((l) => l.action === "BLOCKED").length;
  const securityAlerts = logs.filter(
    (l) => l.action === "BLOCKED" && (l.risk_level === "CRITICAL" || l.risk_level === "HIGH")
  ).length;

  const sqliCount = logs.filter(
    (l) => l.action === "BLOCKED" && l.attack_type === "SQL Injection"
  ).length;
  const xssCount = logs.filter(
    (l) => l.action === "BLOCKED" && l.attack_type === "Cross-Site Scripting"
  ).length;
  const ptCount = logs.filter(
    (l) => l.action === "BLOCKED" && l.attack_type === "Path Traversal"
  ).length;

  const recentLogs = logs.slice(0, 6);

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* Page Title & Status */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-[#0b192c] tracking-tight">Security Dashboard</h1>
          <p className="text-xs text-slate-500">
            Real-time HTTP traffic inspection and threat detection overview.
          </p>
        </div>
        <div>
          <button
            onClick={onGoToTesting}
            className="px-3.5 py-2 rounded-md text-xs font-semibold bg-[#0b192c] hover:bg-[#1e3e62] text-white shadow-sm transition flex items-center gap-1.5"
          >
            <Terminal className="w-3.5 h-3.5 text-sky-300" />
            <span>Simulate Request</span>
          </button>
        </div>
      </div>

      {/* 4 Core Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4">
        <div className="p-4 rounded-lg bg-white border border-slate-200/90 shadow-sm space-y-1">
          <span className="text-[11px] font-mono text-slate-500 uppercase font-semibold">Total Requests</span>
          <div className="text-2xl font-bold font-mono text-[#0b192c]">{totalRequests}</div>
          <p className="text-[11px] text-slate-400">Inspected HTTP transactions</p>
        </div>

        <div className="p-4 rounded-lg bg-white border border-slate-200/90 shadow-sm space-y-1">
          <span className="text-[11px] font-mono text-slate-500 uppercase font-semibold">Allowed Requests</span>
          <div className="text-2xl font-bold font-mono text-emerald-600">{allowedRequests}</div>
          <p className="text-[11px] text-slate-400">Clean traffic permitted</p>
        </div>

        <div className="p-4 rounded-lg bg-white border border-slate-200/90 shadow-sm space-y-1">
          <span className="text-[11px] font-mono text-slate-500 uppercase font-semibold">Blocked Requests</span>
          <div className="text-2xl font-bold font-mono text-rose-600">{blockedRequests}</div>
          <p className="text-[11px] text-slate-400">Mitigated threat payloads</p>
        </div>

        <div className="p-4 rounded-lg bg-white border border-slate-200/90 shadow-sm space-y-1">
          <span className="text-[11px] font-mono text-slate-500 uppercase font-semibold">Security Alerts</span>
          <div className="text-2xl font-bold font-mono text-amber-600">{securityAlerts}</div>
          <p className="text-[11px] text-slate-400">High / Critical severity</p>
        </div>
      </div>

      {/* Security Activity & Attack Overview */}
      <div className="p-5 rounded-lg bg-white border border-slate-200/90 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-[#1e3e62]" />
            <h2 className="text-xs font-bold text-[#0b192c] uppercase tracking-wider font-mono">
              Attack Overview
            </h2>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">
            {blockedRequests} total incidents
          </span>
        </div>

        {blockedRequests === 0 ? (
          <div className="py-6 text-center text-xs text-slate-400 font-mono">
            No malicious activity detected yet. Clean traffic is passing through normally.
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-1">
            {/* SQL Injection */}
            <div className="space-y-1.5 p-3 rounded-md bg-slate-50/70 border border-slate-100">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-700 font-medium">SQL Injection</span>
                <span className="text-rose-600 font-bold">{sqliCount}</span>
              </div>
              <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-rose-500 h-full rounded-full transition-all"
                  style={{
                    width: `${blockedRequests > 0 ? (sqliCount / blockedRequests) * 100 : 0}%`
                  }}
                />
              </div>
              <p className="text-[10px] text-slate-500">Tautology, UNION, comment syntax</p>
            </div>

            {/* Cross-Site Scripting */}
            <div className="space-y-1.5 p-3 rounded-md bg-slate-50/70 border border-slate-100">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-700 font-medium">Cross-Site Scripting</span>
                <span className="text-amber-600 font-bold">{xssCount}</span>
              </div>
              <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-amber-500 h-full rounded-full transition-all"
                  style={{
                    width: `${blockedRequests > 0 ? (xssCount / blockedRequests) * 100 : 0}%`
                  }}
                />
              </div>
              <p className="text-[10px] text-slate-500">Script tags, inline event handlers</p>
            </div>

            {/* Path Traversal */}
            <div className="space-y-1.5 p-3 rounded-md bg-slate-50/70 border border-slate-100">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-700 font-medium">Path Traversal</span>
                <span className="text-sky-600 font-bold">{ptCount}</span>
              </div>
              <div className="w-full bg-slate-200 h-2 rounded-full overflow-hidden">
                <div
                  className="bg-sky-500 h-full rounded-full transition-all"
                  style={{
                    width: `${blockedRequests > 0 ? (ptCount / blockedRequests) * 100 : 0}%`
                  }}
                />
              </div>
              <p className="text-[10px] text-slate-500">Directory climbing (../) &amp; OS files</p>
            </div>
          </div>
        )}
      </div>

      {/* Recent Security Events */}
      <div className="p-4 sm:p-5 rounded-lg bg-white border border-slate-200/90 shadow-sm space-y-4">
        <div className="flex items-center justify-between border-b border-slate-100 pb-3">
          <h2 className="text-xs font-bold text-[#0b192c] uppercase tracking-wider font-mono">
            Recent Security Events
          </h2>
          {logs.length > 0 && (
            <button
              onClick={onViewAllLogs}
              className="text-xs text-[#1e3e62] hover:text-[#0b192c] font-medium flex items-center gap-1 transition cursor-pointer"
            >
              <span>View all logs</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {logs.length === 0 ? (
          <div className="py-10 text-center space-y-2">
            <p className="text-xs text-slate-500 font-mono">No security events yet.</p>
            <button
              onClick={onGoToTesting}
              className="text-xs text-[#1e3e62] font-semibold hover:underline cursor-pointer"
            >
              Run test requests &rarr;
            </button>
          </div>
        ) : (
          <>
            {/* Mobile Cards View (Visible on small screens) */}
            <div className="block md:hidden space-y-2.5">
              {recentLogs.map((log) => (
                <div
                  key={log.id}
                  className={`p-3 rounded-lg border transition ${
                    log.action === "BLOCKED"
                      ? "bg-rose-50/20 border-rose-200/80"
                      : "bg-white border-slate-200"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono text-slate-500">{log.timestamp}</span>
                    {log.action === "BLOCKED" ? (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200">
                        BLOCKED
                      </span>
                    ) : (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                        ALLOWED
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 text-xs font-mono font-medium text-slate-800 break-all mb-1">
                    <span className="px-1.5 py-0.2 bg-slate-100 text-slate-600 rounded text-[10px] font-bold">
                      {log.method}
                    </span>
                    <span className="truncate">{log.path}</span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] font-mono pt-1 text-slate-500">
                    <span>IP: {log.ip_address}</span>
                    <span
                      className={`font-semibold ${
                        log.risk_level === "CRITICAL"
                          ? "text-rose-600"
                          : log.risk_level === "HIGH"
                          ? "text-amber-600"
                          : log.risk_level === "MEDIUM"
                          ? "text-sky-600"
                          : "text-slate-500"
                      }`}
                    >
                      {log.attack_type === "None" ? "Clean" : log.attack_type} ({log.risk_level})
                    </span>
                  </div>
                </div>
              ))}
            </div>

            {/* Desktop / Tablet Table View (Visible on md and up) */}
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full text-left text-xs font-mono min-w-[560px]">
                <thead>
                  <tr className="text-slate-500 border-b border-slate-200 bg-slate-50/80">
                    <th className="py-2.5 px-3 font-semibold">Timestamp</th>
                    <th className="py-2.5 px-3 font-semibold">IP Address</th>
                    <th className="py-2.5 px-3 font-semibold">Request</th>
                    <th className="py-2.5 px-3 font-semibold">Attack Type</th>
                    <th className="py-2.5 px-3 font-semibold">Severity</th>
                    <th className="py-2.5 px-3 font-semibold text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {recentLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-slate-50/80 transition">
                      <td className="py-2.5 px-3 text-slate-500 whitespace-nowrap">{log.timestamp}</td>
                      <td className="py-2.5 px-3 text-slate-700 font-medium">{log.ip_address}</td>
                      <td className="py-2.5 px-3 text-slate-800 max-w-[180px] truncate" title={log.path}>
                        <span className="text-slate-400 font-semibold mr-1.5">{log.method}</span>
                        {log.path}
                      </td>
                      <td className="py-2.5 px-3 text-slate-700">
                        {log.attack_type === "None" ? (
                          <span className="text-slate-400">Clean</span>
                        ) : (
                          <span className="font-semibold text-slate-800">{log.attack_type}</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`font-semibold ${
                            log.risk_level === "CRITICAL"
                              ? "text-rose-600"
                              : log.risk_level === "HIGH"
                              ? "text-amber-600"
                              : log.risk_level === "MEDIUM"
                              ? "text-sky-600"
                              : "text-slate-500"
                          }`}
                        >
                          {log.risk_level}
                        </span>
                      </td>
                      <td className="py-2.5 px-3 text-right">
                        {log.action === "BLOCKED" ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200">
                            BLOCKED
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                            ALLOWED
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
