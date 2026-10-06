import React, { useState } from "react";
import { Search, Trash2 } from "lucide-react";
import { SecurityLog } from "../wafEngine";

interface LogsViewProps {
  logs: SecurityLog[];
  onClearLogs: () => void;
}

export const LogsView: React.FC<LogsViewProps> = ({ logs, onClearLogs }) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [attackFilter, setAttackFilter] = useState("ALL");
  const [actionFilter, setActionFilter] = useState("ALL");
  const [expandedLogId, setExpandedLogId] = useState<number | null>(null);

  const filteredLogs = logs.filter((log) => {
    if (attackFilter !== "ALL") {
      if (attackFilter === "None" && log.attack_type !== "None") return false;
      if (attackFilter !== "None" && log.attack_type !== attackFilter) return false;
    }
    if (actionFilter !== "ALL" && log.action !== actionFilter) return false;
    if (searchTerm.trim()) {
      const q = searchTerm.toLowerCase();
      const matchPath = log.path.toLowerCase().includes(q);
      const matchIp = log.ip_address.toLowerCase().includes(q);
      const matchReason = log.reason.toLowerCase().includes(q);
      const matchRule = (log.matched_rule_id || "").toLowerCase().includes(q);
      if (!matchPath && !matchIp && !matchReason && !matchRule) return false;
    }
    return true;
  });

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 py-6 space-y-5">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-[#0b192c] tracking-tight">Security Audit Logs</h1>
          <p className="text-xs text-slate-500">
            Chronological inspection records for inbound HTTP transactions.
          </p>
        </div>
        {logs.length > 0 && (
          <button
            onClick={() => {
              if (window.confirm("Are you sure you want to clear all security logs?")) {
                onClearLogs();
              }
            }}
            className="px-3 py-1.5 rounded-md text-xs font-medium text-slate-600 hover:text-rose-600 bg-white hover:bg-rose-50 border border-slate-200 hover:border-rose-200 transition flex items-center gap-1.5 shadow-sm self-start sm:self-auto"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Clear Logs</span>
          </button>
        )}
      </div>

      {/* Filter Toolbar */}
      <div className="p-3.5 rounded-lg bg-white border border-slate-200 shadow-sm space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex flex-col sm:flex-row sm:items-center gap-2.5 w-full md:w-auto">
            {/* Search Box */}
            <div className="relative w-full sm:w-64">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder="Search path, IP, or rule..."
                className="w-full bg-slate-50 border border-slate-200 rounded-md pl-8 pr-3 py-1.5 text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:border-[#1e3e62] focus:bg-white font-mono transition"
              />
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              {/* Attack Type Filter */}
              <select
                value={attackFilter}
                onChange={(e) => setAttackFilter(e.target.value)}
                className="flex-1 sm:flex-initial bg-slate-50 border border-slate-200 rounded-md px-2.5 py-1.5 text-xs text-slate-700 font-mono focus:outline-none focus:border-[#1e3e62] focus:bg-white"
              >
                <option value="ALL">All Attack Types</option>
                <option value="SQL Injection">SQL Injection</option>
                <option value="Cross-Site Scripting">Cross-Site Scripting</option>
                <option value="Path Traversal">Path Traversal</option>
                <option value="None">Clean Traffic Only</option>
              </select>

              {/* Action Filter */}
              <select
                value={actionFilter}
                onChange={(e) => setActionFilter(e.target.value)}
                className="flex-1 sm:flex-initial bg-slate-50 border border-slate-200 rounded-md px-2.5 py-1.5 text-xs text-slate-700 font-mono focus:outline-none focus:border-[#1e3e62] focus:bg-white"
              >
                <option value="ALL">All Actions</option>
                <option value="BLOCKED">Blocked Only</option>
                <option value="ALLOWED">Allowed Only</option>
              </select>
            </div>
          </div>

          <div className="text-[11px] text-slate-500 font-mono self-end md:self-auto">
            Showing <strong>{filteredLogs.length}</strong> of {logs.length} entries
          </div>
        </div>

        {/* Quick Filter Pills for fast tap on mobile/desktop */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-slate-100 text-[11px] font-mono">
          <span className="text-slate-400 mr-1 font-sans text-xs">Quick:</span>
          <button
            type="button"
            onClick={() => { setAttackFilter("ALL"); setActionFilter("ALL"); setSearchTerm(""); }}
            className={`px-2 py-0.5 rounded cursor-pointer transition ${
              attackFilter === "ALL" && actionFilter === "ALL" && !searchTerm
                ? "bg-[#0b192c] text-white font-bold"
                : "bg-slate-100 text-slate-600 hover:bg-slate-200"
            }`}
          >
            All
          </button>
          <button
            type="button"
            onClick={() => { setActionFilter("BLOCKED"); setAttackFilter("ALL"); }}
            className={`px-2 py-0.5 rounded cursor-pointer transition ${
              actionFilter === "BLOCKED"
                ? "bg-rose-600 text-white font-bold"
                : "bg-rose-50 text-rose-700 border border-rose-200 hover:bg-rose-100"
            }`}
          >
            Blocked Only
          </button>
          <button
            type="button"
            onClick={() => { setActionFilter("ALLOWED"); setAttackFilter("ALL"); }}
            className={`px-2 py-0.5 rounded cursor-pointer transition ${
              actionFilter === "ALLOWED"
                ? "bg-emerald-600 text-white font-bold"
                : "bg-emerald-50 text-emerald-700 border border-emerald-200 hover:bg-emerald-100"
            }`}
          >
            Allowed Only
          </button>
          <button
            type="button"
            onClick={() => { setAttackFilter("SQL Injection"); }}
            className={`px-2 py-0.5 rounded cursor-pointer transition ${
              attackFilter === "SQL Injection"
                ? "bg-[#1e3e62] text-white font-bold"
                : "bg-slate-100 text-slate-700 hover:bg-slate-200"
            }`}
          >
            SQLi
          </button>
          <button
            type="button"
            onClick={() => { setAttackFilter("Cross-Site Scripting"); }}
            className={`px-2 py-0.5 rounded cursor-pointer transition ${
              attackFilter === "Cross-Site Scripting"
                ? "bg-[#1e3e62] text-white font-bold"
                : "bg-slate-100 text-slate-700 hover:bg-slate-200"
            }`}
          >
            XSS
          </button>
          <button
            type="button"
            onClick={() => { setAttackFilter("Path Traversal"); }}
            className={`px-2 py-0.5 rounded cursor-pointer transition ${
              attackFilter === "Path Traversal"
                ? "bg-[#1e3e62] text-white font-bold"
                : "bg-slate-100 text-slate-700 hover:bg-slate-200"
            }`}
          >
            Path Traversal
          </button>
        </div>
      </div>

      {/* Logs Table / Mobile List */}
      <div className="rounded-lg bg-white border border-slate-200 shadow-sm overflow-hidden">
        {filteredLogs.length === 0 ? (
          <div className="py-12 text-center text-xs text-slate-400 font-mono">
            {logs.length === 0
              ? "No security events recorded yet."
              : "No logs match the current search or filter criteria."}
          </div>
        ) : (
          <>
            {/* Mobile View: Clean Expandable Cards */}
            <div className="block md:hidden divide-y divide-slate-100">
              {filteredLogs.map((log) => {
                const isExpanded = expandedLogId === log.id;
                return (
                  <div
                    key={log.id}
                    className={`p-3.5 transition cursor-pointer ${
                      log.action === "BLOCKED" ? "bg-rose-50/20" : "bg-white"
                    }`}
                    onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
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
                      <span className="px-1.5 py-0.2 bg-slate-100 text-slate-700 rounded text-[10px] font-bold">
                        {log.method}
                      </span>
                      <span>{log.path}</span>
                    </div>
                    <div className="flex items-center justify-between text-[11px] font-mono pt-1 text-slate-600">
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
                        {log.attack_type === "None" ? "Clean" : log.attack_type}
                      </span>
                    </div>
                    <div className="flex items-center justify-end text-[10px] font-medium text-slate-400 pt-1.5">
                      <span>{isExpanded ? "Hide Details \u2191" : "Tap for Details \u2193"}</span>
                    </div>

                    {isExpanded && (
                      <div className="mt-2.5 pt-2.5 border-t border-slate-200 space-y-2 text-[11px] font-mono text-slate-700">
                        <div>
                          <span className="text-slate-500 block font-sans font-medium text-[10px]">Reason:</span>
                          <div className="text-slate-800 bg-white p-2 rounded border border-slate-200 text-xs">
                            {log.reason}
                          </div>
                        </div>
                        <div>
                          <span className="text-slate-500 block font-sans font-medium text-[10px]">Rule:</span>
                          <div className="text-[#0b192c] font-semibold bg-white p-2 rounded border border-slate-200 text-xs">
                            {log.matched_rule_id
                              ? `[${log.matched_rule_id}] ${log.matched_rule_name || ""}`
                              : "None (Clean)"}
                          </div>
                        </div>
                        {log.offending_token && (
                          <div>
                            <span className="text-slate-500 block font-sans font-medium text-[10px]">Flagged Token:</span>
                            <code className="text-rose-700 bg-rose-50 px-2 py-1 rounded border border-rose-200 block break-all font-bold">
                              {log.offending_token}
                            </code>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            {/* Desktop View: Full Data Table */}
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full text-left text-xs font-mono min-w-[650px]">
                <thead>
                  <tr className="text-slate-500 border-b border-slate-200 bg-slate-50">
                    <th className="py-2.5 px-3 font-semibold">Timestamp</th>
                    <th className="py-2.5 px-3 font-semibold">IP Address</th>
                    <th className="py-2.5 px-3 font-semibold">Method</th>
                    <th className="py-2.5 px-3 font-semibold">Request / Path</th>
                    <th className="py-2.5 px-3 font-semibold">Attack Type</th>
                    <th className="py-2.5 px-3 font-semibold">Severity</th>
                    <th className="py-2.5 px-3 font-semibold">Action</th>
                    <th className="py-2.5 px-3 font-semibold text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {filteredLogs.map((log) => {
                    const isExpanded = expandedLogId === log.id;
                    return (
                      <React.Fragment key={log.id}>
                        <tr
                          className={`hover:bg-slate-50/80 transition cursor-pointer ${
                            log.action === "BLOCKED" ? "bg-rose-50/30" : ""
                          }`}
                          onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                        >
                          <td className="py-2.5 px-3 text-slate-500 whitespace-nowrap">
                            {log.timestamp}
                          </td>
                          <td className="py-2.5 px-3 text-slate-700 font-medium">{log.ip_address}</td>
                          <td className="py-2.5 px-3">
                            <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 border border-slate-200 text-[10px] font-bold">
                              {log.method}
                            </span>
                          </td>
                          <td
                            className="py-2.5 px-3 text-slate-900 max-w-[200px] truncate"
                            title={log.path}
                          >
                            {log.path}
                          </td>
                          <td className="py-2.5 px-3">
                            {log.attack_type === "None" ? (
                              <span className="text-slate-400">Clean</span>
                            ) : (
                              <span
                                className={
                                  log.attack_type === "SQL Injection"
                                    ? "text-rose-600 font-semibold"
                                    : log.attack_type === "Cross-Site Scripting"
                                    ? "text-amber-600 font-semibold"
                                    : "text-sky-600 font-semibold"
                                }
                              >
                                {log.attack_type}
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-3">
                            <span
                              className={
                                log.risk_level === "CRITICAL"
                                  ? "text-rose-600 font-bold"
                                  : log.risk_level === "HIGH"
                                  ? "text-amber-600 font-bold"
                                  : log.risk_level === "MEDIUM"
                                  ? "text-sky-600 font-medium"
                                  : "text-slate-500"
                              }
                            >
                              {log.risk_level}
                            </span>
                          </td>
                          <td className="py-2.5 px-3">
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
                          <td className="py-2.5 px-3 text-right text-slate-400 text-[11px] font-medium">
                            {isExpanded ? "Hide \u2191" : "View \u2193"}
                          </td>
                        </tr>

                        {/* Expanded Investigation Detail Row */}
                        {isExpanded && (
                          <tr className="bg-slate-50/90 border-y border-slate-200">
                            <td colSpan={8} className="p-3.5 space-y-2.5">
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px] font-mono text-slate-700">
                                <div className="space-y-1">
                                  <span className="text-slate-500 block font-sans font-medium">Violation Reason:</span>
                                  <div className="text-slate-800 bg-white p-2.5 rounded border border-slate-200 shadow-xs">
                                    {log.reason}
                                  </div>
                                </div>
                                <div className="space-y-1">
                                  <span className="text-slate-500 block font-sans font-medium">
                                    Matched Security Rule:
                                  </span>
                                  <div className="text-[#0b192c] font-semibold bg-white p-2.5 rounded border border-slate-200 shadow-xs">
                                    {log.matched_rule_id
                                      ? `[${log.matched_rule_id}] ${log.matched_rule_name || ""}`
                                      : "None (Clean transaction)"}
                                  </div>
                                </div>
                              </div>

                              {log.offending_token && (
                                <div className="text-[11px] font-mono pt-1">
                                  <span className="text-slate-500 block font-sans font-medium mb-1">
                                    Offending Payload Snippet:
                                  </span>
                                  <code className="text-rose-700 bg-rose-50 px-2.5 py-1 rounded border border-rose-200 block break-all font-bold">
                                    {log.offending_token}
                                  </code>
                                </div>
                              )}
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  );
};
