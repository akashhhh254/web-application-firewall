import React from "react";
import { ShieldAlert, ArrowLeft, FileText } from "lucide-react";
import { SecurityLog } from "../wafEngine";

interface BlockedScreenProps {
  latestBlock: SecurityLog | null;
  onReturnToTesting: () => void;
  onGoToLogs: () => void;
}

export const BlockedScreen: React.FC<BlockedScreenProps> = ({
  latestBlock,
  onReturnToTesting,
  onGoToLogs
}) => {
  const block = latestBlock || {
    id: 104,
    timestamp: new Date().toISOString().replace("T", " ").substring(0, 19),
    ip_address: "127.0.0.1",
    method: "GET",
    url: "/search?q=' OR '1'='1",
    path: "/search",
    attack_type: "SQL Injection",
    risk_level: "HIGH" as const,
    action: "BLOCKED" as const,
    reason: "Matched rule [RULE-SQLI-001]: SQLi - Boolean-based Tautology Pattern in Query Param 'q'",
    matched_rule_id: "RULE-SQLI-001",
    matched_rule_name: "SQLi - Boolean-based Tautology Pattern",
    payload_snippet: "' OR '1'='1",
    offending_token: "' OR '1'='1"
  };

  return (
    <div className="min-h-[80vh] flex items-center justify-center p-4 sm:p-6">
      <div className="w-full max-w-lg bg-white border border-rose-200/90 rounded-lg shadow-md overflow-hidden">
        {/* Top Strip */}
        <div className="bg-rose-50 border-b border-rose-200 p-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-md bg-rose-600 text-white shadow-xs">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <span className="text-[11px] font-mono uppercase font-bold text-rose-700 block tracking-wider">
                HTTP 403 Forbidden
              </span>
              <h1 className="text-base font-bold text-[#0b192c] font-sans">
                REQUEST BLOCKED
              </h1>
            </div>
          </div>
          <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-rose-100 text-rose-800 border border-rose-300">
            BLOCKED
          </span>
        </div>

        {/* Content Body */}
        <div className="p-5 space-y-4 text-xs font-sans">
          <p className="text-slate-600 leading-relaxed">
            The request was blocked by the Web Application Firewall because anomalous or malicious
            syntax matching an active security rule was detected.
          </p>

          {/* Details Table */}
          <div className="rounded-md border border-slate-200 bg-slate-50/70 divide-y divide-slate-200/80 font-mono text-[11px]">
            <div className="grid grid-cols-3 p-2.5">
              <span className="text-slate-500 font-sans font-medium">Attack Type:</span>
              <span className="col-span-2 text-rose-700 font-bold">
                {block.attack_type}
              </span>
            </div>

            <div className="grid grid-cols-3 p-2.5">
              <span className="text-slate-500 font-sans font-medium">Risk Level:</span>
              <span className="col-span-2">
                <span
                  className={
                    block.risk_level === "CRITICAL"
                      ? "text-rose-700 font-bold"
                      : block.risk_level === "HIGH"
                      ? "text-amber-700 font-bold"
                      : "text-sky-700 font-bold"
                  }
                >
                  {block.risk_level}
                </span>
              </span>
            </div>

            <div className="grid grid-cols-3 p-2.5">
              <span className="text-slate-500 font-sans font-medium">Reason:</span>
              <span className="col-span-2 text-slate-800 break-words leading-relaxed font-sans">
                {block.reason}
              </span>
            </div>

            {block.offending_token && (
              <div className="grid grid-cols-3 p-2.5 bg-rose-50/50">
                <span className="text-slate-500 font-sans font-medium">Flagged Token:</span>
                <span className="col-span-2">
                  <code className="text-rose-800 bg-white px-2 py-0.5 rounded border border-rose-200 text-[11px] break-all font-bold">
                    {block.offending_token}
                  </code>
                </span>
              </div>
            )}

            <div className="grid grid-cols-3 p-2.5">
              <span className="text-slate-500 font-sans font-medium">Incident Ref:</span>
              <span className="col-span-2 text-slate-700 font-semibold">#INC-{block.id}</span>
            </div>

            <div className="grid grid-cols-3 p-2.5">
              <span className="text-slate-500 font-sans font-medium">Client IP:</span>
              <span className="col-span-2 text-slate-600">{block.ip_address}</span>
            </div>

            <div className="grid grid-cols-3 p-2.5">
              <span className="text-slate-500 font-sans font-medium">Time:</span>
              <span className="col-span-2 text-slate-600">{block.timestamp}</span>
            </div>
          </div>

          <p className="text-[11px] text-slate-500 pt-1 font-mono">
            This incident has been recorded to the security audit log database.
          </p>

          {/* Action Buttons */}
          <div className="pt-2 flex items-center justify-end gap-2 border-t border-slate-100">
            <button
              onClick={onGoToLogs}
              className="px-3.5 py-1.5 rounded-md border border-slate-200 bg-white text-slate-700 hover:text-slate-900 hover:bg-slate-50 text-xs font-sans transition flex items-center gap-1.5 cursor-pointer shadow-xs"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>View Logs</span>
            </button>
            <button
              onClick={onReturnToTesting}
              className="px-3.5 py-1.5 rounded-md bg-[#0b192c] hover:bg-[#1e3e62] text-white font-medium text-xs font-sans transition flex items-center gap-1.5 cursor-pointer shadow-xs"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Back to Testing</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
