import React, { useState } from "react";
import { Terminal, Play, ArrowRight } from "lucide-react";
import { SecurityRule, evaluateRequest, SecurityLog } from "../wafEngine";

interface TestingViewProps {
  rules: SecurityRule[];
  wafMode: "BLOCKING" | "MONITORING";
  onLogGenerated: (log: SecurityLog, wasBlocked: boolean) => void;
  onPreviewBlocked: (log: SecurityLog) => void;
}

interface TestPreset {
  label: string;
  category: "Normal" | "SQL Injection" | "Cross-Site Scripting" | "Path Traversal";
  method: string;
  path: string;
  paramKey: string;
  paramVal: string;
  expected: "ALLOWED" | "BLOCKED";
}

const PRESETS: TestPreset[] = [
  {
    label: "Normal Search Query",
    category: "Normal",
    method: "GET",
    path: "/search",
    paramKey: "q",
    paramVal: "laptop keyboard",
    expected: "ALLOWED"
  },
  {
    label: "Normal Document View",
    category: "Normal",
    method: "GET",
    path: "/view-file",
    paramKey: "file",
    paramVal: "whitepaper.pdf",
    expected: "ALLOWED"
  },
  {
    label: "SQLi: Boolean Tautology",
    category: "SQL Injection",
    method: "GET",
    path: "/search",
    paramKey: "q",
    paramVal: "' OR 1=1--",
    expected: "BLOCKED"
  },
  {
    label: "SQLi: UNION SELECT Exfiltration",
    category: "SQL Injection",
    method: "GET",
    path: "/search",
    paramKey: "q",
    paramVal: "' UNION SELECT null, username, password FROM users--",
    expected: "BLOCKED"
  },
  {
    label: "XSS: Raw Script Tag",
    category: "Cross-Site Scripting",
    method: "GET",
    path: "/search",
    paramKey: "q",
    paramVal: "<script>alert('XSS')</script>",
    expected: "BLOCKED"
  },
  {
    label: "XSS: Inline Event Handler",
    category: "Cross-Site Scripting",
    method: "GET",
    path: "/search",
    paramKey: "q",
    paramVal: "<img src=x onerror=alert(1)>",
    expected: "BLOCKED"
  },
  {
    label: "Path Traversal: Parent Climbing",
    category: "Path Traversal",
    method: "GET",
    path: "/view-file",
    paramKey: "file",
    paramVal: "../../etc/passwd",
    expected: "BLOCKED"
  },
  {
    label: "Path Traversal: URL Encoded (%2e%2e%2f)",
    category: "Path Traversal",
    method: "GET",
    path: "/view-file",
    paramKey: "file",
    paramVal: "%2e%2e%2f%2e%2e%2fetc/passwd",
    expected: "BLOCKED"
  }
];

export const TestingView: React.FC<TestingViewProps> = ({
  rules,
  wafMode,
  onLogGenerated,
  onPreviewBlocked
}) => {
  const [method, setMethod] = useState("GET");
  const [path, setPath] = useState("/search");
  const [paramKey, setParamKey] = useState("q");
  const [paramVal, setParamVal] = useState("laptop keyboard");

  const [lastResult, setLastResult] = useState<{
    requestString: string;
    detectionResult: string;
    attackType: string;
    severity: string;
    action: "ALLOWED" | "BLOCKED";
    reason: string;
    matchedRule: string | null;
    offendingSnippet?: string;
    log: SecurityLog;
  } | null>(null);

  const runInspection = (
    reqMethod = method,
    reqPath = path,
    reqKey = paramKey,
    reqVal = paramVal
  ) => {
    const queryParams: Record<string, string> = reqMethod === "GET" && reqKey ? { [reqKey]: reqVal } : {};
    const bodyParams: Record<string, string> = reqMethod === "POST" && reqKey ? { [reqKey]: reqVal } : {};

    const decision = evaluateRequest(reqPath, queryParams, bodyParams, rules, wafMode);
    const nowStr = new Date().toISOString().replace("T", " ").substring(0, 19);

    const fullUrl = reqPath + (Object.keys(queryParams).length ? `?${new URLSearchParams(queryParams).toString()}` : "");

    const newLog: SecurityLog = {
      id: Math.floor(1000 + Math.random() * 9000),
      timestamp: nowStr,
      ip_address: "127.0.0.1",
      method: reqMethod,
      url: fullUrl,
      path: reqPath,
      attack_type: decision.attack_type,
      risk_level: decision.risk_level,
      action: decision.action,
      reason: decision.reason,
      matched_rule_id: decision.matched_rule_id,
      matched_rule_name: decision.matched_rule_name,
      payload_snippet: JSON.stringify({ ...queryParams, ...bodyParams }),
      offending_token: decision.offending_value
    };

    onLogGenerated(newLog, decision.is_blocked);

    setLastResult({
      requestString: `${reqMethod} ${fullUrl}`,
      detectionResult: decision.is_blocked || decision.attack_type !== "None"
        ? (wafMode === "BLOCKING" ? "Malicious Syntax Detected" : "Threat Detected (Passive)")
        : "Clean Request Verified",
      attackType: decision.attack_type,
      severity: decision.risk_level,
      action: decision.action,
      reason: decision.reason,
      matchedRule: decision.matched_rule_id
        ? `[${decision.matched_rule_id}] ${decision.matched_rule_name || ""}`
        : null,
      offendingSnippet: decision.offending_value,
      log: newLog
    });
  };

  const applyPreset = (preset: TestPreset) => {
    setMethod(preset.method);
    setPath(preset.path);
    setParamKey(preset.paramKey);
    setParamVal(preset.paramVal);
    runInspection(preset.method, preset.path, preset.paramKey, preset.paramVal);
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 py-6 space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-xl font-bold text-[#0b192c] tracking-tight">WAF Security Testing</h1>
        <p className="text-xs text-slate-500">
          Controlled testing interface for evaluating rule detection on local requests.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Preset Test Vectors & Custom Builder */}
        <div className="lg:col-span-7 space-y-5">
          {/* Quick Presets */}
          <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-sm space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-xs font-bold text-[#0b192c] uppercase font-mono tracking-wider">
                Controlled Test Presets
              </h2>
              <span className="text-[11px] text-slate-400 font-mono">One-click evaluation</span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {PRESETS.map((preset, idx) => {
                const isNormal = preset.expected === "ALLOWED";
                return (
                  <button
                    key={idx}
                    onClick={() => applyPreset(preset)}
                    className="p-2.5 rounded-md bg-slate-50/70 hover:bg-slate-100 border border-slate-200 text-left transition space-y-1 group cursor-pointer"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-slate-800 group-hover:text-[#0b192c]">
                        {preset.label}
                      </span>
                      <span
                        className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded ${
                          isNormal
                            ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                            : "bg-rose-50 text-rose-700 border border-rose-200"
                        }`}
                      >
                        {preset.expected}
                      </span>
                    </div>
                    <code className="text-[10px] text-slate-500 font-mono block truncate">
                      {preset.paramKey}={preset.paramVal}
                    </code>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Custom Request Form */}
          <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-sm space-y-3">
            <h2 className="text-xs font-bold text-[#0b192c] uppercase font-mono tracking-wider">
              Custom Request Inspector
            </h2>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                runInspection();
              }}
              className="space-y-3 text-xs font-mono"
            >
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                <div>
                  <label className="text-slate-600 block mb-1">HTTP Method</label>
                  <select
                    value={method}
                    onChange={(e) => setMethod(e.target.value)}
                    className="w-full bg-slate-50 border border-slate-200 rounded-md px-2.5 py-1.5 text-slate-800 focus:outline-none focus:border-[#1e3e62] focus:bg-white"
                  >
                    <option value="GET">GET</option>
                    <option value="POST">POST</option>
                  </select>
                </div>
                <div className="sm:col-span-2">
                  <label className="text-slate-600 block mb-1">URI Path</label>
                  <input
                    type="text"
                    value={path}
                    onChange={(e) => setPath(e.target.value)}
                    className="w-full bg-slate-50 border border-slate-200 rounded-md px-2.5 py-1.5 text-slate-800 focus:outline-none focus:border-[#1e3e62] focus:bg-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                <div>
                  <label className="text-slate-600 block mb-1">Param Key</label>
                  <input
                    type="text"
                    value={paramKey}
                    onChange={(e) => setParamKey(e.target.value)}
                    placeholder="q"
                    className="w-full bg-slate-50 border border-slate-200 rounded-md px-2.5 py-1.5 text-slate-800 focus:outline-none focus:border-[#1e3e62] focus:bg-white"
                  />
                </div>
                <div className="sm:col-span-2">
                  <label className="text-slate-600 block mb-1">Payload Value</label>
                  <input
                    type="text"
                    value={paramVal}
                    onChange={(e) => setParamVal(e.target.value)}
                    placeholder="e.g. ' OR 1=1--"
                    className="w-full bg-slate-50 border border-slate-200 rounded-md px-2.5 py-1.5 text-slate-800 focus:outline-none focus:border-[#1e3e62] focus:bg-white"
                  />
                </div>
              </div>

              <div className="pt-1">
                <button
                  type="submit"
                  className="w-full py-2 rounded-md bg-[#0b192c] hover:bg-[#1e3e62] text-white font-medium font-sans flex items-center justify-center gap-1.5 transition text-xs shadow-sm cursor-pointer"
                >
                  <Play className="w-3.5 h-3.5 fill-current text-sky-300" />
                  <span>Inspect Request Through WAF</span>
                </button>
              </div>
            </form>
          </div>
        </div>

        {/* Right Column: Inspection Result Panel */}
        <div className="lg:col-span-5 space-y-4">
          <div className="p-4 rounded-lg bg-white border border-slate-200 shadow-sm space-y-4 h-full flex flex-col justify-between">
            <div className="space-y-3">
              <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
                <h2 className="text-xs font-bold text-[#0b192c] uppercase font-mono tracking-wider">
                  Detection Result
                </h2>
                {lastResult && (
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      lastResult.action === "BLOCKED"
                        ? "bg-rose-50 text-rose-700 border border-rose-200"
                        : "bg-emerald-50 text-emerald-700 border border-emerald-200"
                    }`}
                  >
                    {lastResult.action}
                  </span>
                )}
              </div>

              {!lastResult ? (
                <div className="py-16 text-center text-xs text-slate-400 font-mono space-y-2">
                  <p>No test request sent yet.</p>
                  <p className="text-[11px] text-slate-400">
                    Click a preset or customize parameters on the left to evaluate WAF inspection.
                  </p>
                </div>
              ) : (
                <div className="space-y-3 text-xs font-mono">
                  {/* Request */}
                  <div>
                    <span className="text-slate-500 text-[11px] block font-sans font-medium">Evaluated Request:</span>
                    <code className="text-slate-800 bg-slate-50 p-2 rounded-md border border-slate-200 block break-all text-[11px] mt-0.5">
                      {lastResult.requestString}
                    </code>
                  </div>

                  {/* Detection Status */}
                  <div className="grid grid-cols-2 gap-2">
                    <div className="p-2.5 rounded-md bg-slate-50 border border-slate-200">
                      <span className="text-slate-500 text-[10px] block font-sans font-medium">Attack Category</span>
                      <span className="text-slate-900 font-semibold">{lastResult.attackType}</span>
                    </div>
                    <div className="p-2.5 rounded-md bg-slate-50 border border-slate-200">
                      <span className="text-slate-500 text-[10px] block font-sans font-medium">Assessed Severity</span>
                      <span
                        className={
                          lastResult.severity === "CRITICAL"
                            ? "text-rose-600 font-bold"
                            : lastResult.severity === "HIGH"
                            ? "text-amber-600 font-bold"
                            : "text-slate-700 font-semibold"
                        }
                      >
                        {lastResult.severity}
                      </span>
                    </div>
                  </div>

                  {/* Reason */}
                  <div>
                    <span className="text-slate-500 text-[11px] block font-sans font-medium">Inspection Outcome:</span>
                    <div className="p-2.5 rounded-md bg-slate-50 border border-slate-200 text-slate-800 text-[11px] leading-relaxed">
                      {lastResult.reason}
                    </div>
                  </div>

                  {/* Flagged Token */}
                  {lastResult.offendingSnippet && (
                    <div>
                      <span className="text-slate-500 text-[11px] block font-sans font-medium">Flagged Token:</span>
                      <code className="text-rose-700 bg-rose-50 px-2 py-1 rounded-md border border-rose-200 block text-[11px] break-all font-bold">
                        {lastResult.offendingSnippet}
                      </code>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Bottom Action for Blocked Response */}
            {lastResult && lastResult.action === "BLOCKED" && (
              <div className="pt-3 border-t border-slate-100">
                <button
                  onClick={() => onPreviewBlocked(lastResult.log)}
                  className="w-full py-2 rounded-md bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-xs font-sans font-semibold transition flex items-center justify-center gap-1.5 cursor-pointer shadow-2xs"
                >
                  <span>Preview Blocked Request Page (403)</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
