import React, { useState, useEffect } from "react";
import { Navbar, PageTab } from "./components/Navbar";
import { DashboardView } from "./components/DashboardView";
import { LogsView } from "./components/LogsView";
import { RulesView } from "./components/RulesView";
import { TestingView } from "./components/TestingView";
import { SettingsView } from "./components/SettingsView";
import { BlockedScreen } from "./components/BlockedScreen";
import { INITIAL_RULES, SecurityRule, SecurityLog } from "./wafEngine";

const INITIAL_DEMO_LOGS: SecurityLog[] = [
  {
    id: 101,
    timestamp: "2026-10-06 05:10:14",
    ip_address: "127.0.0.1",
    method: "GET",
    url: "/search?q=laptop+keyboard",
    path: "/search",
    attack_type: "None",
    risk_level: "LOW",
    action: "ALLOWED",
    reason: "Clean request verified by WAF rule engine",
    matched_rule_id: null,
    payload_snippet: '{"q":"laptop keyboard"}'
  },
  {
    id: 102,
    timestamp: "2026-10-06 05:12:30",
    ip_address: "127.0.0.1",
    method: "GET",
    url: "/search?q=' OR 1=1--",
    path: "/search",
    attack_type: "SQL Injection",
    risk_level: "HIGH",
    action: "BLOCKED",
    reason: "Triggered rule [RULE-SQLI-001]: SQLi - Boolean-based Tautology Pattern in Query Param 'q'",
    matched_rule_id: "RULE-SQLI-001",
    matched_rule_name: "SQLi - Boolean-based Tautology Pattern",
    payload_snippet: '{"q":"\' OR 1=1--" }',
    offending_token: "' OR 1=1"
  },
  {
    id: 103,
    timestamp: "2026-10-06 05:14:02",
    ip_address: "127.0.0.1",
    method: "GET",
    url: "/search?q=<script>alert('XSS')</script>",
    path: "/search",
    attack_type: "Cross-Site Scripting",
    risk_level: "CRITICAL",
    action: "BLOCKED",
    reason: "Triggered rule [RULE-XSS-001]: XSS - Explicit Script Tag Injection in Query Param 'q'",
    matched_rule_id: "RULE-XSS-001",
    matched_rule_name: "XSS - Explicit Script Tag Injection",
    payload_snippet: '{"q":"<script>alert(\'XSS\')</script>"}',
    offending_token: "<script>alert('XSS')</script>"
  },
  {
    id: 104,
    timestamp: "2026-10-06 05:15:45",
    ip_address: "127.0.0.1",
    method: "GET",
    url: "/view-file?file=../../etc/passwd",
    path: "/view-file",
    attack_type: "Path Traversal",
    risk_level: "CRITICAL",
    action: "BLOCKED",
    reason: "Triggered rule [RULE-PT-001]: Path Traversal - Directory Climbing Sequences in Query Param 'file'",
    matched_rule_id: "RULE-PT-001",
    matched_rule_name: "Path Traversal - Directory Climbing Sequences",
    payload_snippet: '{"file":"../../etc/passwd"}',
    offending_token: "../../"
  }
];

export default function App() {
  const [currentTab, setCurrentTab] = useState<PageTab>("dashboard");

  const [rules, setRules] = useState<SecurityRule[]>(() => {
    try {
      const saved = localStorage.getItem("waf_rules_v2");
      return saved ? JSON.parse(saved) : INITIAL_RULES;
    } catch {
      return INITIAL_RULES;
    }
  });

  const [logs, setLogs] = useState<SecurityLog[]>(() => {
    try {
      const saved = localStorage.getItem("waf_logs_v2");
      return saved ? JSON.parse(saved) : INITIAL_DEMO_LOGS;
    } catch {
      return INITIAL_DEMO_LOGS;
    }
  });

  const [wafMode, setWafMode] = useState<"BLOCKING" | "MONITORING">(() => {
    try {
      const saved = localStorage.getItem("waf_mode");
      return (saved as "BLOCKING" | "MONITORING") || "BLOCKING";
    } catch {
      return "BLOCKING";
    }
  });

  const [latestBlock, setLatestBlock] = useState<SecurityLog | null>(null);

  // Sync to local storage
  useEffect(() => {
    try {
      localStorage.setItem("waf_rules_v2", JSON.stringify(rules));
    } catch (e) {
      console.warn("Storage sync failed", e);
    }
  }, [rules]);

  useEffect(() => {
    try {
      localStorage.setItem("waf_logs_v2", JSON.stringify(logs));
    } catch (e) {
      console.warn("Storage sync failed", e);
    }
  }, [logs]);

  useEffect(() => {
    try {
      localStorage.setItem("waf_mode", wafMode);
    } catch (e) {
      console.warn("Storage sync failed", e);
    }
  }, [wafMode]);

  const handleLogGenerated = (log: SecurityLog, wasBlocked: boolean) => {
    setLogs((prev) => [log, ...prev]);
    if (wasBlocked) {
      setLatestBlock(log);
    }
  };

  const handleToggleRule = (ruleId: string) => {
    setRules((prev) =>
      prev.map((r) => (r.rule_id === ruleId ? { ...r, is_enabled: !r.is_enabled } : r))
    );
  };

  const handleResetRules = () => {
    setRules(INITIAL_RULES);
  };

  const handleClearLogs = () => {
    setLogs([]);
  };

  const handleAddRule = (newRule: SecurityRule) => {
    setRules((prev) => [newRule, ...prev]);
  };

  const handlePreviewBlocked = (blockLog: SecurityLog) => {
    setLatestBlock(blockLog);
    setCurrentTab("blocked");
  };

  const activeRulesCount = rules.filter((r) => r.is_enabled).length;

  return (
    <div className="min-h-screen bg-slate-100/70 text-slate-800 flex flex-col font-sans selection:bg-[#0b192c] selection:text-white">
      {/* Top Navbar */}
      <Navbar
        currentTab={currentTab}
        setCurrentTab={setCurrentTab}
        totalLogsCount={logs.length}
        activeRulesCount={activeRulesCount}
        wafMode={wafMode}
      />

      {/* Main Page Content */}
      <main className="flex-1 pb-10">
        {currentTab === "dashboard" && (
          <DashboardView
            logs={logs}
            onViewAllLogs={() => setCurrentTab("logs")}
            onGoToTesting={() => setCurrentTab("testing")}
          />
        )}

        {currentTab === "logs" && (
          <LogsView logs={logs} onClearLogs={handleClearLogs} />
        )}

        {currentTab === "rules" && (
          <RulesView
            rules={rules}
            onToggleRule={handleToggleRule}
            onResetRules={handleResetRules}
            onAddRule={handleAddRule}
          />
        )}

        {currentTab === "testing" && (
          <TestingView
            rules={rules}
            wafMode={wafMode}
            onLogGenerated={handleLogGenerated}
            onPreviewBlocked={handlePreviewBlocked}
          />
        )}

        {currentTab === "settings" && (
          <SettingsView
            wafMode={wafMode}
            setWafMode={setWafMode}
            rules={rules}
            logs={logs}
            onResetRules={handleResetRules}
            onClearLogs={handleClearLogs}
          />
        )}

        {currentTab === "blocked" && (
          <BlockedScreen
            latestBlock={latestBlock}
            onReturnToTesting={() => setCurrentTab("testing")}
            onGoToLogs={() => setCurrentTab("logs")}
          />
        )}
      </main>

      {/* Clean, Subtle Footer */}
      <footer className="border-t border-slate-200 bg-white text-slate-500 py-3 text-xs font-mono">
        <div className="max-w-6xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>Web Application Firewall (WAF) &bull; Layer 7 Threat Detection System</span>
          <span className="text-slate-400">Rules-Based Security Engine &bull; Local Environment</span>
        </div>
      </footer>
    </div>
  );
}
