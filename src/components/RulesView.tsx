import React, { useState } from "react";
import { Sliders, Plus, RotateCcw, Check, X, Shield } from "lucide-react";
import { SecurityRule } from "../wafEngine";

interface RulesViewProps {
  rules: SecurityRule[];
  onToggleRule: (ruleId: string) => void;
  onResetRules: () => void;
  onAddRule: (rule: SecurityRule) => void;
}

export const RulesView: React.FC<RulesViewProps> = ({
  rules,
  onToggleRule,
  onResetRules,
  onAddRule
}) => {
  const [filterType, setFilterType] = useState<string>("ALL");
  const [showAddModal, setShowAddModal] = useState(false);

  // New Rule State
  const [newRuleId, setNewRuleId] = useState("");
  const [newRuleName, setNewRuleName] = useState("");
  const [newAttackType, setNewAttackType] = useState<"SQL Injection" | "Cross-Site Scripting" | "Path Traversal">("SQL Injection");
  const [newPattern, setNewPattern] = useState("");
  const [newSeverity, setNewSeverity] = useState<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW">("HIGH");
  const [newDescription, setNewDescription] = useState("");

  const activeRulesCount = rules.filter((r) => r.is_enabled).length;

  const filteredRules = rules.filter((r) => {
    if (filterType !== "ALL" && r.attack_type !== filterType) return false;
    return true;
  });

  const handleCreateRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleId.trim() || !newRuleName.trim() || !newPattern.trim()) return;

    onAddRule({
      rule_id: newRuleId.trim().toUpperCase(),
      name: newRuleName.trim(),
      attack_type: newAttackType,
      pattern: newPattern.trim(),
      risk_level: newSeverity,
      action: "BLOCK",
      is_enabled: true,
      description: newDescription.trim() || "Custom rule created by administrator."
    });

    setShowAddModal(false);
    setNewRuleId("");
    setNewRuleName("");
    setNewPattern("");
    setNewDescription("");
  };

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 py-6 space-y-5">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-[#0b192c] tracking-tight">Security Rules</h1>
          <p className="text-xs text-slate-500">
            Signature detection patterns for SQLi, XSS, and Path Traversal threats.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              if (window.confirm("Reset all rules to system defaults?")) {
                onResetRules();
              }
            }}
            className="px-3 py-1.5 rounded-md text-xs font-medium text-slate-600 hover:text-slate-900 bg-white hover:bg-slate-50 border border-slate-200 transition flex items-center gap-1.5 shadow-sm"
            title="Reset rules to initial signatures"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Reset Defaults</span>
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="px-3.5 py-1.5 rounded-md text-xs font-semibold text-white bg-[#0b192c] hover:bg-[#1e3e62] transition flex items-center gap-1.5 shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Rule</span>
          </button>
        </div>
      </div>

      {/* Rules Filter Bar */}
      <div className="p-3.5 rounded-lg bg-white border border-slate-200 shadow-sm flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-slate-500 font-mono">Filter Category:</span>
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="bg-slate-50 border border-slate-200 rounded-md px-2.5 py-1 text-xs text-slate-700 font-mono focus:outline-none focus:border-[#1e3e62] focus:bg-white"
          >
            <option value="ALL">All Categories</option>
            <option value="SQL Injection">SQL Injection</option>
            <option value="Cross-Site Scripting">Cross-Site Scripting</option>
            <option value="Path Traversal">Path Traversal</option>
          </select>

          {/* Quick Filter Buttons */}
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={() => setFilterType("ALL")}
              className={`px-2 py-0.5 rounded text-[11px] font-mono transition cursor-pointer ${
                filterType === "ALL" ? "bg-[#0b192c] text-white font-bold" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
              }`}
            >
              All
            </button>
            <button
              type="button"
              onClick={() => setFilterType("SQL Injection")}
              className={`px-2 py-0.5 rounded text-[11px] font-mono transition cursor-pointer ${
                filterType === "SQL Injection" ? "bg-[#1e3e62] text-white font-bold" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
              }`}
            >
              SQLi
            </button>
            <button
              type="button"
              onClick={() => setFilterType("Cross-Site Scripting")}
              className={`px-2 py-0.5 rounded text-[11px] font-mono transition cursor-pointer ${
                filterType === "Cross-Site Scripting" ? "bg-[#1e3e62] text-white font-bold" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
              }`}
            >
              XSS
            </button>
            <button
              type="button"
              onClick={() => setFilterType("Path Traversal")}
              className={`px-2 py-0.5 rounded text-[11px] font-mono transition cursor-pointer ${
                filterType === "Path Traversal" ? "bg-[#1e3e62] text-white font-bold" : "bg-slate-100 text-slate-600 hover:bg-slate-200"
              }`}
            >
              Traversal
            </button>
          </div>
        </div>

        <div className="text-[11px] text-slate-500 font-mono">
          <strong>{activeRulesCount}</strong> active of {rules.length} rules
        </div>
      </div>

      {/* Rules Table & Mobile Cards */}
      <div className="rounded-lg bg-white border border-slate-200 shadow-sm overflow-hidden">
        {/* Mobile View: Clean Rule Cards */}
        <div className="block md:hidden divide-y divide-slate-100">
          {filteredRules.map((rule) => (
            <div
              key={rule.rule_id}
              className={`p-3.5 transition space-y-2 ${
                !rule.is_enabled ? "opacity-60 bg-slate-50/60" : "bg-white"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <span className="text-[10px] font-mono text-[#1e3e62] font-bold block">{rule.rule_id}</span>
                  <h4 className="text-xs font-bold text-slate-900 font-sans">{rule.name}</h4>
                </div>
                <button
                  type="button"
                  onClick={() => onToggleRule(rule.rule_id)}
                  className={`px-2.5 py-1 rounded text-[11px] font-mono transition shrink-0 cursor-pointer ${
                    rule.is_enabled
                      ? "bg-slate-100 hover:bg-rose-50 hover:text-rose-700 text-slate-700 border border-slate-200"
                      : "bg-emerald-50 text-emerald-700 border border-emerald-200 font-bold"
                  }`}
                >
                  {rule.is_enabled ? "Disable" : "Enable"}
                </button>
              </div>

              <div className="flex flex-wrap items-center gap-1.5 text-[10px] font-mono">
                <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 font-semibold">
                  {rule.attack_type}
                </span>
                <span
                  className={`px-1.5 py-0.5 rounded font-bold ${
                    rule.risk_level === "CRITICAL"
                      ? "bg-rose-50 text-rose-700 border border-rose-200"
                      : rule.risk_level === "HIGH"
                      ? "bg-amber-50 text-amber-700 border border-amber-200"
                      : "bg-sky-50 text-sky-700 border border-sky-200"
                  }`}
                >
                  {rule.risk_level}
                </span>
                <span className="px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 font-semibold">
                  {rule.action}
                </span>
                {rule.is_enabled ? (
                  <span className="text-emerald-600 font-bold flex items-center gap-0.5 ml-auto">
                    <Check className="w-3 h-3" /> Active
                  </span>
                ) : (
                  <span className="text-slate-400 font-medium flex items-center gap-0.5 ml-auto">
                    <X className="w-3 h-3" /> Inactive
                  </span>
                )}
              </div>

              <div className="text-[10px] font-mono text-slate-500 bg-slate-50 p-2 rounded border border-slate-200 break-all">
                <code>{rule.pattern}</code>
              </div>
            </div>
          ))}
        </div>

        {/* Desktop View: Full Rules Table */}
        <div className="hidden md:block overflow-x-auto">
          <table className="w-full text-left text-xs font-mono min-w-[620px]">
            <thead>
              <tr className="text-slate-500 border-b border-slate-200 bg-slate-50">
                <th className="py-2.5 px-3 font-semibold">Rule Name</th>
                <th className="py-2.5 px-3 font-semibold">Attack Type</th>
                <th className="py-2.5 px-3 font-semibold">Severity</th>
                <th className="py-2.5 px-3 font-semibold">Action</th>
                <th className="py-2.5 px-3 font-semibold">Status</th>
                <th className="py-2.5 px-3 font-semibold text-right">Toggle</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredRules.map((rule) => (
                <tr
                  key={rule.rule_id}
                  className={`hover:bg-slate-50/80 transition ${
                    !rule.is_enabled ? "opacity-50 bg-slate-50/50" : ""
                  }`}
                >
                  <td className="py-3 px-3">
                    <div className="font-sans font-semibold text-slate-900">{rule.name}</div>
                    <div className="text-[11px] text-slate-500 font-mono flex items-center gap-2 mt-0.5">
                      <span className="text-[#1e3e62] font-bold">{rule.rule_id}</span>
                      <span>&bull;</span>
                      <code className="text-slate-500 text-[10px] truncate max-w-[280px]" title={rule.pattern}>
                        {rule.pattern}
                      </code>
                    </div>
                  </td>
                  <td className="py-3 px-3 text-slate-700">{rule.attack_type}</td>
                  <td className="py-3 px-3">
                    <span
                      className={`font-semibold ${
                        rule.risk_level === "CRITICAL"
                          ? "text-rose-600 font-bold"
                          : rule.risk_level === "HIGH"
                          ? "text-amber-600 font-bold"
                          : "text-sky-600"
                      }`}
                    >
                      {rule.risk_level}
                    </span>
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-100 text-slate-700 border border-slate-200 font-bold">
                      {rule.action}
                    </span>
                  </td>
                  <td className="py-3 px-3">
                    {rule.is_enabled ? (
                      <span className="inline-flex items-center gap-1 text-emerald-600 font-bold">
                        <Check className="w-3.5 h-3.5" />
                        <span>Active</span>
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-slate-400 font-medium">
                        <X className="w-3.5 h-3.5" />
                        <span>Disabled</span>
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-3 text-right">
                    <button
                      onClick={() => onToggleRule(rule.rule_id)}
                      className={`px-3 py-1 rounded text-xs font-sans transition cursor-pointer ${
                        rule.is_enabled
                          ? "bg-slate-100 hover:bg-rose-50 hover:text-rose-700 text-slate-700 border border-slate-200 hover:border-rose-200"
                          : "bg-emerald-50 hover:bg-emerald-100 text-emerald-700 border border-emerald-200 font-semibold"
                      }`}
                    >
                      {rule.is_enabled ? "Disable" : "Enable"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Add Custom Rule Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="w-full max-w-md max-h-[90vh] overflow-y-auto bg-white border border-slate-200 rounded-lg p-5 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-slate-100 pb-3">
              <h3 className="text-sm font-bold text-[#0b192c]">Add Custom Security Rule</h3>
              <button
                onClick={() => setShowAddModal(false)}
                className="text-slate-400 hover:text-slate-600 text-xs font-mono"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCreateRule} className="space-y-3 text-xs font-mono">
              <div>
                <label className="text-slate-600 block mb-1">Rule ID</label>
                <input
                  type="text"
                  required
                  value={newRuleId}
                  onChange={(e) => setNewRuleId(e.target.value)}
                  placeholder="RULE-CUSTOM-01"
                  className="w-full bg-slate-50 border border-slate-200 rounded px-2.5 py-1.5 text-slate-800 focus:outline-none focus:border-[#1e3e62] focus:bg-white"
                />
              </div>

              <div>
                <label className="text-slate-600 block mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  value={newRuleName}
                  onChange={(e) => setNewRuleName(e.target.value)}
                  placeholder="Detect Custom Command Injection"
                  className="w-full bg-slate-50 border border-slate-200 rounded px-2.5 py-1.5 text-slate-800 focus:outline-none focus:border-[#1e3e62] focus:bg-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-2.5">
                <div>
                  <label className="text-slate-600 block mb-1">Attack Category</label>
                  <select
                    value={newAttackType}
                    onChange={(e) => setNewAttackType(e.target.value as any)}
                    className="w-full bg-slate-50 border border-slate-200 rounded px-2 py-1.5 text-slate-800 focus:outline-none focus:border-[#1e3e62] focus:bg-white"
                  >
                    <option value="SQL Injection">SQL Injection</option>
                    <option value="Cross-Site Scripting">Cross-Site Scripting</option>
                    <option value="Path Traversal">Path Traversal</option>
                  </select>
                </div>
                <div>
                  <label className="text-slate-600 block mb-1">Severity</label>
                  <select
                    value={newSeverity}
                    onChange={(e) => setNewSeverity(e.target.value as any)}
                    className="w-full bg-slate-50 border border-slate-200 rounded px-2 py-1.5 text-slate-800 focus:outline-none focus:border-[#1e3e62] focus:bg-white"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="text-slate-600 block mb-1">Regex Pattern</label>
                <input
                  type="text"
                  required
                  value={newPattern}
                  onChange={(e) => setNewPattern(e.target.value)}
                  placeholder="e.g. (;\\s*(cat|whoami|id))"
                  className="w-full bg-slate-50 border border-slate-200 rounded px-2.5 py-1.5 text-slate-800 focus:outline-none focus:border-[#1e3e62] focus:bg-white"
                />
              </div>

              <div>
                <label className="text-slate-600 block mb-1">Description (Optional)</label>
                <input
                  type="text"
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder="Explains what this rule detects..."
                  className="w-full bg-slate-50 border border-slate-200 rounded px-2.5 py-1.5 text-slate-800 focus:outline-none focus:border-[#1e3e62] focus:bg-white"
                />
              </div>

              <div className="pt-3 border-t border-slate-100 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3 py-1.5 rounded border border-slate-200 text-slate-600 hover:text-slate-800"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 rounded bg-[#0b192c] hover:bg-[#1e3e62] text-white font-medium font-sans shadow-sm"
                >
                  Save Rule
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
