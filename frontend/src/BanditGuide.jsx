import { useMemo, useState } from "react";
import {
  AlertTriangle,
  BookOpen,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  Minus,
  Plus,
  Search,
  Terminal,
  XCircle,
} from "lucide-react";
import { useBanditRules } from "./banditRules";

/* =========================================================
   DATA
========================================================= */

function ruleFor(rules, finding) {
  const id = finding?.test_id;
  const rule = rules?.rules?.[id];
  const cwe = rule?.cwe || finding?.issue_cwe?.id;
  return {
    test_id: id,
    name: rule?.name || (finding?.test_name || id || "").replaceAll("_", " "),
    why: rule?.why || finding?.issue_text,
    fix: rule?.fix,
    vulnerable: rule?.vulnerable || "",
    fixed: rule?.fixed || "",
    category: rule?.category_label || "Other",
    cwe,
    cwe_url: cwe
      ? `https://cwe.mitre.org/data/definitions/${cwe}.html`
      : null,
    docs_url: finding?.more_info || rule?.docs_url,
    known: Boolean(rule),
  };
}

const LEVELS = ["HIGH", "MEDIUM", "LOW"];

function levelClass(level) {
  return String(level || "").toLowerCase();
}

/* =========================================================
   SEVERITY x CONFIDENCE
========================================================= */

export function SeverityConfidence({ severity, confidence, rules }) {
  return (
    <div className="bg-levels">
      <div className="bg-level">
        <span className="bg-level-label">SEVERITY</span>
        <span className={`severity ${levelClass(severity)}`}>
          {severity || "?"}
        </span>
        <p>{rules?.severity_levels?.[severity] || "How bad it is if exploited."}</p>
      </div>
      <div className="bg-level">
        <span className="bg-level-label">CONFIDENCE</span>
        <span className={`severity ${levelClass(confidence)}`}>
          {confidence || "?"}
        </span>
        <p>
          {rules?.confidence_levels?.[confidence] ||
            "How sure Bandit is that this is a real issue."}
        </p>
      </div>
    </div>
  );
}

/* =========================================================
   RULE EXPLAINER (selected finding)
========================================================= */

function CodeCompare({ vulnerable, fixed }) {
  if (!vulnerable && !fixed) return null;
  return (
    <div className="bg-compare">
      {vulnerable && (
        <div className="bg-code bad">
          <div className="bg-code-head">
            <XCircle size={13} /> VULNERABLE PATTERN
          </div>
          <pre>{vulnerable}</pre>
        </div>
      )}
      {fixed && (
        <div className="bg-code good">
          <div className="bg-code-head">
            <CheckCircle2 size={13} /> SAFE PATTERN
          </div>
          <pre>{fixed}</pre>
        </div>
      )}
    </div>
  );
}

export function RuleExplainer({ finding, compact = false }) {
  const rules = useBanditRules();
  const [open, setOpen] = useState(!compact);
  if (!finding) return null;
  const rule = ruleFor(rules, finding);

  return (
    <div className="bg-explainer">
      <button className="bg-explainer-head" onClick={() => setOpen(!open)}>
        <BookOpen size={15} />
        <span>
          What does <b>{rule.test_id}</b> mean?
          <em> {rule.name}</em>
        </span>
        {open ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
      </button>

      {open && (
        <div className="bg-explainer-body">
          <div className="bg-tags">
            <span className="bg-tag">{rule.category}</span>
            {rule.cwe && (
              <a
                className="bg-tag link"
                href={rule.cwe_url}
                target="_blank"
                rel="noreferrer"
              >
                CWE-{rule.cwe} <ExternalLink size={10} />
              </a>
            )}
            {rule.docs_url && (
              <a
                className="bg-tag link"
                href={rule.docs_url}
                target="_blank"
                rel="noreferrer"
              >
                Bandit docs <ExternalLink size={10} />
              </a>
            )}
          </div>

          <p className="bg-why">
            <AlertTriangle size={13} /> {rule.why}
          </p>

          <SeverityConfidence
            severity={finding.issue_severity}
            confidence={finding.issue_confidence}
            rules={rules}
          />

          {finding.code && (
            <div className="bg-code flagged">
              <div className="bg-code-head">
                <Terminal size={13} /> FLAGGED IN YOUR CODE · line{" "}
                {finding.line_number}
              </div>
              <pre>{finding.code}</pre>
            </div>
          )}

          <CodeCompare vulnerable={rule.vulnerable} fixed={rule.fixed} />

          {rule.fix && (
            <p className="bg-fix">
              <CheckCircle2 size={13} /> <b>How to fix:</b> {rule.fix}
            </p>
          )}
        </div>
      )}
    </div>
  );
}

/* =========================================================
   LIVE SCAN TERMINAL
========================================================= */

export function ScanTerminal({ log, scanning, meta }) {
  if (!log?.length && !scanning) return null;
  const progress = meta?.total
    ? Math.round(((meta.scanned || 0) / meta.total) * 100)
    : 0;

  return (
    <section className="panel bg-terminal">
      <div className="panel-head">
        <div>
          <div className="section-kicker">LIVE SAST STREAM</div>
          <h3>Bandit scan</h3>
        </div>
        <div className="stage-status">
          {scanning ? `${progress}%` : "DONE"}
        </div>
      </div>
      {meta?.command && (
        <div className="bg-command">
          <span>$</span> {meta.command}
        </div>
      )}
      <div className="bg-progress">
        <div style={{ width: `${scanning ? progress : 100}%` }} />
      </div>
      {/* column-reverse keeps the view pinned to the newest line */}
      <div className="bg-log">
        <div>
          {log.map((line, i) => (
            <div key={i} className={`bg-log-line ${line.tone || ""}`}>
              {line.text}
            </div>
          ))}
          {scanning && <div className="bg-log-line cursor">▍</div>}
        </div>
      </div>
    </section>
  );
}

/* =========================================================
   BEFORE / AFTER COMPARISON (validation)
========================================================= */

function CountCard({ title, counts }) {
  return (
    <div className="bg-count">
      <span>{title}</span>
      <b>{counts?.total ?? "–"}</b>
      <div>
        {LEVELS.map((l) => (
          <em key={l} className={levelClass(l)}>
            {l[0]} {counts?.[l] ?? 0}
          </em>
        ))}
      </div>
    </div>
  );
}

function FindingRow({ item, kind }) {
  const Icon = kind === "removed" ? Minus : Plus;
  return (
    <div className={`bg-diff-row ${kind}`}>
      <Icon size={13} />
      <b>{item.test_id}</b>
      <span className={`severity ${levelClass(item.severity)}`}>
        {item.severity}
      </span>
      <code>
        {item.file}:{item.line}
      </code>
      <span className="bg-diff-text">{item.text}</span>
    </div>
  );
}

export function BanditComparison({ comparison }) {
  if (!comparison) return null;
  const { before, after, removed = [], introduced = [] } = comparison;
  return (
    <div className="panel bg-comparison">
      <div className="panel-head">
        <div>
          <div className="section-kicker">BANDIT RE-SCAN</div>
          <h3>Findings before vs after the patch</h3>
        </div>
      </div>
      <div className="bg-counts">
        <CountCard title="BEFORE" counts={before} />
        <div className="bg-arrow">→</div>
        <CountCard title="AFTER" counts={after} />
      </div>
      {removed.map((item, i) => (
        <FindingRow key={`r${i}`} item={item} kind="removed" />
      ))}
      {introduced.map((item, i) => (
        <FindingRow key={`i${i}`} item={item} kind="introduced" />
      ))}
      {!removed.length && !introduced.length && (
        <p className="bg-muted">No findings changed.</p>
      )}
      {introduced.length > 0 && (
        <p className="bg-muted">
          Introduced LOW findings such as B603/B404 are informational
          (&quot;check this subprocess call&quot;), not new vulnerabilities.
        </p>
      )}
    </div>
  );
}

/* =========================================================
   BANDIT GUIDE PAGE
========================================================= */

export function BanditGuide({ findings = [], scanMeta }) {
  const rules = useBanditRules();
  const [query, setQuery] = useState("");
  const [onlyFound, setOnlyFound] = useState(findings.length > 0);
  const [openId, setOpenId] = useState(null);
  const [showRaw, setShowRaw] = useState(false);

  const counts = useMemo(() => {
    const c = {};
    findings.forEach((f) => {
      c[f.test_id] = (c[f.test_id] || 0) + 1;
    });
    return c;
  }, [findings]);

  const list = useMemo(() => {
    const ids = new Set([
      ...Object.keys(rules?.rules || {}),
      ...Object.keys(counts),
    ]);
    const q = query.trim().toLowerCase();
    return [...ids]
      .sort()
      .map((id) =>
        ruleFor(rules, findings.find((f) => f.test_id === id) || { test_id: id })
      )
      .filter((r) => !onlyFound || counts[r.test_id])
      .filter(
        (r) =>
          !q ||
          r.test_id.toLowerCase().includes(q) ||
          r.name.toLowerCase().includes(q) ||
          String(r.cwe || "").includes(q) ||
          r.category.toLowerCase().includes(q)
      );
  }, [rules, counts, findings, query, onlyFound]);

  return (
    <div className="detail-stack">
      <div className="panel">
        <div className="panel-head">
          <div>
            <div className="section-kicker">UNDERSTANDING BANDIT</div>
            <h3>How SecurePatch detects vulnerabilities</h3>
          </div>
          {rules?.bandit_version && (
            <div className="stage-status">Bandit {rules.bandit_version}</div>
          )}
        </div>
        <p className="bg-intro">
          <b>Bandit</b> is a static application security testing (SAST) tool
          for Python. It parses every file into an <b>AST</b> (abstract
          syntax tree) and runs rule plugins over it. Each rule (a{" "}
          <b>test ID</b> like <code>B602</code>) looks for one risky pattern,
          such as <code>subprocess(..., shell=True)</code>. A match is a{" "}
          <b>finding</b> with a <b>severity</b> (how bad) and a{" "}
          <b>confidence</b> (how sure), mapped to a <b>CWE</b> weakness ID.
        </p>

        <div className="bg-matrix">
          <div className="bg-matrix-col">
            <span className="bg-level-label">SEVERITY = impact</span>
            {LEVELS.map((l) => (
              <div key={l} className="bg-matrix-row">
                <span className={`severity ${levelClass(l)}`}>{l}</span>
                <p>{rules?.severity_levels?.[l]}</p>
              </div>
            ))}
          </div>
          <div className="bg-matrix-col">
            <span className="bg-level-label">CONFIDENCE = certainty</span>
            {LEVELS.map((l) => (
              <div key={l} className="bg-matrix-row">
                <span className={`severity ${levelClass(l)}`}>{l}</span>
                <p>{rules?.confidence_levels?.[l]}</p>
              </div>
            ))}
          </div>
        </div>

        <p className="bg-muted">
          Prioritise <b>HIGH severity + HIGH confidence</b> first. LOW
          confidence findings need a human look: they can be false positives.
        </p>
      </div>

      {scanMeta?.command && (
        <div className="panel">
          <div className="panel-head">
            <div>
              <div className="section-kicker">LAST SCAN</div>
              <h3>Exact command and raw output</h3>
            </div>
            {scanMeta.duration_ms != null && (
              <div className="stage-status">
                {findings.length} findings · {scanMeta.duration_ms} ms
              </div>
            )}
          </div>
          <div className="bg-command">
            <span>$</span> {scanMeta.command}
          </div>
          <button className="secondary-btn" onClick={() => setShowRaw(!showRaw)}>
            {showRaw ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            {showRaw ? "HIDE" : "SHOW"} RAW BANDIT JSON
          </button>
          {showRaw && (
            <pre className="bg-raw">
              {JSON.stringify({ results: findings }, null, 2)}
            </pre>
          )}
        </div>
      )}

      <div className="panel">
        <div className="panel-head">
          <div>
            <div className="section-kicker">RULE CATALOG</div>
            <h3>
              {onlyFound ? "Rules found in this repository" : "All explained rules"}
            </h3>
          </div>
          <div className="stage-status">{list.length} rules</div>
        </div>

        <div className="bg-filter">
          <div className="repo-input">
            <Search size={15} />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search B608, SQL, CWE-78, crypto..."
            />
          </div>
          <label className="publish-check" style={{ margin: 0 }}>
            <input
              type="checkbox"
              checked={onlyFound}
              disabled={!findings.length}
              onChange={(e) => setOnlyFound(e.target.checked)}
            />
            Only rules in this scan
          </label>
        </div>

        <div className="bg-rules">
          {list.map((rule) => {
            const open = openId === rule.test_id;
            return (
              <div key={rule.test_id} className={`bg-rule ${open ? "open" : ""}`}>
                <button
                  className="bg-rule-head"
                  onClick={() => setOpenId(open ? null : rule.test_id)}
                >
                  <b>{rule.test_id}</b>
                  <span>{rule.name}</span>
                  <em>{rule.category}</em>
                  {counts[rule.test_id] > 0 && (
                    <span className="count-pill">{counts[rule.test_id]} found</span>
                  )}
                  {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                </button>
                {open && (
                  <div className="bg-rule-body">
                    <p className="bg-why">{rule.why}</p>
                    <CodeCompare vulnerable={rule.vulnerable} fixed={rule.fixed} />
                    {rule.fix && (
                      <p className="bg-fix">
                        <CheckCircle2 size={13} /> <b>How to fix:</b> {rule.fix}
                      </p>
                    )}
                    <div className="bg-tags">
                      {rule.cwe && (
                        <a className="bg-tag link" href={rule.cwe_url} target="_blank" rel="noreferrer">
                          CWE-{rule.cwe} <ExternalLink size={10} />
                        </a>
                      )}
                      {rule.docs_url && (
                        <a className="bg-tag link" href={rule.docs_url} target="_blank" rel="noreferrer">
                          Bandit docs <ExternalLink size={10} />
                        </a>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
          {!list.length && <p className="bg-muted">No matching rules.</p>}
        </div>
      </div>
    </div>
  );
}
