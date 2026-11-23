import { useState } from "react";
import { ExternalLink, FolderUp, Search, Sparkles, X } from "lucide-react";

// Deliberately vulnerable Python projects - safe, legal scan targets.
const PRESETS = [
  {
    label: "Vulnerable Flask App",
    url: "https://github.com/we45/Vulnerable-Flask-App",
    note: "18 findings · MD5, SQLi, YAML, TLS",
  },
  {
    label: "Vulpy",
    url: "https://github.com/fportantier/vulpy",
    note: "51 findings · Flask debug, SQLi",
  },
  {
    label: "OWASP PyGoat",
    url: "https://github.com/adeyosemanputra/pygoat",
    note: "Django · OWASP Top 10 labs",
  },
  {
    label: "DVPWA",
    url: "https://github.com/anxolerd/dvpwa",
    note: "aiohttp · small & fast",
  },
];

// GitHub searches that surface intentionally vulnerable Python repos.
const SEARCHES = [
  ["Vulnerable Flask apps", "vulnerable flask app language:Python"],
  ["Damn Vulnerable * (Python)", "\"damn vulnerable\" language:Python"],
  ["Deliberately insecure Python", "deliberately insecure language:Python"],
  ["Topic: vulnerable-app", "topic:vulnerable-application language:Python"],
  ["OWASP training apps", "OWASP vulnerable language:Python"],
  ["Vulnerable Django apps", "vulnerable django app language:Python"],
  ["Security training labs", "security training lab vulnerable language:Python"],
];

function searchUrl(query) {
  return `https://github.com/search?q=${encodeURIComponent(query)}&type=repositories&s=stars&o=desc`;
}

export function RepoPresets({ onPick, onFolder, disabled }) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <div className="rf-presets">
        <span className="rf-label">
          <Sparkles size={12} /> QUICK START
        </span>
        {PRESETS.map((p) => (
          <button
            key={p.url}
            className="rf-chip"
            title={`${p.url}\n${p.note}`}
            disabled={disabled}
            onClick={() => onPick(p.url)}
          >
            {p.label}
          </button>
        ))}
        <button className="rf-chip ghost" onClick={() => setOpen(true)}>
          <Search size={12} /> Find more
        </button>
        {onFolder && (
          <label className={`rf-chip ghost ${disabled ? "disabled" : ""}`}>
            <FolderUp size={12} /> Upload folder
            <input
              type="file"
              hidden
              webkitdirectory=""
              directory=""
              multiple
              disabled={disabled}
              onChange={(e) => {
                const files = [...(e.target.files || [])];
                e.target.value = "";
                if (files.length) onFolder(files);
              }}
            />
          </label>
        )}
      </div>

      {open && (
        <div className="rf-backdrop" onClick={() => setOpen(false)}>
          <div className="rf-modal panel" onClick={(e) => e.stopPropagation()}>
            <div className="panel-head">
              <div>
                <div className="section-kicker">FIND SCAN TARGETS</div>
                <h3>Intentionally vulnerable Python repositories</h3>
              </div>
              <button className="icon-btn" onClick={() => setOpen(false)}>
                <X size={16} />
              </button>
            </div>

            <div className="rf-grid">
              {PRESETS.map((p) => (
                <button
                  key={p.url}
                  className="rf-card"
                  onClick={() => {
                    onPick(p.url);
                    setOpen(false);
                  }}
                >
                  <b>{p.label}</b>
                  <span>{p.note}</span>
                  <code>{p.url.replace("https://", "")}</code>
                </button>
              ))}
            </div>

            <div className="section-kicker" style={{ margin: "16px 0 8px" }}>
              LIVE GITHUB SEARCHES
            </div>
            <div className="rf-searches">
              {SEARCHES.map(([label, q]) => (
                <a key={q} href={searchUrl(q)} target="_blank" rel="noreferrer">
                  <Search size={12} />
                  <span>{label}</span>
                  <code>{q}</code>
                  <ExternalLink size={11} />
                </a>
              ))}
            </div>
            <p className="bg-muted">
              Only scan code you are allowed to test. These projects are
              built to be insecure for training. Copy a repository URL from
              the search and paste it above.
            </p>
          </div>
        </div>
      )}
    </>
  );
}
