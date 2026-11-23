import { useEffect, useState } from "react";
import {
  CheckCircle2,
  Copy,
  ExternalLink,
  GitBranch,
  GitFork,
  GitPullRequest,
  KeyRound,
  Plus,
  RefreshCw,
  Send,
  ShieldCheck,
  Sparkles,
  XCircle,
} from "lucide-react";

import { API } from "./api";

const PROVIDERS = {
  github: {
    label: "GitHub",
    request: "pull request",
    tokenUrl:
      "https://github.com/settings/tokens/new?scopes=repo&description=SecurePatch",
    tokenHint:
      "Classic token with the 'repo' scope (or 'public_repo' for public repos).",
  },
  gitlab: {
    label: "GitLab",
    request: "merge request",
    tokenUrl:
      "https://gitlab.com/-/user_settings/personal_access_tokens?name=SecurePatch&scopes=api",
    tokenHint: "Personal access token with the 'api' scope.",
  },
};

const MODES = [
  {
    id: "auto",
    label: "Auto",
    icon: Sparkles,
    help: "Branch if you can push, fork if you can't, new repo for ZIP uploads.",
  },
  {
    id: "branch",
    label: "Branch",
    icon: GitBranch,
    help: "Push a fix branch to the original repository (needs write access).",
  },
  {
    id: "fork",
    label: "Fork",
    icon: GitFork,
    help: "Fork into your account and push the fix there. The original is untouched.",
  },
  {
    id: "new_repo",
    label: "New repo",
    icon: Plus,
    help: "Create a new repository in your account with the fixed code.",
  },
];

async function postJson(endpoint, body) {
  const response = await fetch(`${API}${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let data = {};
  try {
    data = await response.json();
  } catch {
    // non-JSON error
  }
  if (!response.ok) {
    throw new Error(
      data.detail || `Request failed: ${response.status}`
    );
  }
  return data;
}

export default function PublishPanel({ repoPath }) {
  const [source, setSource] = useState(null);
  const [provider, setProvider] = useState("github");
  const [token, setToken] = useState("");
  const [mode, setMode] = useState("auto");
  const [repoName, setRepoName] = useState("");
  const [isPrivate, setIsPrivate] = useState(true);
  const [openRequest, setOpenRequest] = useState(true);
  const [toUpstream, setToUpstream] = useState(false);

  const [plan, setPlan] = useState(null);
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!repoPath) return;
    fetch(
      `${API}/api/publish/source?repo_path=${encodeURIComponent(
        repoPath
      )}`
    )
      .then((r) => (r.ok ? r.json() : null))
      .then((data) => {
        if (!data) return;
        setSource(data.source);
        setProvider(data.suggested_provider || "github");
      })
      .catch(() => {});
  }, [repoPath]);

  const info = PROVIDERS[provider];
  const effectiveMode = plan?.mode || mode;
  const sameProvider = source && source.provider === provider;
  const showRepoName =
    effectiveMode === "new_repo" ||
    (mode === "auto" && !sameProvider);
  const showUpstream = effectiveMode === "fork" && openRequest;

  function payload() {
    return {
      repo_path: repoPath,
      provider,
      token: token.trim(),
      mode,
      new_repo_name: repoName.trim() || null,
      private: isPrivate,
      open_request: openRequest,
      request_to_upstream: showUpstream && toUpstream,
    };
  }

  async function checkAccess() {
    setBusy("check");
    setError("");
    setResult(null);
    try {
      setPlan(await postJson("/api/publish/preview", payload()));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  }

  async function publish() {
    setBusy("publish");
    setError("");
    setResult(null);
    try {
      setResult(await postJson("/api/publish", payload()));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy("");
    }
  }

  function copyClone() {
    navigator.clipboard
      ?.writeText(result.clone_command)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1500);
      });
  }

  return (
    <div className="panel publish-panel">
      <div className="panel-head">
        <div>
          <div className="section-kicker">PUBLISH VERIFIED FIX</div>
          <h3>Push to GitHub / GitLab</h3>
        </div>
        <div className="stage-status">
          <GitPullRequest size={14} />
          BRANCH · PR · REPO
        </div>
      </div>

      <div className="publish-source">
        {source ? (
          <>
            Imported from{" "}
            <a href={source.web_url} target="_blank" rel="noreferrer">
              {source.host}/{source.path}
            </a>
          </>
        ) : (
          <>
            Uploaded code with no Git remote. A{" "}
            <b>new repository</b> will be created in your account.
          </>
        )}
      </div>

      {/* PROVIDER */}
      <div className="publish-row">
        <span className="publish-label">Provider</span>
        <div className="publish-seg">
          {Object.entries(PROVIDERS).map(([id, p]) => (
            <button
              key={id}
              className={provider === id ? "active" : ""}
              onClick={() => {
                setProvider(id);
                setPlan(null);
              }}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* TOKEN */}
      <div className="publish-row">
        <span className="publish-label">Access token</span>
        <div className="repo-input">
          <KeyRound size={16} />
          <input
            type="password"
            autoComplete="off"
            value={token}
            onChange={(e) => {
              setToken(e.target.value);
              setPlan(null);
            }}
            placeholder={`${info.label} personal access token`}
          />
        </div>
        <div className="publish-hint">
          {info.tokenHint}{" "}
          <a href={info.tokenUrl} target="_blank" rel="noreferrer">
            Create one
          </a>
          . Used only for this request and never saved.
        </div>
      </div>

      {/* MODE */}
      <div className="publish-row">
        <span className="publish-label">Publish as</span>
        <div className="publish-modes">
          {MODES.map(({ id, label, icon: Icon, help }) => {
            const disabled =
              (id === "branch" || id === "fork") && !sameProvider;
            return (
              <button
                key={id}
                disabled={disabled}
                title={
                  disabled
                    ? `Only available for code imported from ${info.label}`
                    : help
                }
                className={mode === id ? "active" : ""}
                onClick={() => {
                  setMode(id);
                  setPlan(null);
                }}
              >
                <Icon size={15} />
                <b>{label}</b>
                <span>{help}</span>
              </button>
            );
          })}
        </div>
      </div>

      {showRepoName && (
        <div className="publish-row">
          <span className="publish-label">New repository</span>
          <div className="repo-input">
            <Plus size={16} />
            <input
              value={repoName}
              onChange={(e) => setRepoName(e.target.value)}
              placeholder={`${source?.name || "project"}-securepatch`}
            />
          </div>
          <label className="publish-check">
            <input
              type="checkbox"
              checked={isPrivate}
              onChange={(e) => setIsPrivate(e.target.checked)}
            />
            Private repository
          </label>
        </div>
      )}

      <label className="publish-check">
        <input
          type="checkbox"
          checked={openRequest}
          onChange={(e) => setOpenRequest(e.target.checked)}
        />
        Open a {info.request} with the Bandit + test results
      </label>

      {showUpstream && (
        <label className="publish-check warn">
          <input
            type="checkbox"
            checked={toUpstream}
            onChange={(e) => setToUpstream(e.target.checked)}
          />
          Send the {info.request} to the original project (
          {source?.path}). Its maintainers will be notified. Leave
          this off to keep the {info.request} inside your fork.
        </label>
      )}

      {(plan || result)?.profile && (
        <ProfileCard profile={(plan || result).profile} provider={info.label} />
      )}

      {plan && (
        <div className="publish-plan">
          <ShieldCheck size={16} />
          <div>
            <b>
              Will publish as{" "}
              {MODES.find((m) => m.id === plan.mode)?.label}
            </b>
            <p>{plan.reason}</p>
          </div>
        </div>
      )}

      {error && (
        <div className="error-banner" style={{ margin: "12px 0 0" }}>
          <XCircle size={15} />
          {error}
        </div>
      )}

      <div className="publish-actions">
        <button
          className="secondary-btn"
          onClick={checkAccess}
          disabled={!token.trim() || !!busy}
        >
          {busy === "check" ? (
            <RefreshCw size={15} className="spin" />
          ) : (
            <ShieldCheck size={15} />
          )}
          CHECK ACCESS
        </button>
        <button
          className="primary-btn"
          onClick={publish}
          disabled={!token.trim() || !!busy}
        >
          {busy === "publish" ? (
            <>
              <RefreshCw size={15} className="spin" />
              PUBLISHING...
            </>
          ) : (
            <>
              <Send size={15} />
              PUBLISH FIX
            </>
          )}
        </button>
      </div>

      {result && (
        <div className="publish-result">
          <div className="publish-result-head">
            <CheckCircle2 size={16} />
            Published to {result.repository.path} as{" "}
            {MODES.find((m) => m.id === result.mode)?.label}
          </div>
          <div className="publish-links">
            {result.request_url && (
              <a href={result.request_url} target="_blank" rel="noreferrer">
                <GitPullRequest size={14} /> Open {result.request_type}
                <ExternalLink size={12} />
              </a>
            )}
            <a href={result.branch_url} target="_blank" rel="noreferrer">
              <GitBranch size={14} /> {result.branch}
              <ExternalLink size={12} />
            </a>
            <a
              href={result.repository.web_url}
              target="_blank"
              rel="noreferrer"
            >
              Repository <ExternalLink size={12} />
            </a>
          </div>
          <div className="publish-clone">
            <code>{result.clone_command}</code>
            <button onClick={copyClone} title="Copy clone command">
              {copied ? <CheckCircle2 size={14} /> : <Copy size={14} />}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function ProfileCard({ profile, provider }) {
  return (
    <a
      className="publish-profile"
      href={profile.profile_url}
      target="_blank"
      rel="noreferrer"
      title={`Open ${provider} profile`}
    >
      {profile.avatar_url ? (
        <img src={profile.avatar_url} alt="" />
      ) : (
        <span className="publish-avatar">
          {profile.username?.[0]?.toUpperCase()}
        </span>
      )}
      <span>
        <b>{profile.name || profile.username}</b>
        <em>
          @{profile.username} · signed in to {provider}
        </em>
      </span>
      <ExternalLink size={13} />
    </a>
  );
}
