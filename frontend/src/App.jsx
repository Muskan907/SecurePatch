import { useMemo, useState } from "react";
import {
  Activity,
  BrainCircuit,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Bot,
  CheckCircle2,
  ChevronRight,
  Code2,
  Download,
  FileCode2,
  GitBranch,
  
  Layers3,
  Link2,
  LockKeyhole,
  Network,
  Play,
  RefreshCw,
  Search,
  Shield,
  ShieldCheck,
  Terminal,
  TestTube2,
  Upload,
  Wrench,
  XCircle,
  Zap,
} from "lucide-react";



import "./App.css";
import AILab from "./AILab";
import Evaluation from "./Evaluation";

const API = "http://127.0.0.1:8000";

const stages = [
  {
    id: "scan",
    label: "Security Scan",
    icon: Search,
  },
  {
    id: "understand",
    label: "Code Analysis",
    icon: Code2,
  },
  {
    id: "graph",
    label: "Source Graph",
    icon: Network,
  },
  {
    id: "impact",
    label: "Impact Analysis",
    icon: Activity,
  },
  {
    id: "patch",
    label: "AI Patch",
    icon: Bot,
  },
  {
    id: "sandbox",
    label: "Sandbox",
    icon: Layers3,
  },
  {
    id: "test",
    label: "Regression Test",
    icon: TestTube2,
  },
  {
    id: "security",
    label: "Security Re-scan",
    icon: ShieldCheck,
  },
  {
    id: "verdict",
    label: "Final Verdict",
    icon: CheckCircle2,
  },
];

function severityClass(severity) {
  return String(severity || "").toLowerCase();
}

function stagesIndex(id) {
  const index = stages.findIndex((stage) => stage.id === id);
  return index === -1 ? 0 : index;
}

function App() {
  const [activeNav, setActiveNav] = useState("Overview");

  /*
   * IMPORTANT:
   * repoPath is now an INTERNAL backend path.
   * The user never types this path.
   */
  const [repoPath, setRepoPath] = useState("");

  // User-facing repository inputs
  const [githubUrl, setGithubUrl] = useState("");
  const [repoFile, setRepoFile] = useState(null);
  const [importing, setImporting] = useState(false);
  const [repositoryName, setRepositoryName] = useState("");
  const [repositorySource, setRepositorySource] = useState("");

  // Main workflow states
  const [scanning, setScanning] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [validating, setValidating] = useState(false);

  const [findings, setFindings] = useState([]);

  const [summary, setSummary] = useState({
    total: 0,
    high: 0,
    medium: 0,
    low: 0,
  });

  const [selected, setSelected] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [patchData, setPatchData] = useState(null);
  const [validation, setValidation] = useState(null);
  const [downloading, setDownloading] = useState(false);
  const [stage, setStage] = useState("scan");
  const [error, setError] = useState("");

  const selectedFinding = useMemo(() => {
    return (
      findings.find(
        (finding) =>
          finding.filename === selected?.filename &&
          finding.line_number === selected?.line_number &&
          finding.test_id === selected?.test_id
      ) || selected
    );
  }, [findings, selected]);

  /*
   * =========================================================
   * GENERIC API REQUEST
   * =========================================================
   */

  async function apiRequest(endpoint, options = {}) {
    const response = await fetch(`${API}${endpoint}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });

    let data;

    try {
      data = await response.json();
    } catch {
      throw new Error("Backend returned an invalid response.");
    }

    if (!response.ok) {
      throw new Error(
        data.detail ||
          data.message ||
          `Request failed: ${response.status}`
      );
    }

    return data;
  }


    async function downloadFixedRepository() {
    if (!validation || validation.status !== "VERIFIED") {
      setError(
        "A verified patch is required before downloading."
      );
      return;
    }

    setDownloading(true);
    setError("");

    try {
      const response = await fetch(
        `${API}/api/download-fixed`
      );

      if (!response.ok) {
        let message =
          "Could not download the verified repository.";

        try {
          const data = await response.json();
          message = data.detail || message;
        } catch {
          // Non-JSON backend error
        }

        throw new Error(message);
      }

      const blob = await response.blob();

      const url =
        window.URL.createObjectURL(blob);

      const anchor =
        document.createElement("a");

      anchor.href = url;
      anchor.download =
        "securepatch_fixed_repository.zip";

      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();

      window.setTimeout(() => {
        window.URL.revokeObjectURL(url);
      }, 1000);
    } catch (error) {
      setError(
        error.message ||
          "Verified repository download failed."
      );
    } finally {
      setDownloading(false);
    }
  }
  /*
   * =========================================================
   * GITHUB REPOSITORY IMPORT
   * =========================================================
   */

  async function importGitHubRepository() {
    if (!githubUrl.trim()) {
      setError("Enter a GitHub repository URL.");
      return;
    }

    if (
      !githubUrl.includes("github.com/")
    ) {
      setError(
        "Please enter a valid GitHub repository URL."
      );
      return;
    }

    setImporting(true);
    setError("");

    try {
      const data = await apiRequest(
        "/api/repositories/github",
        {
          method: "POST",
          body: JSON.stringify({
            url: githubUrl.trim(),
          }),
        }
      );

      setRepoPath(data.repo_path || "");
      setRepositoryName(data.name || "GitHub Repository");
      setRepositorySource("GitHub");

      // Reset previous analysis
      setFindings([]);
      setSummary({
        total: 0,
        high: 0,
        medium: 0,
        low: 0,
      });
      setSelected(null);
      setAnalysis(null);
      setPatchData(null);
      setValidation(null);
      setStage("scan");
      setActiveNav("Overview");

    } catch (error) {
      setError(
        error.message ||
          "GitHub repository import failed."
      );
    } finally {
      setImporting(false);
    }
  }

  /*
   * =========================================================
   * ZIP REPOSITORY IMPORT
   * =========================================================
   */

  async function importUploadedRepository() {
    if (!repoFile) {
      setError(
        "Choose a repository ZIP file first."
      );
      return;
    }

    setImporting(true);
    setError("");

    try {
      const formData = new FormData();

      formData.append("file", repoFile);

      const response = await fetch(
        `${API}/api/repositories/upload`,
        {
          method: "POST",
          body: formData,
        }
      );

      let data;

      try {
        data = await response.json();
      } catch {
        throw new Error(
          "Backend returned an invalid response."
        );
      }

      if (!response.ok) {
        throw new Error(
          data.detail ||
            "Repository upload failed."
        );
      }

      setRepoPath(data.repo_path || "");
      setRepositoryName(
        data.name || repoFile.name
      );
      setRepositorySource("ZIP Upload");

      // Reset previous analysis
      setFindings([]);
      setSummary({
        total: 0,
        high: 0,
        medium: 0,
        low: 0,
      });
      setSelected(null);
      setAnalysis(null);
      setPatchData(null);
      setValidation(null);
      setStage("scan");
      setActiveNav("Overview");

    } catch (error) {
      setError(
        error.message ||
          "Repository upload failed."
      );
    } finally {
      setImporting(false);
    }
  }

  /*
   * =========================================================
   * SECURITY SCAN
   * =========================================================
   */

  async function scanRepository() {
    if (!repoPath) {
      setError(
        "Import a GitHub repository or upload a ZIP first."
      );
      return;
    }

    setScanning(true);
    setError("");

    setSelected(null);
    setAnalysis(null);
    setPatchData(null);
    setValidation(null);

    setStage("scan");
    setActiveNav("Overview");

    try {
      const data = await apiRequest(
        "/api/scan",
        {
          method: "POST",
          body: JSON.stringify({
            repo_path: repoPath,
          }),
        }
      );

      setFindings(data.findings || []);

      setSummary(
        data.summary || {
          total: 0,
          high: 0,
          medium: 0,
          low: 0,
        }
      );

      /*
       * Scan completed.
       * Move workflow to Code Analysis.
       */
      if (data.findings?.length) {
        setStage("understand");
      } else {
        setStage("scan");
      }

    } catch (error) {
      setError(
        error.message ||
          "Could not connect to SecurePatch backend. Start FastAPI on port 8000."
      );
    } finally {
      setScanning(false);
    }
  }

  /*
   * =========================================================
   * CODE ANALYSIS
   * =========================================================
   */

  async function analyzeFinding(
    finding = selectedFinding
  ) {
    if (!finding) {
      setError(
        "Select a vulnerability first."
      );
      return;
    }

    if (!repoPath) {
      setError(
        "Repository is not loaded."
      );
      return;
    }

    setSelected(finding);
    setAnalysis(null);
    setAnalyzing(true);
    setError("");

    setStage("understand");
    setActiveNav("Code Intelligence");

    try {
      const data = await apiRequest(
        "/api/analyze",
        {
          method: "POST",
          body: JSON.stringify({
            repo_path: repoPath,
            file_path: finding.filename,
            line: finding.line_number,
          }),
        }
      );

      setAnalysis(data);

      setStage("understand");
      setActiveNav("Code Intelligence");

    } catch (error) {
      setError(
        error.message ||
          "Code analysis failed."
      );
    } finally {
      setAnalyzing(false);
    }
  }

  /*
   * =========================================================
   * AI PATCH GENERATION
   * =========================================================
   */

async function generatePatch(model = "qwen2.5-coder") {
  if (!selectedFinding) {
    setError(
      "Please select a vulnerability first."
    );
    return;
  }

  if (!repoPath) {
    setError(
      "Repository is not loaded."
    );
    return;
  }

  setGenerating(true);
  setError("");

  setStage("patch");
  setActiveNav("AI Patch");

  try {
    const data = await apiRequest(
      "/api/generate-patch",
      {
        method: "POST",
        body: JSON.stringify({
          repo_path: repoPath,
          file_path:
            selectedFinding.filename,
          line:
            selectedFinding.line_number,
          model: model,
        }),
      }
    );

    setPatchData(data);
    setStage("patch");
    setActiveNav("AI Patch");

  } catch (error) {
    setError(
      error.message ||
        "AI patch generation failed."
    );
  } finally {
    setGenerating(false);
  }
}

  /*
   * =========================================================
   * VALIDATION
   * =========================================================
   */

  async function validatePatch() {
    if (!selectedFinding) {
      setError(
        "Select a vulnerability first."
      );
      return;
    }

    if (!patchData) {
      setError(
        "Generate an AI patch before validation."
      );
      return;
    }

    if (!repoPath) {
      setError(
        "Repository is not loaded."
      );
      return;
    }

    setValidating(true);
    setError("");

    setStage("sandbox");
    setActiveNav("Validation");

    try {
      const patch =
        patchData?.patch?.patch ||
        patchData?.patch?.function ||
        "";

      const data = await apiRequest(
        "/api/validate",
        {
          method: "POST",
          body: JSON.stringify({
            repo_path: repoPath,
            file_path:
              selectedFinding.filename,
            line:
              selectedFinding.line_number,
            patch,
          }),
        }
      );

      setValidation(data);

      if (
        data.status === "VERIFIED"
      ) {
        setStage("verdict");
      } else {
        setStage("test");
      }

      setActiveNav("Validation");

    } catch (error) {
      setError(
        error.message ||
          "Patch validation failed."
      );
    } finally {
      setValidating(false);
    }
  }

  /*
   * =========================================================
   * PIPELINE NAVIGATION
   * =========================================================
   */

  function openStage(id) {
    setStage(id);

    if (id === "scan") {
      setActiveNav("Overview");
    }

    if (id === "understand") {
      setActiveNav("Code Intelligence");
    }

    if (
      id === "graph" ||
      id === "impact"
    ) {
      setActiveNav("Source Graph");
    }

    if (id === "patch") {
      setActiveNav("AI Patch");
    }

    if (
      id === "sandbox" ||
      id === "test" ||
      id === "security" ||
      id === "verdict"
    ) {
      setActiveNav("Validation");
    }
  }

  const pipelineIndex =
    stagesIndex(stage);

  /*
   * =========================================================
   * MAIN UI
   * =========================================================
   */

  return (
    <div className="app-shell">

      {/* SIDEBAR */}
      <aside className="sidebar">

        <div className="brand">

          <div className="brand-mark">
            <Zap
              size={21}
              fill="currentColor"
            />
          </div>

          <div>
            <div className="brand-name">
              SecurePatch
            </div>

            <div className="brand-sub">
              AI SECURITY ENGINE
            </div>
          </div>

        </div>

        <div className="side-label">
          WORKSPACE
        </div>

        <nav>

          {[
            ["Overview", Activity],
            [
              "Code Intelligence",
              Code2,
            ],
            [
              "Source Graph",
              GitBranch,
            ],
            ["AI Patch", Bot],
            ["AI Lab", BrainCircuit],
            [
              "Validation",
              ShieldCheck,
            ],
            ["Evaluation", BarChart3],
          ].map(
            ([name, Icon]) => (
              <button
                key={name}
                className={`nav-item ${
                  activeNav === name
                    ? "active"
                    : ""
                }`}
                onClick={() => {
                  setActiveNav(name);

                  if (
                    name ===
                    "Overview"
                  ) {
                    setStage("scan");
                  }

                  if (
                    name ===
                    "Code Intelligence"
                  ) {
                    setStage(
                      "understand"
                    );
                  }

                  if (
                    name ===
                    "Source Graph"
                  ) {
                    setStage("graph");
                  }

                  if (
                    name ===
                    "AI Patch"
                  ) {
                    setStage("patch");
                  }

                  if (
                    name ===
                    "AI Lab"
                  ) {
                    setStage("patch");
                  }

                  if (
                    name ===
                    "Validation"
                  ) {
                    setStage("sandbox");
                  }

                  if (name === "Evaluation") {
                    setStage("evaluation");
                  }
                }}
              >
                <Icon size={18} />

                <span>
                  {name}
                </span>

                {activeNav ===
                  name && (
                  <ChevronRight
                    size={15}
                    className="nav-arrow"
                  />
                )}
              </button>
            )
          )}

        </nav>

        <div className="sidebar-bottom">

          <div className="system-card">

            <div className="system-dot" />

            <div>
              <div className="system-title">
                SYSTEM OPERATIONAL
              </div>

              <div className="system-meta">
                FastAPI · Bandit · AST
              </div>
            </div>

          </div>

          <div className="version">
            SecurePatch v1.0
          </div>

        </div>

      </aside>

      {/* MAIN */}
      <main className="main">

        {/* TOP BAR */}
        <header className="topbar">

          <div>

            <div className="eyebrow">
              SECURITY OPERATIONS /
              REPOSITORY REPAIR
            </div>

            <h1>
              {activeNav}
            </h1>

          </div>

          <div className="top-actions">

            <div className="live-status">
              <span />
              LIVE
            </div>

            <button
              className="icon-btn"
              onClick={scanRepository}
              disabled={
                !repoPath ||
                scanning ||
                importing
              }
              title="Refresh scan"
            >
              <RefreshCw
                size={17}
              />
            </button>

          </div>

        </header>

        {/* WORKFLOW */}
        {activeNav !== "Evaluation" && (
          <section className="pipeline-card">

          <div className="pipeline-head">

            <div>

              <div className="section-kicker">
                SECUREPATCH WORKFLOW
              </div>

              <h2>
                Detect → Understand →
                Repair → Verify
              </h2>

            </div>

            <div className="pipeline-counter">
              {Math.min(
                pipelineIndex + 1,
                stages.length
              )}{" "}
              / {stages.length} stages
            </div>

          </div>

          <div className="pipeline">

            {stages.map(
              (item, index) => {
                const Icon =
                  item.icon;

                const done =
                  index <
                  pipelineIndex;

                const current =
                  index ===
                  pipelineIndex;

                return (
                  <button
                    key={item.id}
                    className={`stage ${
                      done
                        ? "done"
                        : ""
                    } ${
                      current
                        ? "current"
                        : ""
                    }`}
                    onClick={() =>
                      openStage(
                        item.id
                      )
                    }
                  >

                    <div className="stage-icon">

                      {done ? (
                        <CheckCircle2
                          size={17}
                        />
                      ) : (
                        <Icon
                          size={17}
                        />
                      )}

                    </div>

                    <span>
                      {item.label}
                    </span>

                    {index <
                      stages.length -
                        1 && (
                      <div className="stage-line" />
                    )}

                  </button>
                );
              }
            )}

          </div>

        </section>
        )}

        {/* ERROR */}
        {error && (
          <div className="error-banner">

            <AlertTriangle
              size={17}
            />

            {error}

          </div>
        )}

        {/* OVERVIEW */}
        {activeNav ===
          "Overview" && (
          <Overview
            repoPath={repoPath}
            githubUrl={githubUrl}
            setGithubUrl={
              setGithubUrl
            }
            repoFile={repoFile}
            setRepoFile={
              setRepoFile
            }
            importing={importing}
            repositoryName={
              repositoryName
            }
            repositorySource={
              repositorySource
            }
            importGitHubRepository={
              importGitHubRepository
            }
            importUploadedRepository={
              importUploadedRepository
            }
            scanning={scanning}
            scanRepository={
              scanRepository
            }
            summary={summary}
            findings={findings}
            selectedFinding={
              selectedFinding
            }
            setSelected={setSelected}
            analyzeFinding={
              analyzeFinding
            }
            analysis={analysis}
            analyzing={analyzing}
          />
        )}

        {/* CODE INTELLIGENCE */}
        {activeNav ===
          "Code Intelligence" && (
          <IntelligenceView
            finding={
              selectedFinding
            }
            analysis={analysis}
            analyzing={analyzing}
            onAnalyze={
              analyzeFinding
            }
            onNext={() =>
              openStage("graph")
            }
          />
        )}

        {/* SOURCE GRAPH */}
        {activeNav ===
          "Source Graph" && (
          <>
            <GraphView
              finding={
                selectedFinding
              }
              analysis={analysis}
            />

            <ImpactSection
              finding={
                selectedFinding
              }
              analysis={analysis}
              onNext={() =>
                openStage("patch")
              }
            />
          </>
        )}

        {/* AI PATCH */}
        {activeNav ===
          "AI Patch" && (
          <PatchView
            finding={
              selectedFinding
            }
            analysis={analysis}
            patchData={patchData}
            generating={
              generating
            }
            generatePatch={
              generatePatch
            }
            onValidate={
              validatePatch
            }
          />
        )}

        {/* AI LAB */}
        {activeNav ===
          "AI Lab" && (
          <AILab
            repoPath={repoPath}
            selectedFinding={selectedFinding}
            patchData={patchData}
          />
        )}

        {/* VALIDATION */}
        {activeNav ===
          "Validation" && (
            <ValidationView
              validation={validation}
              validating={validating}
              validatePatch={validatePatch}
              downloading={downloading}
              downloadFixedRepository={downloadFixedRepository}
              stage={stage}
              onStage={openStage}
            />
        )}

        {activeNav === "Evaluation" && (
          <Evaluation />
        )}
      </main>

    </div>
  );
}

/* =========================================================
   OVERVIEW
========================================================= */

function Overview({
  repoPath,
  githubUrl,
  setGithubUrl,
  repoFile,
  setRepoFile,
  importing,
  repositoryName,
  repositorySource,
  importGitHubRepository,
  importUploadedRepository,
  scanning,
  scanRepository,
  summary,
  findings,
  selectedFinding,
  setSelected,
  analyzeFinding,
  analysis,
  analyzing,
}) {
  return (
    <>
      <section className="hero-grid">

        {/* HERO */}
        <div className="hero-card">

          <div className="hero-glow" />

          <div className="hero-content">

            <div className="hero-badge">
              <Shield size={15} />
              AI-ASSISTED
              VULNERABILITY
              REPAIR
            </div>

            <h2>
              Secure your Python
              repository.
            </h2>

            <p>
              Connect your repository,
              detect vulnerabilities,
              understand their code
              impact, generate a minimal
              security patch, and verify
              it safely in an isolated
              environment.
            </p>

            {/* =================================================
                REPOSITORY IMPORT
            ================================================= */}

            <div
              className="repository-import"
              style={{
                marginTop: "20px",
                padding: "16px",
                border:
                  "1px solid #20352a",
                background:
                  "rgba(5, 12, 9, 0.75)",
                borderRadius: "12px",
              }}
            >

              <div
                className="import-title"
                style={{
                  display: "flex",
                  alignItems:
                    "center",
                  gap: "8px",
                  color:
                    "#9ee9b8",
                  fontSize:
                    "10px",
                  fontFamily:
                    "DM Mono, monospace",
                  letterSpacing:
                    "0.12em",
                  textTransform:
                    "uppercase",
                  marginBottom:
                    "10px",
                }}
              >
                <FileCode2
                  size={16}
                />

                <span>
                  Repository Source
                </span>
              </div>

              {/* GITHUB */}
              <div
                className="github-row"
                style={{
                  display: "flex",
                  gap: "9px",
                }}
              >

                <div
                  className="repo-input"
                  style={{
                    flex: 1,
                  }}
                >

                  <GitBranch
                    size={18}
                  />

                  <input
                    value={
                      githubUrl
                    }
                    onChange={(e) =>
                      setGithubUrl(
                        e.target.value
                      )
                    }
                    placeholder="https://github.com/username/repository"
                  />

                </div>

                <button
                  className="secondary-btn"
                  onClick={
                    importGitHubRepository
                  }
                  disabled={
                    importing ||
                    !githubUrl.trim()
                  }
                >
                  {importing ? (
                    <>
                      <RefreshCw
                        size={15}
                        className="spin"
                      />

                      IMPORTING...
                    </>
                  ) : (
                    <>
                      <Link2
                        size={15}
                      />

                      IMPORT GITHUB
                    </>
                  )}
                </button>

              </div>

              {/* OR */}
              <div
                className="or-divider"
                style={{
                  display: "flex",
                  alignItems:
                    "center",
                  gap: "10px",
                  margin:
                    "13px 0",
                  color:
                    "#52655b",
                  fontSize:
                    "9px",
                  fontFamily:
                    "DM Mono, monospace",
                }}
              >
                <span
                  style={{
                    flex: 1,
                    height: "1px",
                    background:
                      "#1a2921",
                  }}
                />

                OR

                <span
                  style={{
                    flex: 1,
                    height: "1px",
                    background:
                      "#1a2921",
                  }}
                />
              </div>

              {/* ZIP */}
              <div
                className="upload-row"
                style={{
                  display: "flex",
                  gap: "9px",
                }}
              >

                <label
                  className="upload-box"
                  style={{
                    flex: 1,
                    minHeight:
                      "43px",
                    display:
                      "flex",
                    alignItems:
                      "center",
                    gap: "9px",
                    padding:
                      "0 12px",
                    border:
                      "1px dashed #31513f",
                    borderRadius:
                      "9px",
                    background:
                      "#080e0b",
                    color:
                      "#7f9489",
                    fontSize:
                      "10px",
                    cursor:
                      "pointer",
                  }}
                >

                  <Upload
                    size={18}
                  />

                  <span>
                    {repoFile
                      ? repoFile.name
                      : "Upload repository ZIP"}
                  </span>

                  <input
                    type="file"
                    accept=".zip"
                    hidden
                    onChange={(e) =>
                      setRepoFile(
                        e.target
                          .files?.[0] ||
                          null
                      )
                    }
                  />

                </label>

                <button
                  className="secondary-btn"
                  onClick={
                    importUploadedRepository
                  }
                  disabled={
                    importing ||
                    !repoFile
                  }
                >
                  {importing ? (
                    <>
                      <RefreshCw
                        size={15}
                        className="spin"
                      />

                      IMPORTING...
                    </>
                  ) : (
                    <>
                      <Upload
                        size={15}
                      />

                      IMPORT ZIP
                    </>
                  )}
                </button>

              </div>

              {/* LOADED REPOSITORY */}
              {repositoryName && (
                <div
                  className="repository-loaded"
                  style={{
                    display:
                      "flex",
                    alignItems:
                      "center",
                    gap: "10px",
                    marginTop:
                      "12px",
                    padding:
                      "10px 12px",
                    border:
                      "1px solid #245338",
                    borderRadius:
                      "8px",
                    background:
                      "#0a1810",
                    color:
                      "#7ee4a2",
                  }}
                >

                  <CheckCircle2
                    size={17}
                  />

                  <div>
                    <strong
                      style={{
                        display:
                          "block",
                        fontSize:
                          "11px",
                      }}
                    >
                      {repositoryName}
                    </strong>

                    <span
                      style={{
                        display:
                          "block",
                        marginTop:
                          "3px",
                        color:
                          "#61786a",
                        fontSize:
                          "8px",
                        fontFamily:
                          "DM Mono, monospace",
                      }}
                    >
                      {repositorySource}
                      {" "}
                      repository
                      {" "}
                      loaded
                    </span>
                  </div>

                </div>
              )}

              {/* RUN SCAN */}
              <button
                className="primary-btn scan-button"
                onClick={
                  scanRepository
                }
                disabled={
                  !repoPath ||
                  importing ||
                  scanning
                }
                style={{
                  width: "100%",
                  marginTop:
                    "12px",
                }}
              >

                {scanning ? (
                  <>
                    <RefreshCw
                      size={17}
                      className="spin"
                    />

                    SCANNING...
                  </>
                ) : (
                  <>
                    <Play
                      size={17}
                      fill="currentColor"
                    />

                    RUN SECURITY SCAN
                  </>
                )}

              </button>

            </div>

          </div>

        </div>

        {/* ENGINE STATUS */}
        <div className="architecture-card">

          <div className="section-kicker">
            ENGINE STATUS
          </div>

          <EngineRow
            icon={
              <Terminal
                size={16}
              />
            }
            label="Bandit Scanner"
            status="READY"
          />

          <EngineRow
            icon={
              <Network
                size={16}
              />
            }
            label="AST Source Graph"
            status="READY"
          />

          <EngineRow
            icon={
              <Bot
                size={16}
              />
            }
            label="AI Patch Generator"
            status="READY"
          />

          <EngineRow
            icon={
              <ShieldCheck
                size={16}
              />
            }
            label="Validation Engine"
            status="READY"
          />

        </div>

      </section>

      {/* STATS */}
      <section className="stats-grid">

        <Stat
          label="Total Findings"
          value={
            summary.total || 0
          }
          icon={AlertTriangle}
        />

        <Stat
          label="High Severity"
          value={
            summary.high || 0
          }
          icon={AlertTriangle}
          tone="high"
        />

        <Stat
          label="Medium Severity"
          value={
            summary.medium || 0
          }
          icon={Shield}
          tone="medium"
        />

        <Stat
          label="Low Severity"
          value={
            summary.low || 0
          }
          icon={Activity}
          tone="low"
        />

      </section>

      {/* FINDINGS */}
      <section className="content-grid">

        <div className="panel">

          <div className="panel-head">

            <div>

              <div className="section-kicker">
                DETECTION RESULTS
              </div>

              <h3>
                Vulnerability Explorer
              </h3>

            </div>

            <span className="count-pill">
              {findings.length}
              {" "}
              findings
            </span>

          </div>

          <div className="finding-list">

            {findings.length === 0 ? (
              <EmptyState
                onScan={
                  scanRepository
                }
                hasRepository={
                  !!repoPath
                }
              />
            ) : (
              findings.map(
                (
                  finding,
                  index
                ) => (
                  <button
                    key={`${finding.test_id}-${finding.line_number}-${index}`}
                    className={`finding ${
                      selectedFinding?.test_id ===
                        finding.test_id &&
                      selectedFinding?.line_number ===
                        finding.line_number
                        ? "selected"
                        : ""
                    }`}
                    onClick={() => {
                      setSelected(
                        finding
                      );

                      analyzeFinding(
                        finding
                      );
                    }}
                  >

                    <div
                      className={`severity-dot ${severityClass(
                        finding.issue_severity
                      )}`}
                    />

                    <div className="finding-main">

                      <div className="finding-top">

                        <span className="rule-id">
                          {
                            finding.test_id
                          }
                        </span>

                        <span
                          className={`severity ${severityClass(
                            finding.issue_severity
                          )}`}
                        >
                          {
                            finding.issue_severity
                          }
                        </span>

                      </div>

                      <div className="finding-title">
                        {
                          finding.issue_text
                        }
                      </div>

                      <div className="finding-file">
                        {
                          finding.filename
                        }
                        :
                        {
                          finding.line_number
                        }
                      </div>

                    </div>

                    <ArrowRight
                      size={17}
                    />

                  </button>
                )
              )
            )}

          </div>

        </div>

        <ContextPanel
          finding={
            selectedFinding
          }
          analysis={analysis}
          analyzing={analyzing}
          onAnalyze={
            analyzeFinding
          }
        />

      </section>
    </>
  );
}

/* =========================================================
   ENGINE ROW
========================================================= */

function EngineRow({
  icon,
  label,
  status,
}) {
  return (
    <div className="engine-row">

      <span>
        {icon}
        {label}
      </span>

      <b>
        {status}
      </b>

    </div>
  );
}

/* =========================================================
   STAT
========================================================= */

function Stat({
  label,
  value,
  icon: Icon,
  tone = "",
}) {
  return (
    <div className="stat-card">

      <div
        className={`stat-icon ${tone}`}
      >
        <Icon size={18} />
      </div>

      <div>

        <div className="stat-value">
          {value}
        </div>

        <div className="stat-label">
          {label}
        </div>

      </div>

    </div>
  );
}

/* =========================================================
   EMPTY STATE
========================================================= */

function EmptyState({
  onScan,
  hasRepository,
}) {
  return (
    <div className="empty">

      <div className="empty-icon">
        <Search size={22} />
      </div>

      <h4>
        {hasRepository
          ? "No scan results yet"
          : "Connect a repository"}
      </h4>

      <p>
        {hasRepository
          ? "Run a Bandit security scan to populate the vulnerability explorer."
          : "Import a GitHub repository or upload a ZIP file to begin."}
      </p>

      {hasRepository && (
        <button
          className="secondary-btn"
          onClick={onScan}
        >
          Run scan
        </button>
      )}

    </div>
  );
}

/* =========================================================
   CONTEXT PANEL
========================================================= */

function ContextPanel({
  finding,
  analysis,
  analyzing,
  onAnalyze,
}) {
  const tests =
    analysis?.related_tests
      ?.map(
        (test) =>
          test.name
      )
      .join(", ") || "";

  return (
    <div className="panel context-panel">

      <div className="panel-head">

        <div>

          <div className="section-kicker">
            CODE INTELLIGENCE
          </div>

          <h3>
            Selected Vulnerability
          </h3>

        </div>

        {finding && (
          <span
            className={`severity ${severityClass(
              finding.issue_severity
            )}`}
          >
            {
              finding.issue_severity
            }
          </span>
        )}

      </div>

      {!finding ? (
        <div className="context-empty">

          <Code2 size={28} />

          <h4>
            Select a finding
          </h4>

          <p>
            SecurePatch will trace
            the affected function
            and repository
            relationships.
          </p>

        </div>
      ) : (
        <>

          <div className="selected-finding">

            <div className="rule-large">
              {finding.test_id}
            </div>

            <div>

              <div className="selected-title">
                {
                  finding.issue_text
                }
              </div>

              <div className="finding-file">
                {
                  finding.filename
                }
                :
                {
                  finding.line_number
                }
              </div>

            </div>

          </div>

          {analyzing ? (
            <div className="loading-box">

              <RefreshCw
                size={18}
                className="spin"
              />

              Building code
              context...

            </div>
          ) : (
            <div className="context-grid">

              <ContextItem
                title="Affected Function"
                value={
                  analysis
                    ?.affected_function
                    ?.name ||
                  "Click analyze"
                }
              />

              <ContextItem
                title="Function Calls"
                value={
                  analysis
                    ?.function_calls
                    ?.join(", ") ||
                  "Click analyze"
                }
              />

              <ContextItem
                title="Imports"
                value={
                  analysis?.imports
                    ?.join(", ") ||
                  "Click analyze"
                }
              />

              <ContextItem
                title="Related Tests"
                value={
                  tests ||
                  "Click analyze"
                }
              />

            </div>
          )}

          <button
            className="secondary-btn wide"
            onClick={() =>
              onAnalyze(
                finding
              )
            }
            disabled={analyzing}
          >

            <Wrench size={16} />

            {analyzing
              ? "ANALYZING..."
              : "ANALYZE CODE CONTEXT"}

          </button>

        </>
      )}

    </div>
  );
}

function ContextItem({
  title,
  value,
}) {
  return (
    <div className="context-item">

      <div className="context-title">
        {title}
      </div>

      <div className="context-value">
        {value}
      </div>

    </div>
  );
}

/* =========================================================
   CODE INTELLIGENCE
========================================================= */

function IntelligenceView({
  finding,
  analysis,
  analyzing,
  onAnalyze,
  onNext,
}) {
  return (
    <div className="detail-stack">

      <div className="detail-header">

        <div>

          <div className="section-kicker">
            STAGE 02 · CODE
            UNDERSTANDING
          </div>

          <h2>
            Repository Context &
            Impact
          </h2>

          <p>
            SecurePatch identifies
            the affected function,
            calls, imports and
            tests before generating
            a patch.
          </p>

        </div>

        <div className="stage-status">
          <CheckCircle2
            size={16}
          />
          ANALYSIS ENGINE
        </div>

      </div>

      {!finding ? (
        <div className="panel">

          <EmptyState
            onScan={() => {}}
            hasRepository={false}
          />

        </div>
      ) : (
        <div className="two-col">

          <CodeCard
            finding={finding}
            analysis={analysis}
          />

          <div className="panel">

            <div className="panel-head">

              <div>

                <div className="section-kicker">
                  STATIC ANALYSIS
                </div>

                <h3>
                  Context Map
                </h3>

              </div>

            </div>

            {analyzing ? (
              <div className="loading-box">

                <RefreshCw
                  size={18}
                  className="spin"
                />

                Analyzing...

              </div>
            ) : (
              <div className="metric-list">

                <Metric
                  icon={Code2}
                  label="Affected function"
                  value={
                    analysis
                      ?.affected_function
                      ?.name ||
                    "Not detected"
                  }
                />

                <Metric
                  icon={Terminal}
                  label="Function calls"
                  value={
                    analysis
                      ?.function_calls
                      ?.join(", ") ||
                    "None"
                  }
                />

                <Metric
                  icon={FileCode2}
                  label="Imports"
                  value={
                    analysis
                      ?.imports
                      ?.join(", ") ||
                    "None"
                  }
                />

                <Metric
                  icon={TestTube2}
                  label="Related tests"
                  value={
                    analysis
                      ?.related_tests
                      ?.map(
                        (test) =>
                          test.name
                      )
                      .join(", ") ||
                    "None detected"
                  }
                />

              </div>
            )}

            <button
              className="secondary-btn wide"
              style={{
                marginTop:
                  "12px",
              }}
              onClick={() =>
                onAnalyze(
                  finding
                )
              }
              disabled={analyzing}
            >

              <Wrench size={16} />

              {analyzing
                ? "ANALYZING..."
                : "ANALYZE"}

            </button>

          </div>

        </div>
      )}

      <div
        className="panel impact-banner"
        onClick={onNext}
        style={{
          cursor: "pointer",
        }}
      >

        <div className="impact-icon">
          <Network size={21} />
        </div>

        <div>

          <div className="section-kicker">
            NEXT STAGE
          </div>

          <h3>
            Source Graph + Impact
            Analysis
          </h3>

          <p>
            The graph connects the
            vulnerable function to
            calls, dependencies and
            related tests before AI
            patch generation.
          </p>

        </div>

        <ArrowRight size={20} />

      </div>

    </div>
  );
}

/* =========================================================
   CODE CARD
========================================================= */

function CodeCard({
  finding,
  analysis,
}) {
  const functionName =
    analysis
      ?.affected_function
      ?.name ||
    "Affected function";

  return (
    <div className="panel code-card">

      <div className="code-head">

        <span>
          {finding?.filename ||
            "Python source"}
        </span>

        <span>
          PYTHON
        </span>

      </div>

      <pre>
        {analysis?.function_code ||
          `Function: ${functionName}

Finding: ${
            finding?.test_id ||
            "N/A"
          }

Line: ${
            finding?.line_number ||
            "N/A"
          }

SecurePatch will extract the actual
vulnerable function here.`}
      </pre>

      <div className="code-warning">

        <AlertTriangle
          size={15}
        />

        Target:{" "}
        {finding?.test_id ||
          "Security Finding"}

      </div>

    </div>
  );
}

/* =========================================================
   METRIC
========================================================= */

function Metric({
  icon: Icon,
  label,
  value,
}) {
  return (
    <div className="metric">

      <div className="metric-icon">
        <Icon size={16} />
      </div>

      <div>

        <span>
          {label}
        </span>

        <b>
          {value}
        </b>

      </div>

    </div>
  );
}

/* =========================================================
   SOURCE GRAPH
========================================================= */

function GraphView({
  finding,
  analysis,
}) {
  const graph =
    analysis?.graph || {};

  const edges =
    graph.edges || [];

  const callers =
    analysis?.impact
      ?.callers || [];

  const firstCall =
    analysis
      ?.function_calls?.[0] ||
    "Security-sensitive call";

  const firstTest =
    analysis
      ?.related_tests?.[0]
      ?.name ||
    callers?.[0] ||
    "Related Test";

  return (
    <div className="detail-stack">

      <div className="detail-header">

        <div>

          <div className="section-kicker">
            STAGE 03 · SEMANTIC
            NAVIGATION
          </div>

          <h2>
            Source Graph
          </h2>

          <p>
            AST-derived
            relationships used to
            understand the
            vulnerability's blast
            radius.
          </p>

        </div>

        <div className="stage-status">

          <GitBranch size={16} />

          AST GRAPH

        </div>

      </div>

      <div className="stats-grid">

        <Stat
          label="Files"
          value={
            graph.files?.length ||
            0
          }
          icon={FileCode2}
        />

        <Stat
          label="Functions"
          value={
            graph.functions
              ?.length || 0
          }
          icon={Code2}
        />

        <Stat
          label="Nodes"
          value={
            graph.nodes?.length ||
            0
          }
          icon={Network}
        />

        <Stat
          label="Edges"
          value={
            graph.edges?.length ||
            0
          }
          icon={GitBranch}
        />

      </div>

      <div className="graph-canvas">

        <div className="graph-node file">

          <FileCode2 size={18} />

          <span>
            {finding?.filename ||
              "Vulnerable File"}
          </span>

          <small>
            FILE
          </small>

        </div>

        <div className="graph-connector c1" />

        <div className="graph-node function">

          <Code2 size={18} />

          <span>
            {analysis
              ?.affected_function
              ?.name ||
              "Affected Function"}
          </span>

          <small>
            FUNCTION
          </small>

        </div>

        <div className="graph-connector c2" />

        <div className="graph-node call">

          <Terminal size={18} />

          <span>
            {firstCall}
          </span>

          <small>
            CALL
          </small>

        </div>

        <div className="graph-connector c3" />

        <div className="graph-node test">

          <TestTube2 size={18} />

          <span>
            {firstTest}
          </span>

          <small>
            DEPENDENCY / TEST
          </small>

        </div>

      </div>

      <div className="graph-legend">

        <span>
          <i className="legend-file" />
          File
        </span>

        <span>
          <i className="legend-function" />
          Function
        </span>

        <span>
          <i className="legend-call" />
          Call
        </span>

        <span>
          <i className="legend-test" />
          Test
        </span>

      </div>

      <div className="panel">

        <div className="panel-head">

          <div>

            <div className="section-kicker">
              GRAPH RELATIONSHIPS
            </div>

            <h3>
              Repository Connections
            </h3>

          </div>

          <span className="count-pill">
            {edges.length}
            {" "}
            edges
          </span>

        </div>

        <div className="metric-list">

          {edges.length === 0 ? (
            <div className="loading-box">
              No graph relationships
              available.
            </div>
          ) : (
            edges
              .slice(0, 15)
              .map(
                (
                  edge,
                  index
                ) => (
                  <div
                    className="metric"
                    key={index}
                  >

                    <div className="metric-icon">
                      <GitBranch
                        size={16}
                      />
                    </div>

                    <div>

                      <span>
                        {
                          edge.relation
                        }
                      </span>

                      <b>
                        {shorten(
                          edge.source
                        )}
                        {" → "}
                        {shorten(
                          edge.target
                        )}
                      </b>

                    </div>

                  </div>
                )
              )
          )}

        </div>

      </div>

    </div>
  );
}

/* =========================================================
   IMPACT
========================================================= */

function ImpactSection({
  finding,
  analysis,
  onNext,
}) {
  const impact =
    analysis?.impact || {};

  const callers =
    impact.callers || [];

  const relatedFiles =
    impact.related_files ||
    [];

  const dependencies =
    impact.dependencies ||
    [];

  const tests =
    analysis?.related_tests
      ?.map(
        (test) =>
          test.name
      ) || [];

  return (
    <div className="detail-stack">

      <div className="detail-header">

        <div>

          <div className="section-kicker">
            STAGE 04 · IMPACT
            ANALYSIS
          </div>

          <h2>
            Vulnerability Impact
          </h2>

          <p>
            SecurePatch checks
            callers, connected
            files, dependencies
            and tests before
            allowing an AI patch.
          </p>

        </div>

        <div className="stage-status">

          <Network size={16} />

          IMPACT MAP

        </div>

      </div>

      <div className="validation-grid">

        <ImpactCard
          title="Callers"
          items={callers}
          icon={GitBranch}
        />

        <ImpactCard
          title="Dependencies"
          items={dependencies}
          icon={Network}
        />

        <ImpactCard
          title="Connected Files"
          items={relatedFiles}
          icon={FileCode2}
        />

      </div>

      <div className="panel">

        <div className="panel-head">

          <div>

            <div className="section-kicker">
              TEST IMPACT
            </div>

            <h3>
              Related Tests
            </h3>

          </div>

          <span className="count-pill">
            {tests.length}
          </span>

        </div>

        <div className="metric-list">

          {tests.length === 0 ? (
            <div className="loading-box">
              No related tests found.
            </div>
          ) : (
            tests.map(
              (
                test,
                index
              ) => (
                <Metric
                  key={index}
                  icon={TestTube2}
                  label="Test"
                  value={test}
                />
              )
            )
          )}

        </div>

      </div>

      <div className="panel impact-banner">

        <div className="impact-icon">
          <LockKeyhole
            size={21}
          />
        </div>

        <div>

          <div className="section-kicker">
            PATCH SCOPE
          </div>

          <h3>
            Minimal security
            modification
          </h3>

          <p>
            AI is instructed to
            fix the reported
            vulnerability without
            changing tests or
            unrelated functionality.
          </p>

        </div>

        <button
          className="secondary-btn"
          onClick={onNext}
        >
          AI Patch
          <ArrowRight size={16} />
        </button>

      </div>

    </div>
  );
}

function ImpactCard({
  title,
  items,
  icon: Icon,
}) {
  return (
    <div className="panel validation-card">

      <div className="validation-icon">
        <Icon size={20} />
      </div>

      <div
        style={{
          minWidth: 0,
        }}
      >

        <div className="section-kicker">
          {title}
        </div>

        <h3>
          {items?.length || 0}
          {" "}
          connected
        </h3>

        <p>
          {items?.length
            ? items
                .slice(0, 3)
                .map(shorten)
                .join(" · ")
            : "No connections detected"}
        </p>

      </div>

    </div>
  );
}

/* =========================================================
   AI PATCH
========================================================= */

function PatchView({
  finding,
  analysis,
  patchData,
  generating,
  generatePatch,
  onValidate,
}) {
  const [selectedModel, setSelectedModel] =
    useState("qwen2.5-coder");

  return (
    <div className="detail-stack">

      <div className="detail-header">

        <div>

          <div className="section-kicker">
            STAGE 05 · AI REPAIR
          </div>


          <div
          className="panel"
          style={{
            padding: 18,
            marginTop: 16,
          }}
        >
          <div className="section-kicker">
            MODEL SELECTION
          </div>

          <h3>
            Choose AI Model
          </h3>

          <div
            style={{
              display: "flex",
              gap: 10,
              marginTop: 12,
              flexWrap: "wrap",
            }}
          >
            {[
              {
                id: "qwen2.5-coder",
                label: "Qwen2.5-Coder 7B",
              },
              {
                id: "llama3.1",
                label: "Llama 3.1 8B",
              },
              {
                id: "codestral",
                label: "Codestral 22B",
              },
            ].map((model) => (
              <button
                key={model.id}
                className={
                  selectedModel === model.id
                    ? "primary-btn"
                    : "secondary-btn"
                }
                onClick={() =>
                  setSelectedModel(model.id)
                }
              >
                {model.label}
              </button>
            ))}
          </div>

          <div
            style={{
              marginTop: 10,
              fontSize: 13,
              opacity: 0.7,
            }}
          >
            Selected model:{" "}
            <b>
              {selectedModel === "qwen2.5-coder"
                ? "Qwen2.5-Coder 7B"
                : selectedModel === "llama3.1"
                ? "Llama 3.1 8B"
                : "Codestral 22B"}
            </b>
          </div>
        </div>
          <h2>
            AI Patch Generation
          </h2>

          <p>
            Security-aware prompt
            constraints produce a
            minimal patch while
            preserving original
            behavior.
          </p>

        </div>

        <div className="stage-status mock">

          <Bot size={16} />

          {patchData?.patch?.provider
            ? patchData.patch.provider.toUpperCase()
            : "OLLAMA"}

        </div>

      </div>

      <div className="patch-layout">

        <div className="panel">

          <div className="panel-head">

            <div>

              <div className="section-kicker">
                GENERATED PATCH
              </div>

              <h3>
                Before / After
              </h3>

            </div>

          </div>

          {!patchData ? (
            <div className="empty">

              <Bot size={25} />

              <h4>
                AI patch not generated
              </h4>

              <p>
                SecurePatch will use
                the vulnerability,
                code context, source
                graph and impact
                analysis to build the
                patch prompt.
              </p>

              <button
                className="primary-btn"
                onClick={() =>
                  generatePatch(selectedModel)
                }
                disabled={
                  generating ||
                  !finding
                }
              >

                {generating ? (
                  <RefreshCw
                    size={16}
                    className="spin"
                  />
                ) : (
                  <Bot size={16} />
                )}

                {generating
                  ? "GENERATING..."
                  : `GENERATE WITH ${
                      selectedModel === "qwen2.5-coder"
                        ? "QWEN"
                        : selectedModel === "llama3.1"
                        ? "LLAMA"
                        : "CODESTRAL"
                    }`}

              </button>

            </div>
          ) : (
            <>

              <div className="diff">

                <div className="diff-line remove">

                  −{" "}

                  {patchData.patch
                    ?.original ||
                    "Original function"}

                </div>

                <div className="diff-line add">

                  +{" "}

                  {patchData.patch
                    ?.patch ||
                    patchData.patch
                      ?.function ||
                    "Generated patch"}

                </div>

              </div>

              <div className="guardrails">

                <span>
                  <CheckCircle2
                    size={14}
                  />
                  Minimal change
                </span>

                <span>
                  <CheckCircle2
                    size={14}
                  />
                  Tests untouched
                </span>

                <span>
                  <CheckCircle2
                    size={14}
                  />
                  No unrelated code
                </span>

                <span>
                  <CheckCircle2
                    size={14}
                  />
                  Security target
                  addressed
                </span>

              </div>

            </>
          )}

        </div>

        <div className="panel">

          <div className="section-kicker">
            REPAIR PLAN
          </div>

          <div className="plan">

            <PlanStep
              n="01"
              title="Retrieve context"
              active={!!analysis}
            />

            <PlanStep
              n="02"
              title="Build security prompt"
              active={!!patchData}
            />

            <PlanStep
              n="03"
              title="Generate minimal patch"
              active={!!patchData}
            />

            <PlanStep
              n="04"
              title="Validate in sandbox"
              active={false}
            />

          </div>

          {patchData && (
            <>

              <div className="context-item">

                <div className="context-title">
                  PROVIDER
                </div>

                <div className="context-value">
                  {patchData.patch
                    ?.provider ||
                    "mock"}
                </div>

              </div>

              <div
                className="context-item"
                style={{
                  marginTop:
                    "8px",
                }}
              >

                <div className="context-title">
                  MODEL
                </div>

                <div className="context-value">
                  {patchData.patch
                    ?.model ||
                    "securepatch-mock"}
                </div>

              </div>

              <button
                className="primary-btn wide"
                style={{
                  marginTop:
                    "14px",
                }}
                onClick={
                  onValidate
                }
              >

                <LockKeyhole
                  size={16}
                />

                APPLY & VALIDATE
              </button>

            </>
          )}

        </div>

      </div>

      {patchData?.prompt && (
        <div className="panel">

          <div className="section-kicker">
            SECURITY-AWARE PROMPT
          </div>

          <pre
            style={{
              whiteSpace:
                "pre-wrap",
              color:
                "#9fb1a7",
              fontSize:
                "10px",
              lineHeight:
                "1.7",
              fontFamily:
                "DM Mono, monospace",
            }}
          >
            {
              patchData.prompt
            }
          </pre>

        </div>
      )}

    </div>
  );
}

function PlanStep({
  n,
  title,
  active,
}) {
  return (
    <div
      className={`plan-step ${
        active
          ? "active"
          : ""
      }`}
    >

      <span>
        {n}
      </span>

      <b>
        {title}
      </b>

      {active ? (
        <CheckCircle2
          size={15}
        />
      ) : (
        <ChevronRight
          size={15}
        />
      )}

    </div>
  );
}

/* =========================================================
   VALIDATION
========================================================= */

function ValidationView({
  validation,
  validating,
  validatePatch,
  downloading,
  downloadFixedRepository,
  stage,
  onStage,
}) {
  const regression =
    validation?.regression;

  const security =
    validation?.security;

  const verified =
    validation?.status ===
    "VERIFIED";

  return (
    <div className="detail-stack">

      <div className="detail-header">

        <div>

          <div className="section-kicker">
            STAGES 06–09 · VERIFY
          </div>

          <h2>
            Sandbox & Validation
          </h2>

          <p>
            Every generated patch
            is tested separately
            before a final security
            verdict.
          </p>

        </div>

        <div className="stage-status">

          <ShieldCheck
            size={16}
          />

          SAFE VALIDATION

        </div>

      </div>

      <div className="validation-grid">

        <ValidationCard
          icon={Layers3}
          title="Sandbox"
          status={
            validation
              ? "PATCH APPLIED"
              : "READY"
          }
          text={
            validation?.sandbox
              ?.path ||
            "Repository copy isolates the generated patch from the original source."
          }
        />

        <ValidationCard
          icon={TestTube2}
          title="Regression Tests"
          status={
            regression
              ? regression.passed
                ? "PASSED"
                : "FAILED"
              : "READY"
          }
          text={
            regression
              ? `${
                  regression.passed_count ||
                  0
                } passed · ${
                  regression.failed_count ||
                  0
                } failed`
              : "pytest checks that existing functionality remains intact."
          }
        />

        <ValidationCard
          icon={ShieldCheck}
          title="Security Re-scan"
          status={
            security
              ? security.passed
                ? "PASSED"
                : "FAILED"
              : "READY"
          }
          text={
            security
              ? `${
                  security.findings_after ||
                  0
                } findings after patch`
              : "Bandit verifies whether the target vulnerability remains."
          }
        />

      </div>

      {validation && (
        <>

          {/* PYTEST */}
          <div className="panel">

            <div className="panel-head">

              <div>

                <div className="section-kicker">
                  REGRESSION TEST OUTPUT
                </div>

                <h3>
                  pytest
                </h3>

              </div>

              <span
                className={`severity ${
                  regression?.passed
                    ? "low"
                    : "high"
                }`}
              >
                {regression?.passed
                  ? "PASSED"
                  : "FAILED"}
              </span>

            </div>

            <pre
              style={{
                whiteSpace:
                  "pre-wrap",
                background:
                  "#080e0b",
                border:
                  "1px solid #18271f",
                borderRadius:
                  "9px",
                padding:
                  "14px",
                color:
                  "#8ea197",
                fontSize:
                  "10px",
                lineHeight:
                  "1.6",
              }}
            >
              {regression?.output ||
                "No pytest output."}
            </pre>

          </div>

          {/* BANDIT */}
          <div className="panel">

            <div className="panel-head">

              <div>

                <div className="section-kicker">
                  SECURITY RE-SCAN OUTPUT
                </div>

                <h3>
                  Bandit
                </h3>

              </div>

              <span
                className={`severity ${
                  security?.passed
                    ? "low"
                    : "high"
                }`}
              >
                {security?.passed
                  ? "PASSED"
                  : "FAILED"}
              </span>

            </div>

            <pre
              style={{
                whiteSpace:
                  "pre-wrap",
                background:
                  "#080e0b",
                border:
                  "1px solid #18271f",
                borderRadius:
                  "9px",
                padding:
                  "14px",
                color:
                  "#8ea197",
                fontSize:
                  "10px",
                lineHeight:
                  "1.6",
              }}
            >
              {security?.output ||
                "No Bandit output."}
            </pre>

            <div
              className="code-warning"
              style={{
                marginTop:
                  "10px",
              }}
            >

              {security?.target_removed ? (
                <>
                  <CheckCircle2
                    size={15}
                  />

                  Target vulnerability
                  removed
                </>
              ) : (
                <>
                  <XCircle
                    size={15}
                  />

                  Target vulnerability
                  still present
                </>
              )}

            </div>

          </div>

        </>
      )}

      {!validation && (
        <div className="panel">

          <div className="empty">

            <ShieldCheck
              size={28}
            />

            <h4>
              Validation is ready
            </h4>

            <p>
              Generate an AI patch
              first, then validate it
              inside the isolated
              sandbox.
            </p>

            <button
              className="primary-btn"
              onClick={
                validatePatch
              }
              disabled={
                validating
              }
            >

              {validating ? (
                <RefreshCw
                  size={17}
                  className="spin"
                />
              ) : (
                <Play
                  size={17}
                  fill="currentColor"
                />
              )}

              {validating
                ? "VALIDATING..."
                : "VALIDATE PATCH"}

            </button>

          </div>

        </div>
      )}

      {/* FINAL VERDICT */}
      {validation && (
        <div
          className="verdict-card"
          style={{
            borderColor:
              verified
                ? "#28583e"
                : "#54292a",
          }}
        >

          <div
            className="verdict-icon"
            style={{
              color:
                verified
                  ? "#79e5a0"
                  : "#ff7777",
            }}
          >

            {verified ? (
              <CheckCircle2
                size={30}
              />
            ) : (
              <XCircle
                size={30}
              />
            )}

          </div>

          <div>

            <div className="section-kicker">
              FINAL VERDICT
            </div>

            <h2>
              {verified
                ? "SECURE PATCH VERIFIED"
                : "PATCH REJECTED"}
            </h2>

            <p>
              {verified
                ? "Regression tests and security validation both passed."
                : "The patch did not pass all required validation checks."}
            </p>

          </div>

          <div className="verdict-state">
            {validation.status ||
              "PENDING"}
          </div>

        </div>
      )}

      {/* VERIFIED DOWNLOAD */}
      {verified && (
        <div
          className="panel"
          style={{
            marginTop: "18px",
            borderColor: "#28583e",
          }}
        >
          <div className="panel-head">
            <div>
              <div className="section-kicker">
                VERIFIED ARTIFACT
              </div>
              <h3>Download Fixed Repository</h3>
            </div>

            <div
              className="stage-status"
              style={{ color: "#79e5a0" }}
            >
              <CheckCircle2 size={15} />
              VERIFIED
            </div>
          </div>

          <p
            style={{
              color: "#82958a",
              fontSize: "11px",
              lineHeight: "1.7",
              margin: "4px 0 14px",
            }}
          >
            The patch passed regression testing and
            security re-scan. Download the verified
            repository as a ZIP archive.
          </p>

          <button
            className="primary-btn wide"
            onClick={downloadFixedRepository}
            disabled={downloading}
          >
            {downloading ? (
              <>
                <RefreshCw size={16} className="spin" />
                PREPARING DOWNLOAD...
              </>
            ) : (
              <>
                <Download size={16} />
                DOWNLOAD VERIFIED REPOSITORY
              </>
            )}
          </button>
        </div>
      )}

      {/* VALIDATION PIPELINE */}
      {validation && (
        <div
          className="pipeline-card"
          style={{
            marginTop:
              "2px",
          }}
        >

          <div className="pipeline-head">

            <div>

              <div className="section-kicker">
                VALIDATION PIPELINE
              </div>

              <h2>
                Sandbox → pytest →
                Bandit → Verdict
              </h2>

            </div>

          </div>

          <div className="pipeline">

            {[
              [
                "sandbox",
                "Sandbox",
                Layers3,
              ],
              [
                "test",
                "Regression Test",
                TestTube2,
              ],
              [
                "security",
                "Security Re-scan",
                ShieldCheck,
              ],
              [
                "verdict",
                "Final Verdict",
                CheckCircle2,
              ],
            ].map(
              (
                [id, label, Icon],
                index
              ) => (
                <button
                  key={id}
                  className={`stage ${
                    stage === id
                      ? "current"
                      : ""
                  } ${
                    stagesIndex(
                      stage
                    ) >
                    stagesIndex(id)
                      ? "done"
                      : ""
                  }`}
                  onClick={() =>
                    onStage(id)
                  }
                >

                  <div className="stage-icon">

                    {stagesIndex(
                      stage
                    ) >
                    stagesIndex(
                      id
                    ) ? (
                      <CheckCircle2
                        size={17}
                      />
                    ) : (
                      <Icon
                        size={17}
                      />
                    )}

                  </div>

                  <span>
                    {label}
                  </span>

                  {index < 3 && (
                    <div className="stage-line" />
                  )}

                </button>
              )
            )}

          </div>

        </div>
      )}

    </div>
  );
}

function ValidationCard({
  icon: Icon,
  title,
  status,
  text,
}) {
  return (
    <div className="panel validation-card">

      <div className="validation-icon">
        <Icon size={20} />
      </div>

      <div>

        <div className="section-kicker">
          {title}
        </div>

        <h3>
          {status}
        </h3>

        <p>
          {text}
        </p>

      </div>

    </div>
  );
}

/* =========================================================
   UTILITY
========================================================= */

function shorten(
  value,
  max = 65
) {
  if (!value) {
    return "N/A";
  }

  const text = String(value);

  if (text.length <= max) {
    return text;
  }

  return `${text.slice(
    0,
    max
  )}...`;
}

export default App;
