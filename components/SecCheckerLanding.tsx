"use client";

import { useState } from "react";

type View = "developer" | "researcher";

const GITHUB = "https://github.com/vishnu-77/secchecker";
const PYPI = "https://pypi.org/project/secchecker/";

const surfaces = [
  ["Prompt & context", "User-controlled data entering privileged prompts, delimiter manipulation, instruction overrides and selected sensitive-context flows."],
  ["RAG boundaries", "Retrieved files, database results and environment-derived content crossing into trusted model context."],
  ["MCP & tool trust", "Poisoned descriptions/docstrings, untrusted metadata, tool-result re-entry and selected remote MCP configuration risks."],
  ["Model output", "Model or tool output reaching eval, exec, subprocess, shell or other consequential execution sinks."],
  ["Agent memory", "Untrusted input persisted directly into memory, long-term state or selected vector-store writes."],
  ["AI credentials", "Selected provider credential relationships using Python structure and usage context, not only token-shaped regexes."]
] as const;

export function SecCheckerLanding() {
  const [view, setView] = useState<View>("developer");

  return (
    <div className="site">
      <header className="topbar">
        <div className="topbar-inner">
          <a href="#top" className="wordmark" aria-label="secchecker home"><img src="/secchecker-mark.svg" alt="" /><span>secchecker</span></a>
          <nav className="navlinks"><a href="#how">How it works</a><a href="#coverage">Coverage</a><a href="#evidence">Evidence</a></nav>
          <div className="top-actions">
            <div className="view-toggle" role="group" aria-label="Audience view">
              <button className={view === "developer" ? "active" : ""} onClick={() => setView("developer")}>Developer</button>
              <button className={view === "researcher" ? "active" : ""} onClick={() => setView("researcher")}>Researcher</button>
            </div>
            <a className="small-button" href={GITHUB}>GitHub</a>
          </div>
        </div>
      </header>

      <main id="top">
        <section className="hero section-rule">
          <div className="grid-bg" aria-hidden="true" />
          <div className="shell hero-grid">
            <div className="hero-copy">
              <div className="brand-line"><img src="/secchecker-mark.svg" alt="SecChecker mark" /><div><span className="eyebrow">TRUST BOUNDARIES FOR AI</span><span className="brand-support">Local analysis · No LLM judge · Zero runtime dependencies</span></div></div>
              <h1>Catch risky AI trust-boundary crossings before they ship.</h1>
              <p className="lead">SecChecker is a lightweight static analyser for AI, LLM, agent and MCP code paths. It inspects the places where untrusted context can become privileged instructions, tool authority, persistent memory or consequential execution.</p>
              <div className="hero-actions"><a className="button primary" href="#quickstart">Scan a repository</a><a className="button" href={GITHUB}>View source</a></div>
              <div className="install-panel">
                <div><span>$</span><code>pip install secchecker</code></div>
                <div><span>$</span><code>secchecker . --type llm</code></div>
              </div>
            </div>
            <BoundaryPanel />
          </div>
        </section>

        {view === "developer" ? <DeveloperView /> : <ResearcherView />}

        <section id="coverage" className="section-rule">
          <div className="shell">
            <Heading eyebrow="DETECTION SURFACES" title="AI-specific focus out of the box." copy="SecChecker complements mature SAST, secret scanners, runtime controls, code review and red-team testing. It does not claim whole-program semantic understanding." />
            <div className="surface-grid">
              {surfaces.map(([title, copy], index) => <article key={title} className="surface-card"><span className="index">0{index + 1}</span><h3>{title}</h3><p>{copy}</p></article>)}
            </div>
          </div>
        </section>

        <section id="evidence" className="section-rule">
          <div className="shell evidence-grid">
            <div><Heading eyebrow="EVALUATION" title="Show the evidence, including where it fails." copy="The current v0.5.0 benchmark separates regression fixtures from adversarial and benign-realistic cases. Regression success is not presented as real-world accuracy." /><p className="caveat">NO FINDINGS ≠ SECURE APPLICATION</p></div>
            <div className="benchmark">
              <Metric label="Known vulnerable regression fixtures" value="23 / 23" note="detected" />
              <Metric label="Paired safe regression fixtures" value="23 / 23" note="clean" />
              <Metric label="Adversarial variants" value="4 / 14" note="detected" />
              <Metric label="Adversarial recall" value="28.57%" note="current corpus" />
              <Metric label="Performance fixture" value="127.5" note="files/sec at 1,600 files" />
            </div>
          </div>
        </section>

        <section className="final-cta">
          <div className="shell final-inner"><div><span className="eyebrow">OPEN SOURCE · MIT</span><h2>Inspect the checks. Reproduce the benchmark. Add a detection.</h2></div><div className="hero-actions"><a className="button primary" href={GITHUB}>Open GitHub</a><a className="button" href={PYPI}>View PyPI</a></div></div>
        </section>
      </main>

      <footer><div className="shell footer-inner"><div className="wordmark"><img src="/secchecker-mark.svg" alt="" /><span>secchecker</span></div><div><a href={`${GITHUB}/blob/main/docs/RULES.md`}>Rules</a><a href={`${GITHUB}/blob/main/docs/EVALUATION.md`}>Evaluation</a><a href={`${GITHUB}/blob/main/THREAT_MODEL.md`}>Threat model</a></div></div></footer>
    </div>
  );
}

function BoundaryPanel() {
  const rows = [
    ["user content", "system instructions", "Prompt Injection via f-string", "HIGH"],
    ["tool metadata", "agent instructions", "Poisoned Tool Description", "HIGH"],
    ["tool result", "shell command", "Tool Call Output Executed Directly", "CRITICAL"]
  ] as const;
  return <aside className="boundary-panel"><div className="panel-head"><span className="eyebrow">TRUST-BOUNDARY INSPECTION</span><span className="status">LOCAL</span></div><div className="scan-window">{rows.map(([source,target,finding,severity])=><div className="boundary-row" key={finding}><div className="transition"><span>{source}</span><b>→</b><span>{target}</span></div><div className="finding"><span>{finding}</span><strong className={severity === "CRITICAL" ? "critical" : "high"}>{severity}</strong></div></div>)}</div><p className="panel-note">Source inspection, not runtime interception. A selected finding is not necessarily the only finding in a report.</p></aside>;
}

function DeveloperView() {
  return <>
    <section id="how" className="section-rule"><div className="shell"><Heading eyebrow="HOW IT WORKS" title="Inspect code before deployment." copy="Deterministic pattern analysis and Python AST checks feed one normalised finding model with severity and security taxonomy metadata where applicable." /><div className="process"><Step n="01" title="Discover" copy="Walk the source tree and select supported code surfaces."/><Step n="02" title="Analyse" copy="Run pattern checks plus Python structural analysis and limited taint tracking."/><Step n="03" title="Normalise" copy="Produce findings with severity, CWE and OWASP/LLM metadata where applicable."/><Step n="04" title="Report" copy="Emit CLI, JSON, SARIF, Markdown, HTML or XML for local and CI workflows."/></div></div></section>
    <section id="quickstart" className="section-rule"><div className="shell quick-grid"><Heading eyebrow="QUICKSTART" title="Two commands to the first scan." copy="Analysis stays local. Source code is not sent to an LLM or external analysis service."/><div className="codebox"><pre><code>{`pip install secchecker\n\n# AI / agent / LLM / MCP surfaces\nsecchecker . --type llm\n\n# SARIF for code scanning\nsecchecker . --type llm --format sarif --output secchecker.sarif`}</code></pre><div className="formats">json · md · xml · sarif · html</div></div></div></section>
  </>;
}

function ResearcherView() {
  return <section id="how" className="section-rule"><div className="shell"><Heading eyebrow="RESEARCH VIEW" title="A bounded static-analysis system, not a universal AI-security claim." copy="The implementation intentionally exposes where deterministic analysis succeeds and where paraphrase, dataflow complexity and runtime authority exceed its current model." /><div className="research-grid"><article><h3>Method</h3><p>Pattern analysis, Python AST structure and limited taint tracking are evaluated against paired vulnerable/safe fixtures, adversarial variants and performance fixtures.</p></article><article><h3>Boundaries</h3><p>No whole-program interprocedural analysis, no runtime enforcement, no LLM judge and no claim that a clean scan proves security.</p></article><article><h3>Open direction</h3><p>Deeper framework source/sink packs, stronger dataflow, adversarial generalisation and clearer links between static trust transitions and runtime authority controls.</p></article></div><div className="text-links"><a href={`${GITHUB}/blob/main/bench/methodology.md`}>Benchmark methodology →</a><a href={`${GITHUB}/blob/main/docs/EVALUATION.md`}>Evaluation details →</a><a href={`${GITHUB}/blob/main/THREAT_MODEL.md`}>Threat model →</a></div></div></section>;
}

function Heading({ eyebrow, title, copy }: { eyebrow: string; title: string; copy: string }) {
  return <div className="heading"><span className="eyebrow">{eyebrow}</span><h2>{title}</h2><p>{copy}</p></div>;
}

function Step({ n, title, copy }: { n: string; title: string; copy: string }) {
  return <article className="step"><span className="index">{n}</span><h3>{title}</h3><p>{copy}</p></article>;
}

function Metric({ label, value, note }: { label: string; value: string; note: string }) {
  return <div className="metric"><span>{label}</span><strong>{value}</strong><small>{note}</small></div>;
}
