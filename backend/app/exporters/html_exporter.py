"""
Contract 04, 05 & 07 Standalone Single-File Interactive HTML Report Exporter.
Zero CDN dependencies, fully embedded dark-theme Cyber SOC dashboard styling.
"""

from __future__ import annotations
import html
from typing import Optional
from app.core.models import ScanJob, Severity, mask_secret, sanitize_sensitive_text


def _safe_html(value: object) -> str:
    """Sanitize untrusted evidence before HTML escaping and rendering."""
    return html.escape(sanitize_sensitive_text(str(value)) or "")


def export_scan_to_html(scan_job: ScanJob) -> str:
    """
    Generates a standalone, interactive HTML security assessment report with zero external CDN dependencies.
    """
    summary = scan_job.summary
    target = scan_job.target
    grade = summary.overall_security_grade if summary else "N/A"
    score = f"{summary.weighted_score:.1f}" if summary else "0.0"

    grade_colors = {
        "A+": "#10b981",
        "A": "#10b981",
        "B": "#3b82f6",
        "C": "#eab308",
        "D": "#f97316",
        "F": "#ef4444",
        "N/A": "#64748b",
    }
    badge_bg = grade_colors.get(grade, "#64748b")

    started_str = scan_job.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan_job.started_at else "N/A"
    duration_str = f"{summary.duration_seconds:.2f}s" if (summary and summary.duration_seconds is not None) else "N/A"

    findings_html_list = []
    for idx, f in enumerate(scan_job.findings, start=1):
        sev_colors = {
            Severity.CRITICAL: ("#ef4444", "#450a0a"),
            Severity.HIGH: ("#f97316", "#431407"),
            Severity.MEDIUM: ("#eab308", "#422006"),
            Severity.LOW: ("#3b82f6", "#172554"),
            Severity.INFO: ("#06b6d4", "#083344"),
        }
        fg_col, bg_col = sev_colors.get(f.severity, ("#94a3b8", "#1e293b"))

        cat = str(f.category or "").lower()
        chk = str(f.check_id or "").lower()
        raw_obs = sanitize_sensitive_text(f.evidence.observed_value) or ""
        if "secret" in cat or "secret" in chk or "key" in cat:
            raw_obs = mask_secret(f.evidence.observed_value)

        ev_loc = _safe_html(f.evidence.location)
        ev_obs = _safe_html(raw_obs)
        ev_exp = _safe_html(f.evidence.expected_value or "Secure default")
        remed_desc = _safe_html(f.remediation)
        desc = _safe_html(f.description)
        impact = _safe_html(f.impact)

        code_snippet_html = ""
        if f.remediation_code_snippet:
            snip_esc = _safe_html(f.remediation_code_snippet)
            code_snippet_html = f"""
            <div class="code-block-container">
              <div class="code-header">
                <span>Remediation Fix</span>
                <button class="btn-copy" onclick="copySnippet('snippet-{idx}')">Copy</button>
              </div>
              <pre id="snippet-{idx}"><code>{snip_esc}</code></pre>
            </div>
            """

        cwe_html = f'<span class="meta-tag">{_safe_html(f.cwe_id)}</span>' if f.cwe_id else ""
        owasp_html = f'<span class="meta-tag">{_safe_html(f.owasp_category)}</span>' if f.owasp_category else ""
        nist_html = f'<span class="meta-tag">{_safe_html(f.nist_control)}</span>' if f.nist_control else ""

        card_html = f"""
        <div class="finding-card severity-{f.severity.value.lower()}" id="finding-{idx}">
          <div class="finding-header" onclick="toggleCard('{idx}')">
            <div class="finding-title-group">
              <span class="severity-badge" style="color: {fg_col}; background-color: {bg_col};">{f.severity.value}</span>
              <span class="check-id">{_safe_html(f.check_id)}</span>
              <h3 class="finding-title">{_safe_html(f.title)}</h3>
            </div>
            <div class="finding-header-meta">
              <span class="cvss-badge">CVSS {f.cvss_score:.1f}</span>
              <span class="chevron" id="chevron-{idx}">▼</span>
            </div>
          </div>
          <div class="finding-body" id="body-{idx}">
            <div class="tags-row">
              {cwe_html}
              {owasp_html}
              {nist_html}
              <span class="meta-tag engine-tag">{_safe_html(f.engine)}</span>
            </div>
            
            <p class="finding-desc"><strong>Description:</strong> {desc}</p>
            <p class="finding-impact"><strong>Impact:</strong> {impact}</p>

            <div class="evidence-box">
              <h4>Evidence & Location</h4>
              <div class="evidence-row">
                <span class="ev-label">Location:</span>
                <code>{ev_loc}</code>
              </div>
              <div class="evidence-row">
                <span class="ev-label">Observed:</span>
                <code class="obs-code">{ev_obs}</code>
              </div>
              <div class="evidence-row">
                <span class="ev-label">Expected:</span>
                <code class="exp-code">{ev_exp}</code>
              </div>
            </div>

            <div class="remediation-box">
              <h4>Remediation Guidance</h4>
              <p>{remed_desc}</p>
              {code_snippet_html}
            </div>
          </div>
        </div>
        """
        findings_html_list.append(card_html)

    findings_content = "\n".join(findings_html_list) if findings_html_list else """
    <div class="no-findings">
      <div class="checkmark">✓</div>
      <h3>Zero Vulnerabilities Detected</h3>
      <p>Target passed all automated security checks without any findings.</p>
    </div>
    """

    crit_cnt = summary.critical_count if summary else 0
    high_cnt = summary.high_count if summary else 0
    med_cnt = summary.medium_count if summary else 0
    low_cnt = summary.low_count if summary else 0
    info_cnt = summary.info_count if summary else 0

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Assessment Report - {_safe_html(target.name)}</title>
  <style>
    :root {{
      --bg-dark: #07090e;
      --card-bg: #0e131f;
      --card-hover: #131a2b;
      --border-color: #1c2438;
      --text-main: #e2e8f0;
      --text-muted: #94a3b8;
      --accent-cyan: #06b6d4;
      --accent-emerald: #10b981;
      --accent-red: #ef4444;
      --accent-orange: #f97316;
      --accent-yellow: #eab308;
      --accent-blue: #3b82f6;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background-color: var(--bg-dark);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
      line-height: 1.6;
      padding: 30px 20px;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    
    /* Top Header */
    .header-panel {{
      background-color: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 20px;
    }}
    .header-title h1 {{ font-size: 24px; color: #ffffff; margin-bottom: 6px; }}
    .header-title .target-val {{ color: var(--accent-cyan); font-family: monospace; font-size: 15px; }}
    .header-meta {{ display: flex; gap: 20px; color: var(--text-muted); font-size: 13px; }}
    
    /* Scorecard Panel */
    .scorecard-panel {{
      display: grid;
      grid-template-columns: 240px 1fr;
      gap: 24px;
      margin-bottom: 24px;
    }}
    @media(max-width: 800px) {{
      .scorecard-panel {{ grid-template-columns: 1fr; }}
    }}
    .grade-card {{
      background-color: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 24px;
      text-align: center;
      display: flex;
      flex-direction: column;
      justify-content: center;
      align-items: center;
    }}
    .grade-badge {{
      font-size: 56px;
      font-weight: 800;
      line-height: 1;
      margin-bottom: 8px;
    }}
    .score-text {{ font-size: 18px; color: var(--text-muted); }}
    .score-text strong {{ color: #ffffff; font-size: 22px; }}
    
    .stats-card {{
      background-color: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 12px;
      padding: 24px;
      display: flex;
      flex-direction: column;
      justify-content: space-around;
    }}
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(110px, 1fr));
      gap: 12px;
    }}
    .stat-pill {{
      background-color: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 12px;
      text-align: center;
    }}
    .stat-count {{ font-size: 24px; font-weight: 700; display: block; }}
    .stat-label {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}

    /* Filters */
    .filter-bar {{
      display: flex;
      gap: 10px;
      margin-bottom: 20px;
      flex-wrap: wrap;
    }}
    .filter-btn {{
      background-color: var(--card-bg);
      border: 1px solid var(--border-color);
      color: var(--text-muted);
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 13px;
      transition: all 0.2s;
    }}
    .filter-btn:hover, .filter-btn.active {{
      background-color: #1e293b;
      color: #ffffff;
      border-color: var(--accent-cyan);
    }}

    /* Findings Cards */
    .finding-card {{
      background-color: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 10px;
      margin-bottom: 16px;
      overflow: hidden;
      transition: border-color 0.2s;
    }}
    .finding-card:hover {{ border-color: #334155; }}
    .finding-header {{
      padding: 16px 20px;
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
      background-color: rgba(255, 255, 255, 0.01);
    }}
    .finding-title-group {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
    .severity-badge {{
      padding: 4px 10px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.5px;
    }}
    .check-id {{ font-family: monospace; font-size: 12px; color: var(--text-muted); }}
    .finding-title {{ font-size: 16px; color: #ffffff; }}
    .finding-header-meta {{ display: flex; align-items: center; gap: 12px; }}
    .cvss-badge {{
      background-color: #1e293b;
      color: var(--accent-cyan);
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
    }}
    .chevron {{ color: var(--text-muted); font-size: 12px; transition: transform 0.2s; }}
    .chevron.open {{ transform: rotate(180deg); }}

    .finding-body {{ padding: 20px; border-top: 1px solid var(--border-color); display: none; }}
    .finding-body.open {{ display: block; }}

    .tags-row {{ display: flex; gap: 8px; margin-bottom: 14px; flex-wrap: wrap; }}
    .meta-tag {{
      background-color: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 11px;
      color: var(--text-muted);
    }}
    .engine-tag {{ color: var(--accent-cyan); border-color: rgba(6, 182, 212, 0.3); }}

    .finding-desc, .finding-impact {{ margin-bottom: 14px; color: #cbd5e1; font-size: 14px; }}
    
    .evidence-box, .remediation-box {{
      background-color: rgba(0, 0, 0, 0.2);
      border: 1px solid var(--border-color);
      border-radius: 8px;
      padding: 14px;
      margin-top: 14px;
    }}
    .evidence-box h4, .remediation-box h4 {{
      font-size: 13px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--accent-cyan);
      margin-bottom: 10px;
    }}
    .evidence-row {{ margin-bottom: 8px; font-size: 13px; }}
    .ev-label {{ color: var(--text-muted); width: 80px; display: inline-block; }}
    code {{ font-family: monospace; background-color: #1e293b; padding: 2px 6px; border-radius: 4px; color: #f8fafc; font-size: 12px; }}
    .obs-code {{ color: var(--accent-red); }}
    .exp-code {{ color: var(--accent-emerald); }}

    .code-block-container {{ margin-top: 10px; background-color: #05070a; border-radius: 6px; border: 1px solid var(--border-color); overflow: hidden; }}
    .code-header {{ display: flex; justify-content: space-between; padding: 6px 12px; background-color: #0f172a; font-size: 11px; color: var(--text-muted); }}
    .btn-copy {{ background: none; border: none; color: var(--accent-cyan); cursor: pointer; font-size: 11px; }}
    .btn-copy:hover {{ text-decoration: underline; }}
    pre {{ padding: 12px; overflow-x: auto; font-family: monospace; font-size: 12px; color: #38bdf8; }}

    .no-findings {{
      text-align: center;
      padding: 60px 20px;
      background-color: var(--card-bg);
      border: 1px solid var(--border-color);
      border-radius: 12px;
    }}
    .checkmark {{ font-size: 48px; color: var(--accent-emerald); margin-bottom: 12px; }}
  </style>
</head>
<body>
  <div class="container">
    <!-- Header Panel -->
    <div class="header-panel">
      <div class="header-title">
        <h1>{_safe_html(target.name)}</h1>
        <div class="target-val">{_safe_html(target.value)}</div>
      </div>
      <div class="header-meta">
        <div><strong>Scan ID:</strong> <code>{html.escape(scan_job.id[:8])}</code></div>
        <div><strong>Timestamp:</strong> {started_str}</div>
        <div><strong>Duration:</strong> {duration_str}</div>
      </div>
    </div>

    <!-- Scorecard & Statistics -->
    <div class="scorecard-panel">
      <div class="grade-card">
        <div class="grade-badge" style="color: {badge_bg};">{grade}</div>
        <div class="score-text">Security Score: <strong>{score}</strong> / 100</div>
      </div>
      <div class="stats-card">
        <div class="stats-grid">
          <div class="stat-pill">
            <span class="stat-count" style="color: var(--accent-red);">{crit_cnt}</span>
            <span class="stat-label">Critical</span>
          </div>
          <div class="stat-pill">
            <span class="stat-count" style="color: var(--accent-orange);">{high_cnt}</span>
            <span class="stat-label">High</span>
          </div>
          <div class="stat-pill">
            <span class="stat-count" style="color: var(--accent-yellow);">{med_cnt}</span>
            <span class="stat-label">Medium</span>
          </div>
          <div class="stat-pill">
            <span class="stat-count" style="color: var(--accent-blue);">{low_cnt}</span>
            <span class="stat-label">Low</span>
          </div>
          <div class="stat-pill">
            <span class="stat-count" style="color: var(--accent-cyan);">{info_cnt}</span>
            <span class="stat-label">Info</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Severity Filter Bar -->
    <div class="filter-bar">
      <button class="filter-btn active" onclick="filterSeverity('all')">All Findings ({len(scan_job.findings)})</button>
      <button class="filter-btn" onclick="filterSeverity('critical')">Critical ({crit_cnt})</button>
      <button class="filter-btn" onclick="filterSeverity('high')">High ({high_cnt})</button>
      <button class="filter-btn" onclick="filterSeverity('medium')">Medium ({med_cnt})</button>
      <button class="filter-btn" onclick="filterSeverity('low')">Low ({low_cnt})</button>
    </div>

    <!-- Findings Cards -->
    <div id="findings-container">
      {findings_content}
    </div>
  </div>

  <script>
    function toggleCard(idx) {{
      const body = document.getElementById('body-' + idx);
      const chevron = document.getElementById('chevron-' + idx);
      if (body) {{
        body.classList.toggle('open');
      }}
      if (chevron) {{
        chevron.classList.toggle('open');
      }}
    }}

    function filterSeverity(sev) {{
      const btns = document.querySelectorAll('.filter-btn');
      btns.forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');

      const cards = document.querySelectorAll('.finding-card');
      cards.forEach(card => {{
        if (sev === 'all' || card.classList.contains('severity-' + sev)) {{
          card.style.display = 'block';
        }} else {{
          card.style.display = 'none';
        }}
      }});
    }}

    function copySnippet(elementId) {{
      const el = document.getElementById(elementId);
      if (el) {{
        navigator.clipboard.writeText(el.innerText).then(() => {{
          alert('Remediation snippet copied to clipboard.');
        }});
      }}
    }}
  </script>
</body>
</html>
"""
