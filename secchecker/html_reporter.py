"""HTML report generator for secchecker — produces self-contained single-file reports."""
import os
from datetime import datetime
from typing import Dict, List

try:
    from secchecker.reporter import get_severity
    from secchecker import __version__ as _VERSION
except ImportError:
    _VERSION = "0.3.0"

    def get_severity(name):
        return "MEDIUM"

_SEVERITY_BG = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#28a745",
}
_SEVERITY_FG = {
    "CRITICAL": "#fff",
    "HIGH": "#fff",
    "MEDIUM": "#212529",
    "LOW": "#fff",
}

_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f8f9fa;color:#212529;line-height:1.6}
.container{max-width:1100px;margin:0 auto;padding:20px}
header{background:#1a1a2e;color:#fff;padding:24px 30px;border-radius:8px;margin-bottom:24px}
header h1{font-size:1.8rem;font-weight:700}
header .meta{font-size:.85rem;color:#adb5bd;margin-top:8px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px;margin-bottom:24px}
.card{background:#fff;border-radius:8px;padding:16px;text-align:center;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.card .num{font-size:2rem;font-weight:700}
.card .lbl{font-size:.8rem;color:#6c757d;text-transform:uppercase}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:600}
details{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);margin-bottom:10px}
details summary{padding:14px 18px;cursor:pointer;font-weight:600;font-size:.9rem;list-style:none;display:flex;align-items:center;gap:10px}
details summary::-webkit-details-marker{display:none}
details summary::before{content:"\\25B6";font-size:.7rem;color:#6c757d}
details[open] summary::before{content:"\\25BC"}
.plist{padding:0 18px 14px}
.pitem{border-top:1px solid #e9ecef;padding:10px 0}
.pname{font-weight:600;font-size:.9rem;margin-bottom:4px}
.match{font-family:'Courier New',monospace;font-size:.8rem;color:#495057;background:#f1f3f5;padding:3px 8px;border-radius:4px;margin:2px 0;word-break:break-all}
.empty{text-align:center;padding:40px;color:#6c757d;background:#fff;border-radius:8px;font-size:1.1rem}
"""


def _esc(text):
    # type: (str) -> str
    return (str(text).replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))


def _badge(severity):
    # type: (str) -> str
    bg = _SEVERITY_BG.get(severity, "#6c757d")
    fg = _SEVERITY_FG.get(severity, "#fff")
    return '<span class="badge" style="background:{};color:{}">{}</span>'.format(bg, fg, severity)


def generate_html_report(results, scan_type="secrets"):
    # type: (Dict[str, Dict[str, List[str]]], str) -> str
    """Generate a self-contained HTML report string."""
    total_files = len(results)
    total_patterns = sum(len(p) for p in results.values())
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for patterns in results.values():
        for name in patterns:
            s = get_severity(name)
            counts[s] = counts.get(s, 0) + 1

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    parts = [
        "<!DOCTYPE html><html lang='en'><head>",
        "<meta charset='UTF-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1.0'>",
        "<title>secchecker Security Report</title>",
        "<style>", _CSS, "</style>",
        "</head><body><div class='container'>",
        "<header><h1>secchecker Security Report</h1>",
        "<div class='meta'>v{} &bull; {} &bull; {}</div>".format(_VERSION, _esc(scan_type), ts),
        "</header>",
        "<div class='grid'>",
    ]

    for num, lbl in [
        (str(total_files), "Files"),
        (str(total_patterns), "Patterns"),
        (str(counts["CRITICAL"]), "Critical"),
        (str(counts["HIGH"]), "High"),
        (str(counts["MEDIUM"]), "Medium"),
        (str(counts["LOW"]), "Low"),
    ]:
        parts.append("<div class='card'><div class='num'>{}</div><div class='lbl'>{}</div></div>".format(num, lbl))

    parts.append("</div>")

    if not results:
        parts.append("<div class='empty'>No security findings detected.</div>")
    else:
        for filepath, patterns in sorted(results.items()):
            file_counts = {}
            for pname in patterns:
                s = get_severity(pname)
                file_counts[s] = file_counts.get(s, 0) + 1
            badges = " ".join(
                "{} x{}".format(_badge(s), c)
                for s, c in sorted(file_counts.items())
            )
            parts.append("<details>")
            parts.append("<summary>{} {}</summary>".format(_esc(os.path.basename(filepath)), badges))
            parts.append("<div class='plist'>")
            for pname, matches in sorted(patterns.items()):
                sev = get_severity(pname)
                parts.append("<div class='pitem'>")
                parts.append("<div class='pname'>{} {}</div>".format(_esc(pname), _badge(sev)))
                for m in matches[:10]:
                    parts.append("<div class='match'>{}</div>".format(_esc(str(m)[:200])))
                if len(matches) > 10:
                    parts.append("<div class='match' style='color:#6c757d'>... and {} more</div>".format(len(matches) - 10))
                parts.append("</div>")
            parts.append("</div></details>")

    parts.append("</div></body></html>")
    return "".join(parts)


def to_html(results, output_file="secchecker_report.html", scan_type="secrets"):
    # type: (Dict[str, Dict[str, List[str]]], str, str) -> str
    """Write HTML report to file. Returns file path."""
    report = generate_html_report(results, scan_type=scan_type)
    output_path = str(output_file)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    return output_path
