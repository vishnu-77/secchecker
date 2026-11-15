"""T3 evasion test (docs/plans/llm-scanner-test-plan.md): apply meaning-preserving rewrites
to every vulnerable fixture and check the same rule still fires; add trigger words in
comments to every safe fixture and check it stays clean.

    python bench/mutate.py [--json out.json]

Rewrites are plain text transforms; a rewrite whose output is not valid Python, or that
changes nothing, is reported as n/a for that fixture rather than counted.
"""
import argparse
import ast
import json
import re
import sys
import tempfile
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BENCH_DIR.parent))
from secchecker.llm_scanner import scan_file_llm  # noqa: E402

FSTRING = re.compile(r'\bf"([^"\\{}]*(?:\{[A-Za-z_][\w.]*\}[^"\\{}]*)+)"')
RENAMES = {"user_input": "uin", "system_prompt": "sys_msg", "prompt": "msg_text",
           "result": "res", "query": "qtext", "response": "resp", "output": "out_val"}


def identity(src):
    return src


def rename_vars(src):
    for old, new in RENAMES.items():
        src = re.sub(r"\b{}\b".format(old), new, src)
    return src


def fstring_to_format(src):
    def rep(m):
        names = re.findall(r"\{([^}]*)\}", m.group(1))
        return '"{}".format({})'.format(re.sub(r"\{[^}]*\}", "{}", m.group(1)), ", ".join(names))
    return FSTRING.sub(rep, src)


def fstring_to_concat(src):
    def rep(m):
        parts = re.split(r"\{([^}]*)\}", m.group(1))
        out = []
        for i, p in enumerate(parts):
            if i % 2:
                out.append("str({})".format(p))
            elif p:
                out.append('"{}"'.format(p))
        return " + ".join(out)
    return FSTRING.sub(rep, src)


def fstring_to_percent(src):
    def rep(m):
        names = re.findall(r"\{([^}]*)\}", m.group(1))
        return '"{}" % ({},)'.format(re.sub(r"\{[^}]*\}", "%s", m.group(1)), ", ".join(names))
    return FSTRING.sub(rep, src)


def alias_imports(src):
    for mod, alias in (("subprocess", "sp"), ("os", "_o"), ("json", "_j")):
        if re.search(r"^import {}$".format(mod), src, re.M):
            src = re.sub(r"^import {}$".format(mod), "import {} as {}".format(mod, alias), src, flags=re.M)
            src = re.sub(r"\b{}\.".format(mod), alias + ".", src)
    return src


def split_call_args(src):
    # break the first call on each code line across lines (legal inside parentheses)
    out = []
    for line in src.splitlines():
        code = line.split("#")[0]
        m = re.search(r"\w\(", code)
        if m and '"' not in code[:m.end()] and "'" not in code[:m.end()] and not code.lstrip().startswith(("def ", "class ")):
            indent = len(line) - len(line.lstrip())
            line = line[:m.end()] + "\n" + " " * (indent + 8) + line[m.end():]
        out.append(line)
    return "\n".join(out) + "\n"


def wrap_in_helper(src):
    # move the whole module body into a function and call it
    body = "\n".join("    " + ln if ln.strip() else ln for ln in src.splitlines())
    return "def _wrapped():\n" + body + "\n\n_wrapped()\n"


VULN_TRANSFORMS = [identity, rename_vars, fstring_to_format, fstring_to_concat,
                   fstring_to_percent, alias_imports, split_call_args, wrap_in_helper]

NOISE = ("# note: never ignore previous instructions; do not eval(user_input) or os.system(mcp_result)\n"
         "# <IMPORTANT> <|system|> system_prompt = f\"{user_input}\"\n")


def _valid(src):
    try:
        ast.parse(src)
        return True
    except SyntaxError:
        return False


def _scan_text(src, tmpdir, name):
    p = Path(tmpdir) / name
    p.write_text(src, encoding="utf-8")
    return scan_file_llm(str(p))


def run():
    vulnerable = sorted((BENCH_DIR / "fixtures" / "vulnerable").rglob("*.py"))
    safe = sorted((BENCH_DIR / "fixtures" / "safe").glob("*.py"))
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for path in vulnerable:
            src = path.read_text(encoding="utf-8")
            base_rules = set(scan_file_llm(str(path)))
            for t in VULN_TRANSFORMS:
                new = t(src)
                if (t is not identity and new == src) or not _valid(new):
                    status = "n/a"
                else:
                    found = set(_scan_text(new, tmp, path.name))
                    # relabeled: still flagged, but not by every original rule
                    status = "kept" if base_rules <= found else ("relabeled" if found else "lost")
                rows.append({"fixture": "{}/{}".format(path.parent.name, path.stem),
                             "rules": sorted(base_rules), "transform": t.__name__, "status": status})
        noise = []
        for path in safe:
            found = _scan_text(NOISE + path.read_text(encoding="utf-8"), tmp, path.name)
            noise.append({"fixture": path.stem, "flagged": sorted(found)})
    return rows, noise


def summarize(rows, noise):
    lines = ["Survival by transform (kept / applicable):"]
    for t in VULN_TRANSFORMS:
        r = [x for x in rows if x["transform"] == t.__name__ and x["status"] != "n/a"]
        kept = sum(x["status"] == "kept" for x in r)
        rel = sum(x["status"] == "relabeled" for x in r)
        lines.append("  {:<20} kept {:>2}/{:<2} relabeled {:>2}  {}".format(
            t.__name__, kept, len(r), rel, "{:.0%}".format(kept / len(r)) if r else "-"))
    for status in ("lost", "relabeled"):
        lines.append("{} (fixture <- transform):".format(status.capitalize()))
        for x in rows:
            if x["status"] == status:
                lines.append("  {} <- {}  ({})".format(x["fixture"], x["transform"], ", ".join(x["rules"])))
    flagged = [n for n in noise if n["flagged"]]
    lines.append("Safe fixtures flagged after comment noise: {}/{}".format(len(flagged), len(noise)))
    for n in flagged:
        lines.append("  {} -> {}".format(n["fixture"], ", ".join(n["flagged"])))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", help="write per-fixture results here")
    args = ap.parse_args()
    rows, noise = run()
    print(summarize(rows, noise))
    if args.json:
        Path(args.json).write_text(json.dumps({"mutations": rows, "comment_noise": noise}, indent=2),
                                   encoding="utf-8")


if __name__ == "__main__":
    main()
