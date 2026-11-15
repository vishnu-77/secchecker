"""T3 harness self-check: bench/mutate.py must stay trustworthy. Known evasion gaps are
reported by the script, not failed here (see docs/plans/llm-scanner-test-plan.md, T3)."""
import ast
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("mutate", ROOT / "bench" / "mutate.py")
mutate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mutate)


def test_identity_and_wrapping_keep_every_finding():
    rows, _ = mutate.run()
    for name in ("identity", "wrap_in_helper"):
        statuses = {r["status"] for r in rows if r["transform"] == name}
        assert statuses == {"kept"}, name


def test_transforms_are_meaning_preserving_rewrites():
    src = (
        "import subprocess\n"
        "def build(user_input):\n"
        "    prompt = f\"Q: {user_input}\"\n"
        "    subprocess.run(prompt)\n"
    )
    for t in mutate.VULN_TRANSFORMS:
        ast.parse(t(src))  # every rewrite of valid code stays valid
    assert '"Q: {}".format(user_input)' in mutate.fstring_to_format(src)
    assert '"Q: " + str(user_input)' in mutate.fstring_to_concat(src)
    assert '"Q: %s" % (user_input,)' in mutate.fstring_to_percent(src)
    assert "import subprocess as sp" in mutate.alias_imports(src)
    assert "sp.run(" in mutate.alias_imports(src)
