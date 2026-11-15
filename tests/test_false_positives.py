"""Regression tests for false positives seen scanning a real repo (lockfile hashes,
decimal scores, SHA-pinned actions) and for the unpinned-action rule missing tag refs."""
from secchecker.core import scan_file
from secchecker.devsecops_scanner import scan_file_devsecops
from secchecker.validators import is_valid_wif

SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"
UV_LOCK = (
    'wheels = [{ url = "x.whl", hash = "sha256:'
    '5accf365cce21998a1c6dd8eafd42c7b226eb54b2747cdce2fac0774f6fbbc82" }]\n'
    'sdist = { hash = "sha256:ac0774f6fbbc82d752de25485e2237888e0123456789abcdef0123456789ab" }\n'
)


def test_lockfile_hashes_not_flagged(tmp_path):
    f = tmp_path / "uv.lock"
    f.write_text(UV_LOCK)
    findings = scan_file(str(f))
    assert "Twilio Account SID" not in findings
    assert "Bitcoin Private Key" not in findings


def test_decimal_score_not_credit_card(tmp_path):
    f = tmp_path / "run.json"
    f.write_text('{"recall": 0.6547619047619048}\n')
    assert "Credit Card" not in scan_file(str(f))


def test_real_twilio_sid_still_flagged(tmp_path):
    f = tmp_path / "cfg.py"
    # built at runtime so the repo holds no SID-shaped literal (push protection)
    f.write_text('sid = "' + "A" + "C" + "3f9a2b7c81d04e56a9b7c3d2e1f08a64" + '"\n')
    assert "Twilio Account SID" in scan_file(str(f))


def test_wif_checksum():
    # public example keys from the Bitcoin wiki (uncompressed and compressed)
    assert is_valid_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")
    assert is_valid_wif("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617")
    assert not is_valid_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTK")


def test_real_wif_still_flagged(tmp_path):
    f = tmp_path / "wallet.txt"
    f.write_text("key: 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ\n")
    assert "Bitcoin Private Key" in scan_file(str(f))


def _unpinned(tmp_path, body):
    f = tmp_path / "ci.yml"
    f.write_text("steps:\n" + body)
    return scan_file_devsecops(str(f)).get("CI - Unpinned GitHub Action", [])


def test_tag_and_branch_refs_flagged(tmp_path):
    hits = _unpinned(tmp_path, (
        "  - uses: actions/checkout@v4\n"
        "  - uses: pypa/gh-action-pypi-publish@release/v1\n"
        "  - uses: owner/repo/sub-action@main\n"
    ))
    assert len(hits) == 3
    assert any("checkout@v4" in str(h) for h in hits)  # full ref reported, not one char


def test_sha_pinned_and_local_not_flagged(tmp_path):
    assert _unpinned(tmp_path, (
        "  - uses: actions/checkout@" + SHA + "  # v4\n"
        "  - uses: ./.github/actions/local\n"
        "  - uses: docker://alpine:3.20\n"
    )) == []
