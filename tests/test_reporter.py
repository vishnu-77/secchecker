from secchecker.reporter import to_json, to_markdown

def test_reporter(tmp_path):
    results = {"file.txt": {"Password in Config": ["password='123'"]}}
    json_file = to_json(results, tmp_path / "out.json")
    md_file = to_markdown(results, tmp_path / "out.md")
    assert str(json_file).endswith("out.json")
    assert str(md_file).endswith("out.md")
