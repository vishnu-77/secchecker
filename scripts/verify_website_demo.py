"""Verify that the website illustration agrees with its captured SARIF report."""
import json
from html.parser import HTMLParser
from pathlib import Path


class TextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []

    def handle_data(self, data):
        self.parts.append(data)


def main():
    root = Path(__file__).resolve().parents[1]
    html = (root / 'website/index.html').read_text(encoding='utf-8')
    report = json.loads((root / 'website/assets/example-scan.sarif').read_text(encoding='utf-8'))
    run = report['runs'][0]
    results = run['results']
    parser = TextParser()
    parser.feed(html)
    text = ''.join(parser.parts)
    files = {r['locations'][0]['physicalLocation']['artifactLocation']['uri'] for r in results}
    count = sum(r['properties']['matchCount'] for r in results)
    expected = '[*] {} finding(s) across {} file(s)'.format(count, len(files))
    assert expected in text, 'Displayed scan totals differ from the report'
    selected = results[0]
    location = selected['locations'][0]['physicalLocation']
    assert selected['ruleId'] in text
    assert selected['message']['text'] in text
    assert '>{}</span>'.format(selected['properties']['severity']) in html
    assert '{} · line {}'.format(location['artifactLocation']['uri'], location['region']['startLine']) in text
    assert 'SecChecker {}'.format(run['tool']['driver']['version']) in text
    assert run['invocations'][0]['startTimeUtc'].startswith('2026-09-20')
    assert 'assets/example-scan.sarif' in html
    assert 'Playback does not run a scan in your browser.' in text
    assert 'tool_result  ───────▶' not in text
    # The public report is limited to the reviewed anonymous paths, with no
    # source excerpts or purported flow traces added during presentation.
    assert files == {'config/service.env', 'examples/provider_check.py', 'config/worker.env', 'tests/provider_logging.py'}
    for result in results:
        assert 'codeFlows' not in result
        for loc in result['locations']:
            assert 'snippet' not in loc['physicalLocation'].get('region', {})
    print('Recorded website scan: transcript, selected finding and report agree.')


if __name__ == '__main__':
    main()
