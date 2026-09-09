"""Render README media and verify every illustrated example against the local CLI.

python -m pip install -r brand/requirements.txt
python brand/render_assets.py          # verify, render, refresh managed README blocks
python brand/render_assets.py --check  # verify existing outputs without rewriting
"""
import argparse
from html import escape
from io import BytesIO
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from PIL import Image, ImageDraw
import resvg_py
from scenarios import SCENARIOS, STAGES, STAGE_SECONDS
from verify_assets import verify_assets, verify_scenarios

ROOT = Path(__file__).resolve().parent
PAPER, INK, MID, LINE = '#F4F4EF', '#111111', '#62625E', '#C6C6BF'
WIDTH, FRAME_MS = 1200, 100
ARROW, DOT = '\u2192', '\u00b7'
OVERVIEW_SECONDS = (3, 3, 3, 3)


def text(x, y, value, size=22, fill=INK, mono=False, spacing=0):
    family = 'Consolas, Liberation Mono, monospace' if mono else 'Arial, Helvetica, sans-serif'
    return (f'<text xml:space="preserve" x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
            f'fill="{fill}" letter-spacing="{spacing}">{escape(value)}</text>')


def rect(x, y, w, h, fill=PAPER, stroke='none', radius=0):
    return f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{radius}" fill="{fill}" stroke="{stroke}"/>'


def line(x1, y, x2):
    return f'<path d="M{x1} {y}H{x2}" stroke="{LINE}"/>'


def document(content, height, title):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="{height}" '
            f'viewBox="0 0 1200 {height}" role="img" aria-labelledby="title desc">'
            f'<title id="title">{escape(title)}</title>'
            '<desc id="desc">Static analysis of source-code trust boundaries. '
            'Text alternatives and exact illustrated examples are available in the README.</desc>' + content + '</svg>')


def rasterize(svg):
    return Image.open(BytesIO(resvg_py.svg_to_bytes(svg_string=svg, background=PAPER))).convert('RGB')


def editor(source, highlight=None):
    name = 'safe.py' if highlight is None else 'vulnerable.py'
    p = [rect(40, 236, 756, 364, '#FAFAF7', LINE, 8), rect(41, 237, 754, 43, '#E8E8E2', radius=7),
         text(112, 265, name, 18, MID, mono=True)]
    for x in (59, 75, 91):
        p.append(f'<circle cx="{x}" cy="259" r="4" fill="{MID}"/>')
    for i, value in enumerate(source.splitlines(), 1):
        y = 315 + (i - 1) * 34
        if i == highlight:
            p.append(rect(49, y - 25, 736, 33, INK, radius=3))
        p.extend([text(60, y, str(i), 17, PAPER if i == highlight else MID, True),
                  text(97, y, value, 21, PAPER if i == highlight else INK, True)])
    return ''.join(p)


def walkthrough(scenario, stage):
    p = [rect(0, 0, 1200, 720), text(40, 37, scenario.title.upper(), 15, MID, True, 1),
         text(937, 37, 'SOURCE / REVIEW', 14, MID, True, 1)]
    for i, name in enumerate(STAGES):
        x = 40 + i * 380
        p.extend([text(x, 94, f'0{i + 1}', 17, INK if i == stage else MID, True),
                  text(x + 40, 94, name, 24, INK if i == stage else MID),
                  rect(x, 117, 360, 3, INK if i < stage else LINE)])
    p.append(text(40, 193, scenario.titles[stage], 32))
    if stage == 1:
        p.extend([rect(40, 236, 756, 364, '#FAFAF7', LINE, 8),
                  text(64, 271, 'SELECTED FINDING', 15, MID, True, 2),
                  rect(64, 297, 134, 34, INK, radius=4), text(82, 321, scenario.severity, 20, PAPER, True),
                  text(64, 371, scenario.finding, 25),
                  text(64, 412, f'Displayed source: vulnerable.py {DOT} line {scenario.risky_line}', 18, MID, True),
                  rect(64, 447, 708, 56, INK, radius=4),
                  text(82, 482, scenario.risky.splitlines()[scenario.risky_line - 1].strip(), 23, PAPER, True),
                  text(64, 552, 'Review this transition before deployment.', 22)])
    else:
        p.append(editor(scenario.risky if stage == 0 else scenario.safer, scenario.risky_line if stage == 0 else None))
    heading, notes = scenario.notes[stage]
    p.extend([text(840, 255, f'0{stage + 1} / {STAGES[stage].upper()}', 14, MID, True, 1),
              text(840, 297, heading, 26), line(840, 320, 1158)])
    p.extend(text(840, 360 + i * 32, value, 21, MID) for i, value in enumerate(notes))
    if stage == 2:
        p.extend([rect(40, 613, 756, 34, '#E5E5DF', radius=4),
                  text(57, 637, 'This example: [+] No findings detected.', 19, mono=True)])
    p.extend([line(40, 666, 1160), text(40, 694, 'STATIC SOURCE ANALYSIS', 13, MID, True, 1),
              text(747, 694, f'RISKY CODE {ARROW} FINDING {ARROW} SAFER BOUNDARY', 13, MID, True)])
    return ''.join(p)


def bracket_svg():
    return (f'<path d="M0 16V0H16 M130 0H146V16 M146 42V58H130 M16 58H0V42" '
            f'fill="none" stroke="{INK}" stroke-width="2"/>')


def overview(stage):
    p = [rect(0, 0, 1200, 520), text(40, 57, 'Catch risky AI trust-boundary crossings', 38),
         text(40, 101, 'before they ship.', 38),
         text(40, 146, f'Local analysis {DOT} No LLM judge {DOT} Zero runtime dependencies', 20, MID)]
    rows = [('Prompt', 'user content', 'system instructions', 'Prompt injection', 'HIGH'),
            ('MCP', 'tool description', 'agent instructions', 'Tool poisoning', 'HIGH'),
            ('Execution', 'tool result', 'shell command', 'Shell execution', 'CRITICAL')]
    for i, (label, source, sink, finding, severity) in enumerate(rows):
        y = 178 + i * 97
        p.extend([rect(40, y, 1120, 82, '#FAFAF7', LINE, 6), text(60, y + 47, label, 23),
                  text(230, y + 49, source, 25), text(500, y + 49, ARROW, 28),
                  text(552, y + 49, sink, 25)])
        if i < stage or stage == 3:
            p.extend([rect(919, y + 10, 221, 62, '#E5E5DF', radius=4),
                      text(934, y + 34, severity, 16, INK, True), text(934, y + 59, finding, 20)])
        if stage == 3:
            p.append(f'<g transform="translate(442 {y + 12})">{bracket_svg()}</g>')
    captions = ('Inspecting prompt construction in source code.', 'Inspecting tool metadata in source code.',
                'Inspecting tool-output handling in source code.', 'Three risky transitions, identified in source before deployment.')
    p.append(text(40, 495, captions[stage], 18, MID))
    return ''.join(p)


def animated_svg(scenes, durations, height, title, is_overview):
    total = sum(durations)
    starts = [sum(durations[:i]) for i in range(len(durations) + 1)]
    times = ';'.join(str(t / total) for t in starts)
    motion = []
    for stage, content in enumerate(scenes):
        values = ';'.join('1' if i == stage else '0' for i in range(len(scenes)))
        values += ';' + ('1' if stage == 0 else '0')
        motion.append(f'<g opacity="{1 if stage == 0 else 0}">{content}'
                      f'<animate attributeName="opacity" values="{values}" keyTimes="{times}" '
                      f'calcMode="discrete" dur="{total}s" repeatCount="indefinite"/>')
        if not is_overview or stage < 3:
            # One global loop makes progress reset reliably without chained begin events.
            keys = sorted(set((0, starts[stage], starts[stage + 1], total)))
            phases = [max(0, min(1, (t - starts[stage]) / durations[stage])) for t in keys]
            key_times = ';'.join(str(t / total) for t in keys)
            if is_overview:
                y = 190 + stage * 97
                transforms = ';'.join(f'{210 + 514 * phase} {y}' for phase in phases)
                motion.append(f'<g transform="translate(210 {y})">{bracket_svg()}'
                              f'<animateTransform attributeName="transform" type="translate" values="{transforms}" '
                              f'keyTimes="{key_times}" dur="{total}s" repeatCount="indefinite"/></g>')
            else:
                widths = ';'.join(str(360 * phase) for phase in phases)
                motion.append(f'<rect x="{40 + stage * 380}" y="117" width="0" height="3" fill="{INK}">'
                              f'<animate attributeName="width" values="{widths}" keyTimes="{key_times}" '
                              f'dur="{total}s" repeatCount="indefinite"/></rect>')
        motion.append('</g>')
    return document(''.join(motion), height, title)


def draw_bracket(draw, x, y):
    for points in (((x, y + 16), (x, y), (x + 16, y)),
                   ((x + 130, y), (x + 146, y), (x + 146, y + 16)),
                   ((x + 146, y + 42), (x + 146, y + 58), (x + 130, y + 58)),
                   ((x + 16, y + 58), (x, y + 58), (x, y + 42))):
        draw.line(points, fill=INK, width=2)


def render(stem, scenes, durations, height, title, is_overview=False):
    (ROOT / f'{stem}-animated.svg').write_text(animated_svg(scenes, durations, height, title, is_overview), encoding='utf-8')
    bases = [rasterize(document(scene, height, title)) for scene in scenes]
    if is_overview:
        still = bases[-1]
    else:
        still = Image.new('RGB', (1200, height * len(bases)), PAPER)
        for i, base in enumerate(bases):
            still.paste(base, (0, i * height))
    still.save(ROOT / f'{stem}-static.png', optimize=True)
    palette_source = Image.new('RGB', (1200, height * len(bases)), PAPER)
    for i, base in enumerate(bases):
        palette_source.paste(base, (0, i * height))
    palette = palette_source.quantize(colors=64)
    frames = []
    for stage, (base, seconds) in enumerate(zip(bases, durations)):
        count = seconds * 1000 // FRAME_MS
        for tick in range(count):
            frame = base.copy()
            draw = ImageDraw.Draw(frame)
            phase = tick / count
            if is_overview and stage < 3:
                draw_bracket(draw, round(210 + 514 * phase), 190 + stage * 97)
            elif not is_overview and tick:
                x = 40 + stage * 380
                draw.rectangle((x, 117, x + round(360 * phase), 119), fill=INK)
            frames.append(frame.quantize(palette=palette, dither=Image.Dither.NONE))
    frames[0].save(ROOT / f'{stem}.gif', save_all=True, append_images=frames[1:],
                   duration=FRAME_MS, loop=0, optimize=True, disposal=1)
    print(f'Rendered {stem}.gif', flush=True)


def walkthrough_markdown(scenario):
    return f'''<p align="center">
  <img src="brand/{scenario.slug}.gif" width="100%" alt="{scenario.title}: risky code, {scenario.severity} finding, and a safer boundary.">
</p>

[View the still walkthrough](brand/{scenario.slug}-static.png)

<details>
<summary>Read the example and reproduce the scan</summary>

Selected finding: `{scenario.finding}` ({scenario.severity}).

Save this as `vulnerable.py` in a separate scratch folder:

```python
{scenario.risky}
```

Save this as `safe.py` in the same folder:

```python
{scenario.safer}
```

{scenario.explanation}

Run from that scratch folder, outside this repository's self-scan exclusions:

```bash
secchecker vulnerable.py --type llm --format json -o vulnerable.json
secchecker safe.py --type llm
```

The vulnerable example exits with code `1`; its report includes the selected finding above. The safer example exits with code `0` and prints `[+] No findings detected.` A clean scan is not proof of security.

Adapted from the [vulnerable fixture]({scenario.fixture}) and [paired fixture]({scenario.safe_fixture}).

</details>'''


def refresh_readme():
    path = ROOT.parent / 'README.md'
    source = path.read_text(encoding='utf-8')
    for scenario in SCENARIOS:
        begin, end = f'<!-- brand:{scenario.slug}:start -->', f'<!-- brand:{scenario.slug}:end -->'
        pattern = re.escape(begin) + '.*?' + re.escape(end)
        replacement = begin + '\n' + walkthrough_markdown(scenario) + '\n' + end
        source, count = re.subn(pattern, lambda _: replacement, source, flags=re.S)
        if count != 1:
            raise ValueError(f'Expected one README placeholder for {scenario.slug}')
    path.write_text(source, encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Verify CLI examples and media without rewriting files')
    args = parser.parse_args()
    verify_scenarios()
    if not args.check:
        lockup = ET.parse(ROOT / 'secchecker-lockup.svg').getroot()
        _, _, width, height = map(float, lockup.attrib['viewBox'].split())
        lockup.set('width', str(int(width * 2)))
        lockup.set('height', str(int(height * 2)))
        rasterize(ET.tostring(lockup, encoding='unicode')).save(ROOT / 'secchecker-banner.png', optimize=True)
        render('secchecker-hero', [overview(i) for i in range(4)], OVERVIEW_SECONDS, 520,
               'Catch risky AI trust-boundary crossings before they ship.', is_overview=True)
        for scenario in SCENARIOS:
            render(scenario.slug, [walkthrough(scenario, i) for i in range(3)], STAGE_SECONDS, 720, scenario.title)
        refresh_readme()
    verify_assets()


if __name__ == '__main__':
    main()
