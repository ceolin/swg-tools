# Copyright (c) 2026 Flavio Ceolin <flavio.ceolin@gmail.com>
# SPDX-License-Identifier: Apache-2.0
'''Render a self-contained HTML dashboard from the advisory database.

The output is a single HTML file with inline styles and SVG charts (no
external assets or network access), so it opens straight from disk and
works offline. Charts follow the project data-viz conventions: severity
uses the reserved status palette, state uses the categorical palette,
counts carry direct labels, and a searchable table backs every chart.
'''

import html
import json
from collections import Counter
from datetime import datetime
from typing import Any, Optional

from . import db as db_mod

# Severity → reserved status palette (fixed, not themed).
SEVERITY_ORDER = ('critical', 'high', 'medium', 'low', 'unknown')
SEVERITY_COLOR = {
    'critical': '#d03b3b',
    'high': '#ec835a',
    'medium': '#fab219',
    'low': '#0ca30c',
    'unknown': '#898781',
}

# State → categorical palette slots 1-4 (themed via CSS variables).
STATE_ORDER = ('draft', 'triage', 'published', 'closed')

# CVSS rating bands per the CVSS spec, used to colour histogram columns.
CVSS_BANDS = (
    (9.0, 10.01, 'critical'),
    (7.0, 9.0, 'high'),
    (4.0, 7.0, 'medium'),
    (0.1, 4.0, 'low'),
)


# ─── Aggregation ──────────────────────────────────────────────────────────────

def _severity(a: dict[str, Any]) -> str:
    sev = (a.get('severity') or '').lower()
    return sev if sev in SEVERITY_COLOR else 'unknown'


def _cvss_band(score: Optional[float]) -> str:
    if score is None:
        return 'unknown'
    for lo, hi, name in CVSS_BANDS:
        if lo <= score < hi:
            return name
    return 'unknown'


def _cwe_ids(a: dict[str, Any]) -> list[str]:
    return [c.get('cwe_id') for c in (a.get('cwes') or []) if c.get('cwe_id')]


def _month(created_at: Optional[str]) -> Optional[str]:
    if not created_at:
        return None
    try:
        dt = datetime.fromisoformat(created_at.replace('Z', '+00:00'))
    except ValueError:
        return None
    return dt.strftime('%Y-%m')


def aggregate(advisories: list[dict[str, Any]],
              today: str) -> dict[str, Any]:
    '''Compute every figure the dashboard renders from the raw advisories.'''
    severity = Counter(_severity(a) for a in advisories)
    state = Counter((a.get('state') or 'unknown') for a in advisories)
    cwe = Counter()
    for a in advisories:
        cwe.update(_cwe_ids(a))

    cvss_hist = Counter()
    scored = 0
    for a in advisories:
        score = (a.get('cvss') or {}).get('score')
        if score is None:
            continue
        scored += 1
        bucket = min(int(score), 9)  # 0-9 → buckets [0,1)…[9,10]
        cvss_hist[bucket] += 1

    months = Counter()
    for a in advisories:
        m = _month(a.get('created_at'))
        if m:
            months[m] += 1

    past_embargo = sum(
        1 for a in advisories
        if a.get('embargo') and a['embargo'] < today)
    open_count = state.get('draft', 0) + state.get('triage', 0)
    high_plus = severity.get('critical', 0) + severity.get('high', 0)
    with_fix = sum(1 for a in advisories
                   if db_mod.parse_patches(a.get('description')))

    return {
        'total': len(advisories),
        'open': open_count,
        'published': state.get('published', 0),
        'past_embargo': past_embargo,
        'high_plus': high_plus,
        'with_fix': with_fix,
        'scored': scored,
        'severity': severity,
        'state': state,
        'cwe_top': cwe.most_common(10),
        'cvss_hist': cvss_hist,
        'months': months,
    }


# ─── SVG chart builders ───────────────────────────────────────────────────────

def _esc(text: Any) -> str:
    return html.escape(str(text), quote=True)


def _hbar_chart(rows: list[tuple[str, int, str]], *, unit: str = '') -> str:
    '''Horizontal bar chart. rows = [(label, value, fill-css), …].'''
    if not rows:
        return '<p class="empty">No data.</p>'
    w, gutter, pad_right = 360, 104, 46
    bar_area = w - gutter - pad_right
    row_h, bar_h = 30, 16
    height = row_h * len(rows) + 8
    max_val = max((v for _, v, _ in rows), default=1) or 1

    parts = [f'<svg viewBox="0 0 {w} {height}" role="img" '
             f'preserveAspectRatio="xMinYMin meet" class="chart">']
    for i, (label, value, fill) in enumerate(rows):
        y = i * row_h + 8
        cy = y + bar_h / 2
        bar_w = max(2, bar_area * value / max_val)
        parts.append(
            f'<text x="{gutter - 8}" y="{cy}" class="cat" '
            f'text-anchor="end" dominant-baseline="central">{_esc(label)}</text>')
        parts.append(
            f'<rect x="{gutter}" y="{y}" width="{bar_w:.1f}" height="{bar_h}" '
            f'rx="4" fill="{fill}"><title>{_esc(label)}: {value}{unit}</title></rect>')
        parts.append(
            f'<text x="{gutter + bar_w + 6:.1f}" y="{cy}" class="val" '
            f'dominant-baseline="central">{value}{unit}</text>')
    parts.append('</svg>')
    return ''.join(parts)


def _severity_rows(counts: Counter) -> list[tuple[str, int, str]]:
    return [(s.capitalize(), counts.get(s, 0), SEVERITY_COLOR[s])
            for s in SEVERITY_ORDER if counts.get(s, 0)]


def _state_rows(counts: Counter) -> list[tuple[str, int, str]]:
    return [(s.capitalize(), counts.get(s, 0), f'var(--state-{s})')
            for s in STATE_ORDER if counts.get(s, 0)]


def _cwe_rows(cwe_top: list[tuple[str, int]]) -> list[tuple[str, int, str]]:
    # Single-series magnitude ranking → one sequential blue hue.
    return [(cwe, n, 'var(--series-1)') for cwe, n in cwe_top]


def _cvss_histogram(hist: Counter) -> str:
    '''Vertical column histogram of CVSS scores in 1-point buckets 0–10.'''
    buckets = list(range(10))
    if not any(hist.get(b) for b in buckets):
        return '<p class="empty">No CVSS scores.</p>'
    w, h = 380, 190
    left, bottom, top, right = 30, 26, 12, 8
    plot_w = w - left - right
    plot_h = h - bottom - top
    col_w = plot_w / len(buckets)
    max_val = max(hist.values()) or 1

    parts = [f'<svg viewBox="0 0 {w} {h}" role="img" '
             f'preserveAspectRatio="xMinYMin meet" class="chart">']
    # y baseline
    parts.append(f'<line x1="{left}" y1="{top + plot_h}" x2="{w - right}" '
                 f'y2="{top + plot_h}" class="axis"/>')
    for b in buckets:
        val = hist.get(b, 0)
        band = _cvss_band(b + 0.5)
        fill = SEVERITY_COLOR[band]
        x = left + b * col_w + 2
        bw = col_w - 4
        bh = (plot_h * val / max_val) if val else 0
        y = top + plot_h - bh
        if val:
            parts.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" '
                f'height="{bh:.1f}" rx="3" fill="{fill}">'
                f'<title>CVSS {b}.0–{b}.9: {val}</title></rect>')
            parts.append(
                f'<text x="{x + bw / 2:.1f}" y="{y - 3:.1f}" class="val" '
                f'text-anchor="middle">{val}</text>')
        parts.append(
            f'<text x="{x + bw / 2:.1f}" y="{top + plot_h + 14:.1f}" '
            f'class="tick" text-anchor="middle">{b}</text>')
    parts.append('</svg>')
    return ''.join(parts)


def _timeline(months: Counter) -> str:
    '''Monthly area+line chart of advisories created over time.'''
    if not months:
        return '<p class="empty">No dates.</p>'
    keys = sorted(months)
    # Fill gaps so the x-axis is continuous month-by-month.
    start = datetime.strptime(keys[0], '%Y-%m')
    end = datetime.strptime(keys[-1], '%Y-%m')
    seq: list[tuple[str, int]] = []
    y, m = start.year, start.month
    while (y, m) <= (end.year, end.month):
        key = f'{y:04d}-{m:02d}'
        seq.append((key, months.get(key, 0)))
        m += 1
        if m > 12:
            m, y = 1, y + 1

    w, h = 720, 220
    left, bottom, top, right = 34, 28, 16, 10
    plot_w = w - left - right
    plot_h = h - bottom - top
    n = len(seq)
    max_val = max((v for _, v in seq), default=1) or 1

    def px(i: int) -> float:
        return left + (plot_w * i / (n - 1) if n > 1 else 0)

    def py(v: int) -> float:
        return top + plot_h - plot_h * v / max_val

    pts = [(px(i), py(v)) for i, (_, v) in enumerate(seq)]
    line = ' '.join(f'{x:.1f},{y:.1f}' for x, y in pts)
    area = (f'M{pts[0][0]:.1f},{top + plot_h:.1f} '
            + ' '.join(f'L{x:.1f},{y:.1f}' for x, y in pts)
            + f' L{pts[-1][0]:.1f},{top + plot_h:.1f} Z')

    parts = [f'<svg viewBox="0 0 {w} {h}" role="img" '
             f'preserveAspectRatio="xMinYMin meet" class="chart">']
    # horizontal gridlines + y ticks (0 and max)
    for frac in (0, 0.5, 1):
        gy = top + plot_h - plot_h * frac
        parts.append(f'<line x1="{left}" y1="{gy:.1f}" x2="{w - right}" '
                     f'y2="{gy:.1f}" class="grid"/>')
        parts.append(f'<text x="{left - 6}" y="{gy:.1f}" class="tick" '
                     f'text-anchor="end" dominant-baseline="central">'
                     f'{round(max_val * frac)}</text>')
    parts.append(f'<path d="{area}" class="area"/>')
    parts.append(f'<polyline points="{line}" class="line"/>')
    # year boundary ticks
    for i, (key, _) in enumerate(seq):
        if key.endswith('-01') or i == 0:
            parts.append(f'<text x="{px(i):.1f}" y="{top + plot_h + 16:.1f}" '
                         f'class="tick" text-anchor="middle">{key[:4]}</text>')
    # hover dots with native tooltips
    for i, (key, v) in enumerate(seq):
        parts.append(f'<circle cx="{px(i):.1f}" cy="{py(v):.1f}" r="6" '
                     f'fill="transparent"><title>{key}: {v}</title></circle>')
    parts.append('</svg>')
    return ''.join(parts)


def _legend(items: list[tuple[str, str]]) -> str:
    chips = ''.join(
        f'<span class="lg"><span class="sw" style="background:{c}"></span>'
        f'{_esc(label)}</span>' for label, c in items)
    return f'<div class="legend">{chips}</div>'


# ─── Table ────────────────────────────────────────────────────────────────────

def _table_records(advisories: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records = []
    for a in advisories:
        cvss = (a.get('cvss') or {}).get('score')
        records.append({
            'ghsa': a.get('ghsa_id') or '',
            'cve': a.get('cve_id') or '',
            'severity': _severity(a),
            'state': a.get('state') or 'unknown',
            'cvss': cvss,
            'embargo': a.get('embargo') or '',
            'created': (a.get('created_at') or '')[:10],
            'summary': (a.get('summary') or '').replace('\n', ' '),
            'url': a.get('html_url') or '',
        })
    return records


# ─── Page assembly ────────────────────────────────────────────────────────────

def _tile(value: Any, label: str, *, accent: str = '') -> str:
    style = f' style="color:{accent}"' if accent else ''
    return (f'<div class="tile"><div class="tile-v"{style}>{value}</div>'
            f'<div class="tile-l">{_esc(label)}</div></div>')


def _card(title: str, body: str, *, wide: bool = False,
          note: str = '') -> str:
    cls = 'card wide' if wide else 'card'
    note_html = f'<span class="note">{_esc(note)}</span>' if note else ''
    return (f'<section class="{cls}"><h2>{_esc(title)}{note_html}</h2>'
            f'{body}</section>')


def render_dashboard(advisories: list[dict[str, Any]], repo: str,
                     generated_at: str) -> str:
    today = generated_at[:10]
    agg = aggregate(advisories, today)
    records = _table_records(advisories)

    tiles = ''.join([
        _tile(agg['total'], 'Total advisories'),
        _tile(agg['open'], 'Open (draft + triage)', accent='var(--series-1)'),
        _tile(agg['published'], 'Published'),
        _tile(agg['high_plus'], 'Critical + High', accent=SEVERITY_COLOR['high']),
        _tile(agg['past_embargo'], 'Past embargo', accent=SEVERITY_COLOR['critical']),
        _tile(agg['with_fix'], 'With patch info'),
    ])

    severity_card = _card(
        'By severity',
        _hbar_chart(_severity_rows(agg['severity'])))
    state_card = _card(
        'By state',
        _hbar_chart(_state_rows(agg['state'])))
    cwe_card = _card(
        'Top CWEs',
        _hbar_chart(_cwe_rows(agg['cwe_top'])),
        note=f'{len(agg["cwe_top"])} shown')
    cvss_card = _card(
        'CVSS score distribution',
        _cvss_histogram(agg['cvss_hist'])
        + _legend([('Critical', SEVERITY_COLOR['critical']),
                   ('High', SEVERITY_COLOR['high']),
                   ('Medium', SEVERITY_COLOR['medium']),
                   ('Low', SEVERITY_COLOR['low'])]),
        note=f'{agg["scored"]} scored')
    timeline_card = _card(
        'Advisories created over time',
        _timeline(agg['months']), wide=True)

    data_json = json.dumps(records, separators=(',', ':'))

    return _PAGE.format(
        repo=_esc(repo),
        generated=_esc(generated_at),
        tiles=tiles,
        severity_card=severity_card,
        state_card=state_card,
        cwe_card=cwe_card,
        cvss_card=cvss_card,
        timeline_card=timeline_card,
        severity_colors=json.dumps(SEVERITY_COLOR),
        data_json=data_json,
    )


_PAGE = '''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Zephyr advisory dashboard — {repo}</title>
<style>
:root {{
  color-scheme: light dark;
  --plane: #f9f9f7; --surface: #fcfcfb;
  --ink: #0b0b0b; --ink-2: #52514e; --muted: #898781;
  --grid: #e1e0d9; --axis: #c3c2b7; --border: rgba(11,11,11,.10);
  --series-1: #2a78d6;
  --state-draft: #2a78d6; --state-triage: #1baf7a;
  --state-published: #eda100; --state-closed: #008300;
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    --plane: #0d0d0d; --surface: #1a1a19;
    --ink: #fff; --ink-2: #c3c2b7; --muted: #898781;
    --grid: #2c2c2a; --axis: #383835; --border: rgba(255,255,255,.10);
    --series-1: #3987e5;
    --state-draft: #3987e5; --state-triage: #199e70;
    --state-published: #c98500; --state-closed: #008300;
  }}
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; background: var(--plane); color: var(--ink);
  font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
  font-size: 14px; line-height: 1.45;
}}
header {{ padding: 28px 32px 8px; }}
header h1 {{ margin: 0; font-size: 22px; }}
header .sub {{ color: var(--ink-2); margin-top: 4px; }}
main {{ padding: 16px 32px 48px; max-width: 1200px; }}
.tiles {{
  display: grid; gap: 12px; margin-bottom: 20px;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
}}
.tile {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 16px 18px;
}}
.tile-v {{ font-size: 30px; font-weight: 650; letter-spacing: -.02em; }}
.tile-l {{ color: var(--ink-2); font-size: 12.5px; margin-top: 2px; }}
.grid-cards {{
  display: grid; gap: 16px; margin-bottom: 16px;
  grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
}}
.card {{
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 16px 18px 18px;
}}
.card.wide {{ grid-column: 1 / -1; }}
.card h2 {{
  margin: 0 0 12px; font-size: 13px; font-weight: 600;
  text-transform: uppercase; letter-spacing: .04em; color: var(--ink-2);
  display: flex; justify-content: space-between; align-items: baseline;
}}
.card h2 .note {{
  text-transform: none; letter-spacing: 0; font-weight: 400;
  color: var(--muted); font-size: 12px;
}}
.chart {{ width: 100%; height: auto; display: block; }}
.chart .cat {{ fill: var(--ink-2); font-size: 12px; }}
.chart .val {{ fill: var(--ink); font-size: 12px; font-weight: 600;
  font-variant-numeric: tabular-nums; }}
.chart .tick {{ fill: var(--muted); font-size: 10.5px;
  font-variant-numeric: tabular-nums; }}
.chart .axis {{ stroke: var(--axis); stroke-width: 1; }}
.chart .grid {{ stroke: var(--grid); stroke-width: 1; }}
.chart .line {{ fill: none; stroke: var(--series-1); stroke-width: 2;
  stroke-linejoin: round; stroke-linecap: round; }}
.chart .area {{ fill: var(--series-1); opacity: .14; }}
.empty {{ color: var(--muted); font-size: 13px; margin: 8px 0; }}
.legend {{ display: flex; flex-wrap: wrap; gap: 12px; margin-top: 10px; }}
.lg {{ display: inline-flex; align-items: center; gap: 5px;
  font-size: 12px; color: var(--ink-2); }}
.lg .sw {{ width: 10px; height: 10px; border-radius: 3px; display: inline-block; }}
.controls {{
  display: flex; flex-wrap: wrap; gap: 8px; align-items: center;
  margin-bottom: 12px;
}}
.controls input[type=search] {{
  flex: 1 1 220px; min-width: 160px; padding: 8px 12px;
  border: 1px solid var(--border); border-radius: 8px;
  background: var(--surface); color: var(--ink); font: inherit;
}}
.chip {{
  border: 1px solid var(--border); background: var(--surface);
  color: var(--ink-2); border-radius: 999px; padding: 5px 12px;
  font: inherit; font-size: 12.5px; cursor: pointer;
}}
.chip[aria-pressed=true] {{ color: var(--ink); border-color: currentColor; }}
.chip .dot {{ display: inline-block; width: 8px; height: 8px;
  border-radius: 50%; margin-right: 5px; vertical-align: middle; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
thead th {{
  text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--axis);
  color: var(--ink-2); font-weight: 600; cursor: pointer; white-space: nowrap;
  position: sticky; top: 0; background: var(--surface);
}}
thead th .arrow {{ color: var(--muted); font-size: 10px; }}
tbody td {{ padding: 7px 10px; border-bottom: 1px solid var(--grid);
  vertical-align: top; }}
tbody td.num {{ font-variant-numeric: tabular-nums; }}
tbody tr:hover {{ background: color-mix(in srgb, var(--series-1) 6%, transparent); }}
a {{ color: var(--series-1); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.sev-chip {{ display: inline-flex; align-items: center; gap: 5px;
  white-space: nowrap; }}
.sev-chip .dot {{ width: 9px; height: 9px; border-radius: 50%; }}
.count {{ color: var(--muted); margin-left: 8px; font-size: 12px; }}
.table-wrap {{ overflow-x: auto; }}
</style>
</head>
<body>
<header>
  <h1>Zephyr security advisory dashboard</h1>
  <div class="sub">{repo} · generated {generated}</div>
</header>
<main>
  <div class="tiles">{tiles}</div>
  <div class="grid-cards">
    {severity_card}
    {state_card}
    {cwe_card}
    {cvss_card}
    {timeline_card}
  </div>
  <section class="card">
    <h2>Advisories<span class="note"><span id="count"></span></span></h2>
    <div class="controls">
      <input type="search" id="q" placeholder="Search GHSA, CVE, or summary…"
             autocomplete="off">
      <span id="sev-filters"></span>
    </div>
    <div class="table-wrap">
      <table id="tbl">
        <thead><tr>
          <th data-k="ghsa">GHSA <span class="arrow"></span></th>
          <th data-k="cve">CVE <span class="arrow"></span></th>
          <th data-k="severity">Severity <span class="arrow"></span></th>
          <th data-k="state">State <span class="arrow"></span></th>
          <th data-k="cvss">CVSS <span class="arrow"></span></th>
          <th data-k="embargo">Embargo <span class="arrow"></span></th>
          <th data-k="summary">Summary <span class="arrow"></span></th>
        </tr></thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
  </section>
</main>
<script>
const DATA = {data_json};
const SEV_COLORS = {severity_colors};
const SEV_ORDER = ["critical","high","medium","low","unknown"];
const SEV_RANK = Object.fromEntries(SEV_ORDER.map((s,i)=>[s,i]));
let sort = {{k:"created", dir:-1}};
let activeSev = new Set();

const rowsEl = document.getElementById("rows");
const countEl = document.getElementById("count");
const qEl = document.getElementById("q");

function esc(s) {{
  return String(s).replace(/[&<>"]/g, c =>
    ({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}})[c]);
}}
function sevChip(s) {{
  return '<span class="sev-chip"><span class="dot" style="background:'
    + SEV_COLORS[s] + '"></span>' + s + '</span>';
}}
function cmp(a, b, k) {{
  if (k === "severity") return SEV_RANK[a.severity] - SEV_RANK[b.severity];
  if (k === "cvss") return (a.cvss ?? -1) - (b.cvss ?? -1);
  return String(a[k]).localeCompare(String(b[k]));
}}
function render() {{
  const q = qEl.value.trim().toLowerCase();
  let rows = DATA.filter(r => {{
    if (activeSev.size && !activeSev.has(r.severity)) return false;
    if (!q) return true;
    return (r.ghsa + " " + r.cve + " " + r.summary).toLowerCase().includes(q);
  }});
  rows.sort((a, b) => cmp(a, b, sort.k) * sort.dir);
  rowsEl.innerHTML = rows.map(r => {{
    const ghsa = r.url
      ? '<a href="' + esc(r.url) + '" target="_blank" rel="noopener">'
        + esc(r.ghsa) + '</a>'
      : esc(r.ghsa);
    return "<tr>"
      + "<td>" + ghsa + "</td>"
      + "<td>" + esc(r.cve || "—") + "</td>"
      + "<td>" + sevChip(r.severity) + "</td>"
      + "<td>" + esc(r.state) + "</td>"
      + '<td class="num">' + (r.cvss ?? "—") + "</td>"
      + '<td class="num">' + esc(r.embargo || "—") + "</td>"
      + "<td>" + esc(r.summary) + "</td>"
      + "</tr>";
  }}).join("");
  countEl.textContent = rows.length + " of " + DATA.length;
  document.querySelectorAll("th[data-k]").forEach(th => {{
    const arr = th.querySelector(".arrow");
    arr.textContent = th.dataset.k === sort.k ? (sort.dir === 1 ? "▲" : "▼") : "";
  }});
}}
document.querySelectorAll("th[data-k]").forEach(th => {{
  th.addEventListener("click", () => {{
    const k = th.dataset.k;
    if (sort.k === k) sort.dir *= -1;
    else sort = {{k, dir: k === "cvss" || k === "severity" ? -1 : 1}};
    render();
  }});
}});
const sevWrap = document.getElementById("sev-filters");
SEV_ORDER.forEach(s => {{
  const b = document.createElement("button");
  b.className = "chip";
  b.setAttribute("aria-pressed", "false");
  b.innerHTML = '<span class="dot" style="background:' + SEV_COLORS[s]
    + '"></span>' + s;
  b.addEventListener("click", () => {{
    if (activeSev.has(s)) {{ activeSev.delete(s); b.setAttribute("aria-pressed","false"); }}
    else {{ activeSev.add(s); b.setAttribute("aria-pressed","true"); }}
    render();
  }});
  sevWrap.appendChild(b);
}});
qEl.addEventListener("input", render);
render();
</script>
</body>
</html>
'''
