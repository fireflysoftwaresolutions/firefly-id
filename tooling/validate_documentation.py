#!/usr/bin/env python3
"""Validate the actual static handbook, not just authored Markdown paths."""
import base64
import hashlib
from html.parser import HTMLParser
import json
import math
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids = set()
        self.references = []
        self.text = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id'):
            self.ids.add(attrs['id'])
        for name in ('href', 'src'):
            if attrs.get(name):
                self.references.append(attrs[name])
        if attrs.get('srcset'):
            self.references.extend(item.strip().split()[0] for item in attrs['srcset'].split(','))

    def handle_data(self, data):
        self.text.append(data)


def local_path(site, page, target, base_path='/firefly-id/'):
    decoded = unquote(target)
    if decoded.startswith('/'):
        if not decoded.startswith(base_path):
            raise ValueError('Absolute reference is outside the project')
        resolved = (site / decoded[len(base_path):]).resolve()
    else:
        resolved = (page.parent / decoded).resolve() if decoded else page
    if not resolved.is_relative_to(site):
        raise ValueError('Reference escapes site')
    return resolved


def validate_svg(path, font, mode=None):
    failures = []
    source = path.read_text()
    try:
        svg = ET.fromstring(source)
    except ET.ParseError:
        return ['Malformed SVG: ' + path.name]
    namespace = '{http://www.w3.org/2000/svg}'
    if svg.tag != namespace + 'svg':
        failures.append('Missing SVG root: ' + path.name)
    viewbox = []
    try:
        viewbox = [float(value) for value in svg.get('viewBox', '').replace(',', ' ').split()]
        if len(viewbox) != 4 or not all(math.isfinite(value) for value in viewbox) or min(viewbox[2:]) <= 0:
            raise ValueError
    except ValueError:
        failures.append('Invalid SVG viewBox: ' + path.name)
    if not any(''.join(text.itertext()).strip() for text in svg.iter(namespace + 'text')):
        failures.append('Diagram has no visible text source: ' + path.name)
    ids = {element.get('id'): element for element in svg.iter() if element.get('id')}
    title = svg.get('aria-labelledby', '').split()
    if not title or any(name not in ids or not ''.join(ids[name].itertext()).strip() for name in title):
        failures.append('Diagram has no accessible title: ' + path.name)
    font_uri = 'data:font/woff2;base64,' + base64.b64encode(font).decode()
    if font_uri not in source:
        failures.append('Diagram does not embed canonical Manrope: ' + path.name)
    for element in svg.iter():
        if element.tag.rsplit('}', 1)[-1] in {'script', 'foreignObject'}:
            failures.append('Executable SVG content: ' + path.name)
        for name, value in element.attrib.items():
            local = name.rsplit('}', 1)[-1]
            if local.lower().startswith('on') or (local == 'href' and not value.startswith('#')):
                failures.append('Executable or external SVG reference: ' + path.name)
    for target in re.findall(r'url\([\'"]?([^\)\'"\s]+)', source):
        if not target.startswith('#') and target != font_uri:
            failures.append('Unpackaged SVG resource: ' + path.name)
    if mode:
        try:
            dimensions = [float(svg.get(name, '')) for name in ('width', 'height')]
            if len(viewbox) != 4 or any(not math.isfinite(value) or abs(value - expected) > 0.01
                                        for value, expected in zip(dimensions, viewbox[2:])):
                raise ValueError
        except ValueError:
            failures.append('Diagram dimensions do not match its intrinsic viewBox: ' + path.name)
        expected = 'rgb(39, 40, 32)' if mode == 'dark' else 'rgb(255, 255, 255)'
        if not re.search(r'background-color:\s*' + re.escape(expected), svg.get('style', '')):
            failures.append('Standalone diagram background is missing: ' + path.name)
    return failures


def validate_diagram_inventory(folder, diagrams):
    expected = {diagram['id'] + '-' + mode + '.svg' for diagram in diagrams for mode in ('light', 'dark')}
    actual = {path.name for path in folder.glob('*.svg')}
    return (['Missing diagram variant: ' + name for name in sorted(expected - actual)] +
            ['Stale diagram variant: ' + name for name in sorted(actual - expected)])


def validate(site):
    from documentation_diagrams import extract
    from documentation_support import publishable
    diagrams = []
    for source in sorted((ROOT / 'docs').rglob('*.md')):
        relative = source.relative_to(ROOT / 'docs').as_posix()
        if publishable(relative):
            diagrams.extend(extract(source.read_text(), relative))
    pages = {path.resolve(): Document(path.read_text()) for path in site.rglob('*.html')}
    folder = site / 'assets/diagrams/generated'
    failures = validate_diagram_inventory(folder, diagrams)
    font_bytes = (ROOT / 'assets/brand/fonts/manrope-latin-wght-normal.woff2').read_bytes()
    diagram_files = sorted((site / 'assets/diagrams').rglob('*.svg'))
    for path in diagram_files:
        mode = path.stem.rsplit('-', 1)[-1] if path.parent == folder else None
        failures.extend(validate_svg(path, font_bytes, mode=mode))
    referenced = {urlsplit(target).path.rsplit('/', 1)[-1] for document in pages.values() for target in document.references}
    for path in folder.glob('*.svg'):
        if path.name not in referenced:
            failures.append('Unreferenced diagram variant: ' + path.name)
    checked = 0
    for path, document in pages.items():
        visible = ' '.join(' '.join(document.text).split()).lower()
        if any(phrase in visible for phrase in ('integration contract review', 'reviewed public sources',
                                                'reviewed commit', 'current qualification', 'source-parent', 'draft pr', 'still pending')):
            failures.append('Internal engineering narrative entered product page: ' + path.relative_to(site).as_posix())
        for target in document.references:
            url = urlsplit(target)
            if url.scheme or url.netloc:
                continue
            try:
                resolved = local_path(site, path, url.path)
            except ValueError:
                failures.append('Link escapes site: ' + path.relative_to(site).as_posix())
                continue
            if resolved.is_dir():
                resolved /= 'index.html'
            checked += 1
            if not resolved.is_file():
                failures.append('Missing local target: ' + path.relative_to(site).as_posix() + ' -> ' + url.path)
            elif url.fragment and resolved in pages and unquote(url.fragment) not in pages[resolved].ids:
                failures.append('Missing local anchor: ' + path.relative_to(site).as_posix() + ' -> ' + target)
    for path in site.rglob('*'):
        relative = path.relative_to(site)
        if path.is_symlink() or any(part.startswith('.') or part in {'superpowers', 'overrides', 'node_modules', 'target'} for part in relative.parts):
            failures.append('Excluded source entered output: ' + relative.as_posix())
        if path.name in {'credentials.json', 'ownership.json', 'private-source-index.example.json'} or path.suffix == '.log':
            failures.append('Private evidence entered output: ' + relative.as_posix())
    css = site / 'stylesheets/extra.css'
    for target in re.findall(r'url\([\'"]?([^\)\'"\s]+)', css.read_text()):
        url = urlsplit(target)
        if url.scheme or url.netloc or not (css.parent / target).resolve().is_file():
            failures.append('Stylesheet asset is not locally packaged')
    font = Path('assets/brand/fonts/manrope-latin-wght-normal.woff2')
    if (site / font).read_bytes() != (ROOT / font).read_bytes():
        failures.append('Canonical Manrope bytes changed')
    for component in ('firefly', 'mkdocs', 'mkdocs-material', 'mermaid'):
        if not any((site / 'assets/licenses' / component).glob('*')):
            failures.append('Distributed notice is missing: ' + component)
    search = json.loads((site / 'search/search_index.json').read_text())
    internal = ('identity-proofing-evaluation', 'progress/', 'evidence/', 'documentation/')
    if any(any(name in item.get('location', '') for name in internal) for item in search.get('docs', [])):
        failures.append('Internal report entered product search')
    if any((site / name / 'index.html').exists() for name in ('identity-proofing-evaluation', 'progress', 'evidence', 'documentation')):
        failures.append('Internal report entered product publication')
    manifest = json.loads((site / 'documentation-provenance.json').read_text())
    if manifest.get('source_dirty') or not manifest.get('publication_ready'):
        failures.append('Uncommitted preview cannot qualify a publishable source revision')
    if manifest['policy_sha256'] != hashlib.sha256((ROOT / 'config/authentication-policies.json').read_bytes()).hexdigest():
        failures.append('Policy provenance differs from source')
    if len(pages) < 40:
        failures.append('Public handbook inventory is incomplete')
    return {'scope': 'Static documentation output only', 'pages': len(pages),
            'local_references': checked, 'diagrams': len(diagrams), 'diagram_svg_assets': len(diagram_files), 'canonical_manrope': True if not failures else None,
            'source_revision': manifest['source_revision'], 'failures': failures}


if __name__ == '__main__':
    site = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / '.work/documentation/site').resolve()
    result = validate(site)
    (site.parent / 'output-summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    sys.exit(bool(result['failures']))
