#!/usr/bin/env python3
"""Validate the actual static handbook, not just authored Markdown paths."""
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


class Document(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.ids = set()
        self.references = []
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


def validate(site):
    pages = {path.resolve(): Document(path.read_text()) for path in site.rglob('*.html')}
    failures = []
    checked = 0
    for path, document in pages.items():
        for target in document.references:
            url = urlsplit(target)
            if url.scheme or url.netloc:
                continue
            resolved = ((site / unquote(url.path).lstrip('/')) if url.path.startswith('/')
                        else path.parent / unquote(url.path)).resolve() if url.path else path
            if not resolved.is_relative_to(site):
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
    for component in ('firefly', 'mkdocs', 'mkdocs-material'):
        if not any((site / 'assets/licenses' / component).glob('*')):
            failures.append('Distributed notice is missing: ' + component)
    manifest = json.loads((site / 'documentation-provenance.json').read_text())
    if manifest.get('source_dirty') or not manifest.get('publication_ready'):
        failures.append('Uncommitted preview cannot qualify a publishable source revision')
    if manifest['policy_sha256'] != hashlib.sha256((ROOT / 'config/authentication-policies.json').read_bytes()).hexdigest():
        failures.append('Policy provenance differs from source')
    if len(pages) < 40:
        failures.append('Public handbook inventory is incomplete')
    return {'scope': 'Static documentation output only', 'pages': len(pages),
            'local_references': checked, 'canonical_manrope': True if not failures else None,
            'source_revision': manifest['source_revision'], 'failures': failures}


if __name__ == '__main__':
    site = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / '.work/documentation/site').resolve()
    result = validate(site)
    (site.parent / 'output-summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    sys.exit(bool(result['failures']))
