"""Deterministic source and paired static-figure markup for product diagrams."""
import hashlib
import html
from pathlib import PurePosixPath
import re

BLOCK = re.compile(r'^```mermaid\s*\n(.*?)^```\s*$', re.MULTILINE | re.DOTALL)


def extract(markdown, page):
    result = []
    heading = next((line[2:].strip() for line in markdown.splitlines() if line.startswith('# ')), 'Flow')
    for index, match in enumerate(BLOCK.finditer(markdown), 1):
        source = match[1].strip()
        if '%%{' in source or source.startswith('---') or re.search(r'^\s*click\s', source, re.MULTILINE):
            raise ValueError('Diagram configuration and executable links belong to the strict renderer')
        if source.startswith(('sequenceDiagram', 'stateDiagram')):
            for line in source.splitlines():
                literal = re.sub(r'#[a-zA-Z0-9]+;', '', line)
                if '->' in literal and ':' in literal and ';' in literal:
                    raise ValueError('Escape a message semicolon with the Mermaid #59; entity')
        key = hashlib.sha256((page + '\n' + source).encode()).hexdigest()[:24]
        result.append({'id': key, 'source': source, 'title': heading + ' — diagram ' + str(index), 'page': page})
    return result


def replace(markdown, page, page_url):
    diagrams = iter(extract(markdown, page))
    prefix = '../' * len(PurePosixPath(page_url).parts)
    def figure(match):
        diagram = next(diagrams)
        title = html.escape(diagram['title'], quote=True)
        path = prefix + 'assets/diagrams/generated/' + diagram['id']
        variants = []
        for mode in ('light', 'dark'):
            variants.append(f'<a class="diagram-{mode}" href="{path}-{mode}.svg" aria-label="Open full diagram: {title}">'
                            f'<img src="{path}-{mode}.svg" alt="{title}"></a>')
        return ('\n\n<figure class="flow-figure"><div class="flow-scroll" tabindex="0" role="region" '
                f'aria-label="{title}">' + ''.join(variants) + '</div>'
                '<figcaption>Open the diagram to view it at full size. Wide diagrams can be scrolled horizontally.</figcaption></figure>\n\n')
    return BLOCK.sub(figure, markdown)


if __name__ == '__main__':
    import json
    from pathlib import Path
    from documentation_support import publishable
    root = Path(__file__).resolve().parents[1]
    diagrams = []
    for page in sorted((root / 'docs').rglob('*.md')):
        name = page.relative_to(root / 'docs').as_posix()
        if publishable(name):
            diagrams.extend(extract(page.read_text(), name))
    print(json.dumps(diagrams))
