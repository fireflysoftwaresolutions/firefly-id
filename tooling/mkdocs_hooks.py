"""Publish authored guides and original assets without duplicating their source."""
import hashlib
import base64
from importlib.metadata import distribution
import json
import os
from pathlib import Path
import re
import subprocess
from mkdocs.structure.files import File
from documentation_support import policy_reference, publishable, rewrite_target, source_provenance
from documentation_diagrams import extract as extract_diagrams, replace as replace_diagrams

ROOT = Path(__file__).resolve().parents[1]
HEAD = subprocess.check_output(
    ['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
DIRTY = bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=normal'], cwd=ROOT, text=True).strip())
PROVENANCE = source_provenance(HEAD, os.environ.get('DOCS_SOURCE_SHA'), DIRTY)
REVISION = PROVENANCE['source_revision']
if not re.fullmatch('[0-9a-f]{40}', REVISION):
    raise ValueError('An exact documentation source revision is required')
SOURCE = 'https://github.com/fireflysoftwaresolutions/firefly-id/blob/' + REVISION
LINK = re.compile(r'(!?\[[^\]\n]*\]\()([^\s)]+)([^)\n]*\))')


def on_files(files, config, **kwargs):
    for item in list(files):
        if not publishable(item.src_uri):
            files.remove(item)
        elif item.src_uri.startswith('assets/diagrams/') and item.src_uri.endswith('.svg'):
            content = Path(item.abs_src_path).read_text()
            font = base64.b64encode((ROOT / 'assets/brand/fonts/manrope-latin-wght-normal.woff2').read_bytes()).decode()
            files.remove(item)
            files.append(File.generated(config, item.src_uri, content=content.replace('__MANROPE_DATA_URI__', 'data:font/woff2;base64,' + font)))
    catalogue = json.loads((ROOT / 'config/authentication-policies.json').read_text())
    files.append(File.generated(config, 'reference/effective-defaults.md', content=policy_reference(catalogue)))
    images = json.loads((ROOT / 'deploy/images.lock.json').read_text())
    versions = ['# Supported versions', '',
                'Use the following pinned component versions when building the distribution and local environment. '
                'Keep native providers aligned with the server version.', '',
                '| Component | Version | Use |', '| --- | --- | --- |',
                '| Keycloak | 26.8.1 | Authentication server and native provider APIs |',
                '| PostgreSQL | 17.11 | Identity database in the supplied environment |',
                '| Java | 21 | Native providers and gateway |',
                '| Manrope | Bundled variable font | Web typography |', '',
                '## Immutable container images', '',
                'Use the exact references below or the maintained [image lock](../../deploy/images.lock.json) '
                'when building. Review upstream release notes and rehearse migrations before changing versions.', '',
                '| Component | Exact image |', '| --- | --- |']
    versions.extend(f"| {name} | `{images[name]['image']}` |" for name in ('keycloak', 'postgres', 'mailpit'))
    versions.extend(['', 'Mailpit is the local mail sink. Configure an authenticated production notification channel '
                     'instead of promoting the local mail settings.', '',
                     'See [operations](../operations.md), [native installation](../native-recovery.md) and '
                     '[backup and recovery](../retained-data.md) for upgrade and compatibility steps.', ''])
    files.append(File.generated(config, 'reference/versions.md', content='\n'.join(versions)))
    for item in list(files):
        authored = ROOT / 'docs' / item.src_uri
        if item.src_uri.endswith('.md') and authored.is_file():
            for diagram in extract_diagrams(authored.read_text(), item.src_uri):
                for mode in ('light', 'dark'):
                    name = diagram['id'] + '-' + mode + '.svg'
                    rendered = ROOT / '.work/documentation/diagrams' / name
                    if not rendered.is_file():
                        raise ValueError('Build the static product diagrams before MkDocs: ' + item.src_uri)
                    files.append(File.generated(config, 'assets/diagrams/generated/' + name, abs_src_path=str(rendered)))
    for asset in sorted((ROOT / 'assets').rglob('*')):
        if asset.is_file() and (asset.suffix in {'.svg', '.woff2'} or asset.name == 'OFL.txt'):
            files.append(File.generated(config, asset.relative_to(ROOT).as_posix(), abs_src_path=str(asset)))
    for name in ('LICENSE', 'NOTICE'):
        files.append(File.generated(config, 'assets/licenses/firefly/' + name, abs_src_path=str(ROOT / name)))
    mermaid_license = ROOT / '.work/docs-diagrams/node_modules/mermaid/LICENSE'
    if not mermaid_license.is_file():
        raise ValueError('Install the pinned diagram builder before building documentation')
    files.append(File.generated(config, 'assets/licenses/mermaid/LICENSE.txt', abs_src_path=str(mermaid_license)))
    for name in ('mkdocs', 'mkdocs-material'):
        package = distribution(name)
        licenses = [item for item in package.files or [] if item.name.lower() in {'license', 'license.md', 'license.txt', 'copying'}]
        if not licenses:
            raise ValueError('Documentation package license is missing: ' + name)
        for index, license_file in enumerate(licenses):
            files.append(File.generated(config, f'assets/licenses/{name}/{index}-{license_file.name}.txt',
                                        abs_src_path=str(package.locate_file(license_file))))
    return files


def on_page_markdown(markdown, page, **kwargs):
    def replace(match):
        target = rewrite_target(match[2], page.file.src_uri, ROOT, SOURCE, image=match[1].startswith('!'))
        return match[1] + target + match[3]
    result = replace_diagrams(LINK.sub(replace, markdown), page.file.src_uri, page.url)
    if DIRTY:
        result = '!!! warning "Uncommitted documentation preview"\n    This checkout contains uncommitted source. Repository links refer to its committed baseline; this build cannot be published as exact-source evidence.\n\n' + result
    return result


def on_post_build(config, **kwargs):
    site = Path(config.site_dir)
    manifest = {
        'scope': 'Documentation build only; not CIAM production or legal/provider acceptance',
        **PROVENANCE,
        'policy_sha256': hashlib.sha256((ROOT / 'config/authentication-policies.json').read_bytes()).hexdigest(),
        'manrope_sha256': hashlib.sha256((ROOT / 'assets/brand/fonts/manrope-latin-wght-normal.woff2').read_bytes()).hexdigest(),
        'pages': sorted(p.relative_to(site).as_posix() for p in site.rglob('*.html')),
    }
    (site / 'documentation-provenance.json').write_text(json.dumps(manifest, indent=2) + '\n')
