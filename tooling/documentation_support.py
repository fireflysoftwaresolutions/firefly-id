"""Source mapping and generated policy reference for the public handbook."""
import json
import posixpath
from pathlib import Path
from urllib.parse import quote, urlsplit, urlunsplit


def source_provenance(head, requested, dirty):
    if requested and requested != head:
        raise ValueError('Documentation revision differs from its source checkout')
    return {'source_revision': head, 'source_dirty': bool(dirty), 'publication_ready': not dirty}


def publishable(path):
    parts = Path(path).parts
    return bool(parts) and not any(part.startswith('.') for part in parts) and parts[0] not in {
        'superpowers', 'overrides', 'private-source-index.example.json',
        'progress.md', 'evidence.md', 'identity-proofing-evaluation.md', 'documentation.md',
    }


def rewrite_target(target, page_path, root, source_url, image=False):
    url = urlsplit(target)
    if url.scheme or url.netloc or not url.path or url.path.startswith('/'):
        return target
    root = Path(root).resolve()
    docs = root / 'docs'
    resolved = (docs / Path(page_path).parent / url.path).resolve()
    if not resolved.is_relative_to(root):
        raise ValueError('Documentation link escapes the repository')
    relative = resolved.relative_to(root).as_posix()
    if any(part.startswith('.') for part in resolved.relative_to(root).parts):
        raise ValueError('Documentation link targets private working state')
    if resolved.is_relative_to(docs) and publishable(resolved.relative_to(docs)):
        return target
    if not resolved.exists():
        raise ValueError('Documentation source link targets a missing file: ' + relative)
    if image and relative.startswith('assets/'):
        local = posixpath.relpath(relative, Path(page_path).parent.as_posix())
        return urlunsplit(('', '', local, url.query, url.fragment))
    base = source_url.replace('/blob/', '/tree/') if resolved.is_dir() else source_url
    result = base.rstrip('/') + '/' + quote(relative, safe='/')
    return urlunsplit((*urlsplit(result)[:3], url.query, url.fragment))


def policy_reference(catalogue):
    if catalogue.get('schemaVersion') != 1:
        raise ValueError('Unsupported authentication policy catalogue')
    text = ['# Default realm settings', '',
            'Use this reference for the population settings supplied with the local environment. '
            'The values are not a regulatory certification; select the factor and session settings '
            'appropriate to each deployed journey.', '',
            'Read [authentication policies](../authentication-policies.md) for enforcement and '
            '[EU and US controls](../controls-matrix.md) for applicability.', '',
            '## Shared brute-force settings', '', '| Property | Value |', '| --- | --- |']
    def value(item):
        return json.dumps(item, ensure_ascii=False).replace('|', '\\|')
    text.extend(f'| `{key}` | `{value(item)}` |' for key, item in catalogue['defaults'].items())
    mfa = {
        'customers': 'Optional in the synthetic customer profile; this is not a banking SCA policy.',
        'workforce': 'Required password and OTP in the workforce browser flow.',
        'institutions': 'Optional in the synthetic institutional-human profile; organizational authority is separate.',
        'administrators': 'Configure permanent administrator phishing-resistant MFA and remove temporary bootstrap access before operating privileged administration.',
    }
    for name, profile in catalogue['profiles'].items():
        text.extend(['', '## ' + name.capitalize(), '', profile['population'], '',
                     f"Application mechanism: `{profile['application']}`. Catalogue `mfaRequired`: "
                     f"`{value(profile['mfaRequired'])}`. {mfa[name]}", '',
                     '| Realm property | Value |', '| --- | --- |'])
        text.extend(f'| `{key}` | `{value(item)}` |' for key, item in profile['realmSettings'].items())
    text.extend(['', '## Applying a change', '',
                 'The local generator applies these values when creating new realms. For an existing realm, '
                 'apply the selected settings through the Admin Console or authorized Admin API, '
                 'then verify the effective values. Import does not overwrite an existing realm. '
                 'Enroll required factors and configure application inactivity separately; editing '
                 'the catalogue does not migrate retained users.', ''])
    return '\n'.join(text)
