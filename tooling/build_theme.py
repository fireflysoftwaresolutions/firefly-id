"""Build a deterministic, self-contained Keycloak theme archive and directory."""

import hashlib
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
KINDS = ("login", "account", "admin", "email", "welcome")


def build(output: Path) -> Path:
    entries = {}
    for source in sorted((ROOT / "themes/firefly-id").rglob("*")):
        if source.is_file():
            entries["theme/firefly-id/" + source.relative_to(ROOT / "themes/firefly-id").as_posix()] = source.read_bytes()
    for source in sorted((ROOT / "themes/firefly-id-native").rglob("*")):
        if source.is_file():
            entries["theme/firefly-id-native/" + source.relative_to(ROOT / "themes/firefly-id-native").as_posix()] = source.read_bytes()
    for kind in ("login", "account", "admin", "welcome"):
        prefix = f"theme/firefly-id/{kind}/resources/"
        entries[prefix + "css/firefly-tokens.css"] = (ROOT / "themes/tokens.css").read_bytes()
        entries[prefix + "css/firefly-icons.css"] = (ROOT / "themes/icons.css").read_bytes()
        for source in sorted((ROOT / "assets/icons").rglob("*")):
            if source.is_file():
                entries[prefix + "img/icons/" + source.relative_to(ROOT / "assets/icons").as_posix()] = source.read_bytes()
        if kind in ("account", "admin"):
            entries[prefix + "css/firefly-console.css"] = (ROOT / "themes/console.css").read_bytes()
            entries[prefix + "js/copyright.js"] = (ROOT / "themes/console-copyright.js").read_bytes()
            entries[prefix + "js/presentation-policy.js"] = (ROOT / "themes/console-policy.js").read_bytes()
        for variant in ("light", "dark"):
            entries[prefix + f"img/wordmark-{variant}.svg"] = (ROOT / f"assets/brand/firefly-id-{variant}.svg").read_bytes()
        entries[prefix + "img/favicon.svg"] = (ROOT / "assets/brand/favicon.svg").read_bytes()
        entries[prefix + "fonts/manrope.woff2"] = (ROOT / "assets/brand/fonts/manrope-latin-wght-normal.woff2").read_bytes()
        entries[prefix + "fonts/OFL.txt"] = (ROOT / "assets/brand/fonts/OFL.txt").read_bytes()
    entries["META-INF/keycloak-themes.json"] = (json.dumps({"themes": [
        {"name": "firefly-id", "types": list(KINDS)},
        {"name": "firefly-id-native", "types": ["login", "account"]}]}, indent=2) + "\n").encode()
    entries["META-INF/LICENSE"] = (ROOT / "LICENSE").read_bytes()
    entries["META-INF/NOTICE"] = (ROOT / "NOTICE").read_bytes()
    entries["theme/firefly-id/LICENSE"] = (ROOT / "LICENSE").read_bytes()
    entries["theme/firefly-id/NOTICE"] = (ROOT / "NOTICE").read_bytes()
    entries["META-INF/licenses/lucide-ISC-MIT.txt"] = (ROOT / "assets/icons/LICENSE").read_bytes()
    for variant in ("light", "dark", "mobile-light", "mobile-dark"):
        entries[f"theme/firefly-id/login/resources/img/authentication-{variant}.svg"] = (
            ROOT / f"assets/identity-backgrounds/authentication-{variant}.svg").read_bytes()
    target = output / "firefly-id-theme.jar"
    checksums = output / "SHA256SUMS"
    unpacked = {output / "themes" / name.removeprefix("theme/"): data
                for name, data in entries.items() if name.startswith("theme/")}
    directories = set()
    for path in unpacked:
        parent = path.parent
        while parent != output:
            directories.add(parent)
            parent = parent.parent
    if any(path.is_symlink() for path in {output, target, checksums, *unpacked, *directories}):
        raise ValueError("Theme output targets must not be symlinks")
    output.mkdir(parents=True, exist_ok=True)
    # Bind-mounted public themes must remain readable by the nonroot server regardless of the caller's umask.
    for directory in sorted(directories, key=lambda path: (len(path.parts), str(path))):
        directory.mkdir(exist_ok=True)
        directory.chmod(0o755)
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(entries.items()):
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    target.chmod(0o644)
    for path, data in unpacked.items():
        path.write_bytes(data)
        path.chmod(0o644)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    checksums.write_text(f"{digest}  {target.name}\n")
    checksums.chmod(0o644)
    return target


if __name__ == "__main__":
    print(build(ROOT / "dist").relative_to(ROOT))
