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
    entries["META-INF/keycloak-themes.json"] = (json.dumps({"themes": [{"name": "firefly-id", "types": list(KINDS)}]}, indent=2) + "\n").encode()
    entries["META-INF/LICENSE"] = (ROOT / "LICENSE").read_bytes()
    entries["META-INF/NOTICE"] = (ROOT / "NOTICE").read_bytes()
    entries["theme/firefly-id/LICENSE"] = (ROOT / "LICENSE").read_bytes()
    entries["theme/firefly-id/NOTICE"] = (ROOT / "NOTICE").read_bytes()
    entries["META-INF/licenses/lucide-ISC-MIT.txt"] = (ROOT / "assets/icons/LICENSE").read_bytes()
    for variant in ("light", "dark", "mobile-light", "mobile-dark"):
        entries[f"theme/firefly-id/login/resources/img/authentication-{variant}.svg"] = (
            ROOT / f"assets/identity-backgrounds/authentication-{variant}.svg").read_bytes()
    output.mkdir(parents=True, exist_ok=True)
    target = output / "firefly-id-theme.jar"
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, data in sorted(entries.items()):
            info = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
            if name.startswith("theme/"):
                unpacked = output / "themes" / name.removeprefix("theme/")
                unpacked.parent.mkdir(parents=True, exist_ok=True)
                unpacked.write_bytes(data)
    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    (output / "SHA256SUMS").write_text(f"{digest}  {target.name}\n")
    return target


if __name__ == "__main__":
    print(build(ROOT / "dist").relative_to(ROOT))
