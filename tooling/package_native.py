"""Package explicitly supplied native build artifacts without executing a JVM."""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import struct
import zipfile

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "native-recovery": (
        "META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory",
        "META-INF/services/org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory",
        "META-INF/services/org.keycloak.services.managers.BruteForceProtectorFactory",
        "META-INF/services/org.keycloak.events.EventListenerProviderFactory",
        "META-INF/services/org.keycloak.authentication.AuthenticatorFactory",
        "META-INF/firefly-native-recovery.xml",
        "META-INF/firefly-reproofing.xml",
        "META-INF/orm.xml",
        "META-INF/jandex.idx",
        "META-INF/beans.xml",
    ),
    "native-domain-gateway": (
        "META-INF/services/io.firefly.id.nativeauth.NativeCeremonyGateway$Factory",
    ),
}


def inspect(path: Path, module: str) -> dict:
    with zipfile.ZipFile(path) as archive:
        if "META-INF/services/io.firefly.id.nativeauth.NativeSupportAuthorization$Factory" in archive.namelist():
            raise ValueError("The default distribution must not activate a support authorization owner")
        for name in REQUIRED[module]:
            if not archive.read(name):
                raise ValueError(f"Empty required resource: {name}")
            if name.startswith("META-INF/services/"):
                source = ROOT / "extensions" / module / "src/main/resources" / name
                if archive.read(name).strip() != source.read_bytes().strip():
                    raise ValueError(f"Provider registration differs from this source checkout: {name}")
            if name.endswith(".xml"):
                source = ROOT / "extensions" / module / "src/main/resources" / name
                if archive.read(name) != source.read_bytes():
                    raise ValueError(f"Native installation mapping differs from this source checkout: {name}")
        for name in ("LICENSE", "NOTICE"):
            if archive.read("META-INF/" + name) != (ROOT / name).read_bytes():
                raise ValueError(f"Distribution {name} differs from this source checkout")
        classes = [name for name in archive.namelist() if name.endswith(".class")]
        if not classes:
            raise ValueError("Native artifact contains no compiled classes")
        for name in classes:
            magic, minor, major = struct.unpack(">IHH", archive.read(name)[:8])
            if magic != 0xCAFEBABE or major != 65 or minor == 65535:
                raise ValueError("Native artifacts must target Java 21 without preview features")
    return {"module": module, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "bytes": path.stat().st_size, "class_count": len(classes), "java_release": 21}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-jar", required=True, type=Path)
    parser.add_argument("--gateway-jar", required=True, type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "dist/native")
    args = parser.parse_args()
    artifacts = [(args.native_jar, "native-recovery"), (args.gateway_jar, "native-domain-gateway")]
    records = [inspect(path, module) for path, module in artifacts]
    # Refuse retained output rather than silently mixing build attempts.
    args.output.mkdir(parents=True, exist_ok=False)
    providers = args.output / "providers"
    providers.mkdir()
    for (path, module), record in zip(artifacts, records):
        target = providers / ("firefly-id-" + module + ".jar")
        shutil.copyfile(path, target)
        record["file"] = "providers/" + target.name
    manifest = {"keycloak_version": "26.8.1", "artifacts": records,
                "scope": "Installation candidate; artifact integrity is not runtime or production acceptance."}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest))


if __name__ == "__main__":
    main()
