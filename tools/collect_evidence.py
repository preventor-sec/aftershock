"""Collect explicit installed runtime observations; no target HTTP requests or uploads.

Runs version commands only on this machine, or inside specifically named Docker
containers. This is installed-binary evidence, not attestation of running workers.
Inspect this script before running it in your environment.
"""
import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

COMMANDS = [("PHP", ["php", "-v"], r"PHP (\d+\.\d+\.\d+[^\s]*)"),
            ("Node.js", ["node", "--version"], r"v(\d+\.\d+\.\d+[^\s]*)"),
            ("NGINX", ["nginx", "-v"], r"nginx/(\d+\.\d+\.\d+[^\s]*)")]

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def run(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=10, check=False, shell=False)
        return (result.stdout + "\n" + result.stderr)[:10000] if result.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""

def collect(args):
    components = []
    scopes = args.container or [None]
    docker = shutil.which("docker") if args.container else None
    if args.container and not docker:
        raise ValueError("Docker executable was not found.")
    for container in scopes:
        if container and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", container):
            raise ValueError("Use an exact container name, without flags or shell syntax.")
        revision = "not supplied"
        if container:
            image = run([docker, "inspect", "--format", "{{.Image}}", container]).strip()
            if not image:
                raise ValueError(f"Cannot inspect container {container}.")
            revision = image
        for runtime, command, pattern in COMMANDS:
            if container:
                argv = [docker, "exec", container, *command]
            else:
                binary = shutil.which(command[0])
                if not binary:
                    continue
                argv = [binary, *command[1:]]
            match = re.search(pattern, run(argv))
            if not match:
                continue
            scope = container or args.name
            components.append({"id": f"{scope}:{command[0]}", "name": f"{scope} / {runtime}",
                "runtime": runtime, "version": match.group(1), "environment": args.environment,
                "revision": revision, "collectedAt": now(),
                "source": "Installed binary in named container; running process unverified" if container else "Local CLI binary; deployment unverified",
                "evidenceType": "installed-binary", "config": {}})
    if not components:
        raise ValueError("No supported runtime version found. No evidence file was written.")
    return {"schemaVersion": "1.0", "target": args.target, "capturedAt": now(), "components": components}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--target", required=True, help="App URL used only as a label")
    p.add_argument("--container", action="append", help="Exact existing Docker container name; repeat for more")
    p.add_argument("--name", default="local-host", help="Stable component name for local evidence")
    p.add_argument("--environment", default="local", help="Environment represented by these observations")
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    target = urlsplit(args.target)
    if target.scheme not in ("https", "http") or not target.hostname or target.username or target.password:
        p.error("Use an HTTP(S) target without credentials.")
    args.target = f"{target.scheme}://{target.netloc}"
    try:
        bundle = collect(args)
        with args.output.open("x", encoding="utf-8") as out:
            json.dump(bundle, out, indent=2)
        print(f"Wrote {len(bundle['components'])} observations to {args.output}.")
        print("No data uploaded. These are installed binaries, not verified running-process versions.")
    except (ValueError, OSError) as error:
        p.error(str(error))

if __name__ == "__main__":
    main()
