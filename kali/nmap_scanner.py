#!/usr/bin/env python3
"""ThreatMesh Kali collector: scope kontrolu + Nmap XML uretimi.

Kullanim (MAC/vendor icin root gerekir):
  sudo python3 kali/nmap_scanner.py --profile home_hotspot --mode discovery
  sudo python3 kali/nmap_scanner.py --profile home_hotspot --mode services
"""
import argparse
import ipaddress
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "config" / "scope.yaml"
DEFAULT_OUT = ROOT / "data" / "incoming"

# V1: NSE scripti yok, sadece host discovery ve servis/surum tespiti.
MODES = {
    "discovery": ["-sn"],
    "services": ["-sV", "--top-ports", "100", "-T3"],
}


def load_profile(cfg_path, name):
    cfg = yaml.safe_load(Path(cfg_path).read_text(encoding="utf-8")) or {}
    profile = (cfg.get("profiles") or {}).get(name)
    if profile is None:
        sys.exit(f"[!] Profil bulunamadi: {name}")
    if profile.get("authorized") is not True:
        sys.exit(f"[!] '{name}' profilinde authorized: true yok. Tarama reddedildi.")
    subnets = [ipaddress.ip_network(s, strict=False) for s in profile.get("subnets") or []]
    if not subnets:
        sys.exit(f"[!] '{name}' profilinde subnets bos. Once scope.yaml'i doldur.")
    excludes = [str(ipaddress.ip_network(x, strict=False)) for x in profile.get("exclude") or []]
    return subnets, excludes


def check_targets(targets, subnets):
    for t in targets:
        net = ipaddress.ip_network(t, strict=False)
        ok = any(net.version == s.version and net.subnet_of(s) for s in subnets)
        if not ok:
            sys.exit(f"[!] Hedef scope disinda: {t}")


def main():
    ap = argparse.ArgumentParser(description="ThreatMesh Nmap collector")
    ap.add_argument("--profile", required=True)
    ap.add_argument("--mode", choices=MODES, default="discovery")
    ap.add_argument("--target", help="Scope icinde alt hedef (CIDR/IP). Bos: tum subnetler")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG))
    ap.add_argument("--out", default=str(DEFAULT_OUT), help="Cikti klasoru (Shared Folder olabilir)")
    ap.add_argument("--sensor-id", default="kali-01")
    args = ap.parse_args()

    if shutil.which("nmap") is None:
        sys.exit("[!] nmap bulunamadi: sudo apt install nmap")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("[i] Root degilsin: MAC/vendor bilgisi gelmeyebilir. sudo ile calistir.", file=sys.stderr)

    subnets, excludes = load_profile(args.config, args.profile)
    targets = [args.target] if args.target else [str(s) for s in subnets]
    check_targets(targets, subnets)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    started = datetime.now(timezone.utc)
    stem = f"scan_{started.strftime('%Y%m%dT%H%M%SZ')}_{args.mode}"
    xml_path = out_dir / f"{stem}.xml"

    cmd = ["nmap", *MODES[args.mode]]
    if excludes:
        cmd += ["--exclude", ",".join(excludes)]
    cmd += ["-oX", str(xml_path), *targets]

    print("[*] Komut:", " ".join(cmd))
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        sys.exit(f"[!] Nmap hata kodu {e.returncode}")

    meta = {
        "sensor_id": args.sensor_id,
        "profile": args.profile,
        "mode": args.mode,
        "targets": targets,
        "excludes": excludes,
        "started_at": started.isoformat(timespec="seconds"),
        "nmap_args": " ".join(cmd),
    }
    xml_path.with_suffix(".json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[+] Bitti: {xml_path}")


if __name__ == "__main__":
    main()
