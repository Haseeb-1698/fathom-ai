#!/usr/bin/env python3
"""
do_gpu_watcher.py — Polls Digital Ocean for MI300X GPU availability.
When available in atl1, deploys a droplet, runs LlamaFactory smoke test,
and sends an email notification.

Required env vars:
  DO_API_KEY       — Digital Ocean API token
  HF_TOKEN         — HuggingFace token (for dataset download)
  NOTIFY_FROM      — Gmail address to send from
  NOTIFY_PASS      — Gmail App Password (accounts.google.com/AppPasswords)
  NOTIFY_TO        — Destination email (default: i22198@nu.edu.pk)

Optional:
  POLL_INTERVAL    — Seconds between polls (default: 60)
  TARGET_REGION    — DO region slug (default: atl1)
"""

import os
import sys
import time
import json
import smtplib
import logging
import subprocess
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import requests

# ─── Config ──────────────────────────────────────────────────────────────────
DO_API_KEY     = os.environ["DO_API_KEY"]
HF_TOKEN       = os.environ["HF_TOKEN"]
NOTIFY_FROM    = os.environ.get("NOTIFY_FROM", "")
NOTIFY_PASS    = os.environ.get("NOTIFY_PASS", "")
NOTIFY_TO      = os.environ.get("NOTIFY_TO", "i22198@nu.edu.pk")
POLL_INTERVAL  = int(os.environ.get("POLL_INTERVAL", "60"))
# All MI300X plans to watch (x1 preferred, x8 if x1 not available)
TARGET_PLANS = [
    {"slug": "gpu-mi300x1-192gb",   "label": "MI300X x1 (192GB)",   "priority": 1},
    {"slug": "gpu-mi300x8-1536gb",  "label": "MI300X x8 (1.5TB)",   "priority": 2},
]

# All DO regions to check (ordered by preference — US first, then EU/APAC)
ALL_REGIONS = [
    "atl1", "ric1", "nyc3", "nyc1", "nyc2", "sfo3", "sfo2",
    "ams3", "fra1", "lon1", "tor1", "sgp1", "syd1", "blr1",
]

DO_SSH_KEY_ID  = 55202822                   # FYP key on DO account
DO_IMAGE       = "ubuntu-22-04-x64"

HEADERS = {
    "Authorization": f"Bearer {DO_API_KEY}",
    "Content-Type": "application/json",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("/workspace/logs/do_watcher.log"),
    ],
)
log = logging.getLogger(__name__)

# ─── Email ────────────────────────────────────────────────────────────────────
SMTP_HOST = os.environ.get("SMTP_HOST", "mail.onichealth.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SMTP_USER", "alert@onichealth.com")
SMTP_PASS = os.environ.get("SMTP_PASS", "123onichealth")


def send_email(subject: str, body: str):
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SMTP_USER
        msg["To"]      = NOTIFY_TO
        msg.attach(MIMEText(body, "plain"))
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=30) as s:
            s.login(SMTP_USER, SMTP_PASS)
            s.sendmail(SMTP_USER, NOTIFY_TO, msg.as_string())
        log.info(f"Email sent to {NOTIFY_TO}: {subject}")
    except Exception as e:
        log.error(f"Email failed: {e}")


# ─── DO API helpers ───────────────────────────────────────────────────────────
def check_availability() -> dict | None:
    """
    Check all MI300X plans across all regions.
    Returns first available match as {"slug": ..., "region": ..., "label": ...}
    or None if nothing available. Prefers x1 over x8, US regions first.
    """
    r = requests.get("https://api.digitalocean.com/v2/sizes?per_page=200", headers=HEADERS, timeout=15)
    r.raise_for_status()
    sizes = {s["slug"]: s["regions"] for s in r.json()["sizes"]}

    # Check in priority order: x1 before x8, preferred regions first
    for plan in sorted(TARGET_PLANS, key=lambda p: p["priority"]):
        available_regions = sizes.get(plan["slug"], [])
        for region in ALL_REGIONS:
            if region in available_regions:
                return {"slug": plan["slug"], "region": region, "label": plan["label"]}

    return None


def create_droplet(slug: str, region: str) -> dict:
    """Create MI300X GPU droplet and return droplet dict."""
    payload = {
        "name": f"fathom-gpu-{datetime.now().strftime('%m%d-%H%M')}",
        "region": region,
        "size": slug,
        "image": DO_IMAGE,
        "ssh_keys": [DO_SSH_KEY_ID],
        "tags": ["fathom", "gpu", "training"],
        "user_data": build_cloud_init(),
    }
    r = requests.post("https://api.digitalocean.com/v2/droplets", headers=HEADERS, json=payload, timeout=30)
    if r.status_code not in (200, 202):
        raise RuntimeError(f"Droplet creation failed: {r.status_code} {r.text}")
    return r.json()["droplet"]


def wait_for_droplet(droplet_id: int, max_wait: int = 300) -> str:
    """Poll until droplet is active and returns its public IP."""
    log.info(f"Waiting for droplet {droplet_id} to become active...")
    deadline = time.time() + max_wait
    while time.time() < deadline:
        r = requests.get(f"https://api.digitalocean.com/v2/droplets/{droplet_id}", headers=HEADERS, timeout=15)
        d = r.json()["droplet"]
        status = d["status"]
        networks = d.get("networks", {}).get("v4", [])
        public_ips = [n["ip_address"] for n in networks if n["type"] == "public"]
        log.info(f"  Status: {status}, IPs: {public_ips}")
        if status == "active" and public_ips:
            return public_ips[0]
        time.sleep(15)
    raise TimeoutError(f"Droplet {droplet_id} not ready after {max_wait}s")


def wait_for_ssh(ip: str, max_wait: int = 300) -> bool:
    """Wait until SSH port 22 is reachable."""
    log.info(f"Waiting for SSH on {ip}...")
    deadline = time.time() + max_wait
    while time.time() < deadline:
        result = subprocess.run(
            ["ssh", "-i", "/root/.ssh/id_ed25519_do", "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=5", f"root@{ip}", "echo OK"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            log.info("SSH ready.")
            return True
        time.sleep(10)
    return False


def run_smoketest(ip: str) -> str:
    """Upload and run smoke test script on GPU droplet. Returns stdout."""
    log.info(f"Uploading smoke test to {ip}...")
    subprocess.run(
        ["scp", "-i", "/root/.ssh/id_ed25519_do", "-o", "StrictHostKeyChecking=no",
         "/workspace/fathom/backend/scripts/do_smoketest.sh", f"root@{ip}:/workspace/do_smoketest.sh"],
        check=True
    )
    log.info("Running smoke test (this takes 15-25 min)...")
    result = subprocess.run(
        ["ssh", "-i", "/root/.ssh/id_ed25519_do", "-o", "StrictHostKeyChecking=no",
         f"root@{ip}",
         f"export HF_TOKEN={HF_TOKEN} && bash /workspace/do_smoketest.sh 2>&1 | tee /workspace/smoketest.log"],
        capture_output=True, text=True, timeout=1800
    )
    return result.stdout + result.stderr


# ─── Cloud-init user_data ─────────────────────────────────────────────────────
def build_cloud_init() -> str:
    return """#!/bin/bash
mkdir -p /workspace /workspace/logs
echo "DO GPU droplet initialized" >> /workspace/init.log
date >> /workspace/init.log
"""


# ─── Main loop ────────────────────────────────────────────────────────────────
def main():
    plans_str = ", ".join(p["label"] for p in TARGET_PLANS)
    log.info(f"Starting DO GPU watcher — plans: {plans_str}")
    log.info(f"Regions checked: {', '.join(ALL_REGIONS)}")
    log.info(f"Polling every {POLL_INTERVAL}s. Notify → {NOTIFY_TO}")
    log.info("Waiting for MI300X to become available...")

    attempt = 0
    while True:
        attempt += 1
        try:
            match = check_availability()
            if match:
                slug   = match["slug"]
                region = match["region"]
                label  = match["label"]
                log.info(f"{label} AVAILABLE in {region}! Deploying droplet...")
                send_email(
                    subject=f"[Fathom] {label} Available in {region} — Deploying",
                    body=(
                        f"{label} became available in {region} at {datetime.now()}.\n"
                        f"Deploying droplet and running smoke test...\n"
                        f"Cost: ${1.99 if 'x1' in slug else 15.92}/hr (AMD credits applicable)"
                    ),
                )

                droplet = create_droplet(slug, region)
                droplet_id = droplet["id"]
                droplet_name = droplet["name"]
                log.info(f"Droplet created: {droplet_name} (ID: {droplet_id})")

                ip = wait_for_droplet(droplet_id)
                log.info(f"Droplet active at {ip}")

                if not wait_for_ssh(ip):
                    raise RuntimeError("SSH never became ready")

                smoketest_output = run_smoketest(ip)
                log.info("Smoke test complete.")

                success = "SMOKE TEST PASSED" in smoketest_output
                status = "PASSED ✅" if success else "FAILED ❌"

                send_email(
                    subject=f"[Fathom] {label} Smoke Test {status}",
                    body=(
                        f"GPU: {label}\n"
                        f"Droplet: {droplet_name}\n"
                        f"IP: {ip} (DO ID: {droplet_id})\n"
                        f"Region: {region}\n"
                        f"Time: {datetime.now()}\n\n"
                        f"=== SMOKE TEST OUTPUT ===\n{smoketest_output[-3000:]}\n\n"
                        f"SSH in:  ssh root@{ip}\n"
                        f"Log:     /workspace/smoketest.log"
                    ),
                )
                log.info(f"Done. Droplet {ip} is up and ready for training.")
                log.info("Watcher exiting — droplet deployed.")
                break
            else:
                if attempt % 10 == 0:
                    log.info(f"[Poll {attempt}] No MI300X available in any region yet. Rechecking in {POLL_INTERVAL}s...")
                else:
                    log.debug(f"[Poll {attempt}] Not available.")

        except requests.exceptions.RequestException as e:
            log.warning(f"API error (will retry): {e}")
        except Exception as e:
            log.error(f"Unexpected error: {e}", exc_info=True)
            send_email(
                subject="[Fathom] GPU Watcher Error",
                body=f"Error at {datetime.now()}:\n{e}",
            )

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
