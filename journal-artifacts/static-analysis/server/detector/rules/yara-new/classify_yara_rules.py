import os
import shutil

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

RESEARCH_DIR = os.path.join(BASE_DIR, "99_research")

DEST_DIRS = {
    "filetype":   os.path.join(BASE_DIR, "01_filetype"),
    "capability": os.path.join(BASE_DIR, "02_capability"),
    "family":     os.path.join(BASE_DIR, "03_family"),
    "research":   RESEARCH_DIR,
}


def ensure_dest_dirs():
    for d in DEST_DIRS.values():
        os.makedirs(d, exist_ok=True)


# ---- classification helpers ----

def is_apt_or_campaign(name: str) -> bool:
    n = name.lower()
    if n.startswith("apt_"):
        return True
    if n.startswith(("unc", "ta17_", "ta18_", "mar_", "cn_pentestset_")):
        return True
    if "fiveeyes" in n or "uscert" in n or "cisa" in n:
        return True
    return False


def is_family_like(name: str) -> bool:
    n = name.lower()

    # OS trojan / infostealer / worm / virus / rootkit / generic threat
    family_prefixes = (
        "windows_trojan_",
        "windows_infostealer_",
        "windows_wiper_",
        "windows_virus_",
        "windows_worm_",
        "windows_rootkit_",
        "windows_generic_threat",
        "windows_generic_malcert",
        "linux_trojan_",
        "linux_rootkit_",
        "linux_worm_",
        "linux_virus_",
        "linux_generic_threat",
        "macos_trojan_",
        "macos_infostealer_",
        "macos_virus_",
        "multi_trojan_",
        "multi_generic_threat",
    )
    if n.startswith(family_prefixes):
        return True

    # obvious crimeware / PUP / PUA / spy
    if n.startswith(("crime_", "pup_", "pua_", "spy_")):
        return True

    return False


def is_capability_like(name: str) -> bool:
    n = name.lower()

    # hacktools & redteam toolsets
    if "hacktool" in n:
        return True
    if "cobaltstrike" in n or "cobalt_strike" in n:
        return True
    if "sliver" in n:
        return True
    if "empire" in n:
        return True
    if "metasploit" in n:
        return True
    if "bruteratel" in n:
        return True
    if "mythic" in n:
        return True
    if "havoc" in n:
        return True
    if "redteam" in n:
        return True

    # exploit / vuln signatures
    if n.startswith("expl_") or n.startswith("vul_"):
        return True

    # generic hunting / suspicious activity
    if n.startswith(("susp_", "generic_", "gen_")) and (
        "susp" in n
        or "anomal" in n
        or "url_" in n
        or "dump" in n
        or "kerberoast" in n
        or "wmi_" in n
        or "gcti_" in n
    ):
        return True

    return False


def classify(name: str) -> str:
    """
    Decide bucket for a rule currently in 99_research.
    Returns one of: 'family', 'capability', 'filetype', 'research'
    """
    if is_apt_or_campaign(name):
        return "research"

    if is_family_like(name):
        return "family"

    if is_capability_like(name):
        return "capability"

    # default: stay in research
    return "research"


def main():
    ensure_dest_dirs()

    moved = {"family": 0, "capability": 0, "filetype": 0, "research": 0}

    for fname in os.listdir(RESEARCH_DIR):
        if not fname.lower().endswith((".yar", ".yara")):
            continue

        src_path = os.path.join(RESEARCH_DIR, fname)
        if not os.path.isfile(src_path):
            continue

        bucket = classify(fname)
        dest_dir = DEST_DIRS[bucket]
        dest_path = os.path.join(dest_dir, fname)

        if bucket == "research":
            # stays where it is
            moved["research"] += 1
            continue

        # don't overwrite if something with same name already exists
        if os.path.exists(dest_path):
            print(f"[SKIP] {fname} -> {bucket} (already exists at destination)")
            continue

        print(f"[MOVE] {fname} -> {bucket}")
        shutil.move(src_path, dest_path)
        moved[bucket] += 1

    print("\nReclassification summary (from 99_research):")
    for k, v in moved.items():
        print(f"  {k:10s}: {v} files")


if __name__ == "__main__":
    main()
