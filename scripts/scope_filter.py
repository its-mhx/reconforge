
import fnmatch
from pathlib import Path

INPUT = Path("output/passive_subdomains.txt")
CONFIG = Path("config/scope.txt")
OUTPUT = Path("output")


def load_rules():
    rules = []

    if not CONFIG.exists():
        raise FileNotFoundError("config/scope.txt not found")

    for line in CONFIG.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#"):
            continue

        parts = line.split(maxsplit=1)

        if len(parts) != 2:
            raise ValueError(f"Invalid rule: {line}")

        action, pattern = parts
        action = action.upper()
        pattern = pattern.lower().rstrip(".")

        if action not in {"ALLOW", "REVIEW", "DENY"}:
            raise ValueError(f"Invalid action: {action}")

        rules.append((action, pattern))

    return rules


def classify(host, rules):
    host = host.lower().rstrip(".")

    matched = [
        action for action, pattern in rules
        if fnmatch.fnmatchcase(host, pattern)
    ]

    if "DENY" in matched:
        return "out_of_scope"

    if "ALLOW" in matched:
        return "in_scope_candidate"

    if "REVIEW" in matched:
        return "needs_review"

    return "out_of_scope"


def main():
    OUTPUT.mkdir(parents=True, exist_ok=True)

    if not INPUT.exists():
        raise FileNotFoundError(
            "Run Passive Recon before Scope Validation"
        )

    rules = load_rules()

    hosts = sorted(set(
        line.strip().lower().rstrip(".")
        for line in INPUT.read_text().splitlines()
        if line.strip()
    ))

    categories = {
        "in_scope_candidates.txt": [],
        "needs_review.txt": [],
        "out_of_scope.txt": [],
    }

    for host in hosts:
        result = classify(host, rules)

        if result == "in_scope_candidate":
            categories["in_scope_candidates.txt"].append(host)
        elif result == "needs_review":
            categories["needs_review.txt"].append(host)
        else:
            categories["out_of_scope.txt"].append(host)

    for filename, hosts_list in categories.items():
        (OUTPUT / filename).write_text(
            "\n".join(hosts_list) + ("\n" if hosts_list else "")
        )

    print("========== SCOPE SUMMARY ==========")
    for filename, hosts_list in categories.items():
        print(f"{filename}: {len(hosts_list)}")

    print("[+] Scope filtering completed")


if __name__ == "__main__":
    main()
