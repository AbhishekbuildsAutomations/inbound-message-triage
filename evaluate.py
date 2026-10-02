"""
Score results.json against the hand-written answer key in expected.json.

    python evaluate.py                # uses results.json
    python evaluate.py other.json
"""

import json
import sys
from pathlib import Path

import guard
import rules
from triage import HERE, load_brand_facts

# Messages where the bot finishing alone would do real harm.
# These must always reach a human, whatever else the score says.
MUST_REACH_HUMAN = ["MSG-005", "MSG-008", "MSG-011", "MSG-016", "MSG-019", "MSG-021"]


def main():
    results_path = sys.argv[1] if len(sys.argv) > 1 else "results.json"
    results = json.loads(Path(results_path).read_text(encoding="utf-8"))["results"]
    expected = json.loads((HERE / "expected.json").read_text(encoding="utf-8"))
    expected.pop("_note", None)
    facts = load_brand_facts()
    by_id = {r["id"]: r for r in results}

    action_ok = owner_ok = urgency_ok = 0
    missing = [message_id for message_id in expected if message_id not in by_id]
    for message_id, want in expected.items():
        got = by_id.get(message_id)
        if got is None:
            print(f"{message_id}: MISSING from results")
            continue
        right_action = got["action"] in want["actions"]
        right_owner = got["owner"] == want["owner"]
        # Urgency may be higher than expected, never lower.
        right_urgency = (rules.URGENCY_ORDER.index(got["urgency"])
                         >= rules.URGENCY_ORDER.index(want["min_urgency"]))
        action_ok += right_action
        owner_ok += right_owner
        urgency_ok += right_urgency
        if not (right_action and right_owner and right_urgency):
            print(f"{message_id}: got {got['action']} / {got['owner']} / {got['urgency']}, expected "
                  f"{' or '.join(want['actions'])} / {want['owner']} / at least {want['min_urgency']}")
            print(f"    why: {'; '.join(got['reasons'])}")

    total = len(expected)
    print(f"\nAction correct: {action_ok}/{total}   Owner correct: {owner_ok}/{total}   "
          f"Urgency high enough: {urgency_ok}/{total}")

    # Every customer gets an immediate reply.
    silent = [r["id"] for r in results if not r["reply_to_customer"]]
    print("Every message got a reply:", "FAILED " + ", ".join(silent) if silent else "passed")

    # No model-written reply may break the output gate (re-checked here).
    leaked = [r["id"] for r in results if r["reply_source"] == "model"
              and guard.check_reply(r["reply_to_customer"], facts.get(r["brand"], []))]
    print("Model replies pass the output gate:", "FAILED " + ", ".join(leaked) if leaked else "passed")

    unsafe = [m for m in MUST_REACH_HUMAN if m not in by_id or not by_id[m]["human_review"]]
    print("Risky messages reach a human:", "FAILED " + ", ".join(unsafe) if unsafe else "passed")
    perfect = action_ok == owner_ok == urgency_ok == total
    sys.exit(0 if perfect and not (missing or unsafe or leaked or silent) else 1)


if __name__ == "__main__":
    main()
