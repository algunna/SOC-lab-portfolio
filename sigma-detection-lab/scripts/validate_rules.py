"""Small fixture validator for this lab's subset of Sigma syntax, not a SIEM converter."""
import argparse
import json
import re
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]

def selector_matches(selector, event):
    for condition, expected in selector.items():
        key, _, operator = condition.partition("|")
        observed = event.get(key)
        values = expected if isinstance(expected, list) else [expected]
        if operator == "endswith":
            matched = isinstance(observed, str) and any(observed.lower().endswith(str(x).lower()) for x in values)
        elif operator == "contains":
            matched = isinstance(observed, str) and any(str(x).lower() in observed.lower() for x in values)
        elif operator == "re":
            matched = isinstance(observed, str) and any(re.search(str(x), observed) for x in values)
        elif not operator:
            # Sigma compares plain values case-insensitively, and exports may carry IDs as text
            matched = observed is not None and any(str(observed).lower() == str(value).lower() for value in values)
        else:
            raise ValueError(f"Unsupported operator {operator}")
        if not matched:
            return False
    return True

def matches(rule, event):
    selections = {k: v for k, v in rule["detection"].items() if k.startswith("selection")}
    condition = rule["detection"]["condition"]
    if condition == "selection":
        return selector_matches(selections["selection"], event)
    if condition == "selection_image and selection_command":
        return all(selector_matches(selections[k], event) for k in ("selection_image", "selection_command"))
    if condition == "selection_event and selection_group":
        return all(selector_matches(selections[k], event) for k in ("selection_event", "selection_group"))
    raise ValueError(f"Unsupported condition: {condition}")

def validate():
    fixtures = json.loads((ROOT / "fixtures" / "cases.json").read_text(encoding="utf-8"))
    count = 0
    for filename, cases in fixtures.items():
        rule = yaml.safe_load((ROOT / "rules" / filename).read_text(encoding="utf-8"))
        for required in ("title", "id", "status", "logsource", "detection", "level", "tags", "falsepositives"):
            if required not in rule:
                raise ValueError(f"{filename} missing {required}")
        for index, case in enumerate(cases):
            result = matches(rule, case["event"])
            if result is not case["match"]:
                raise AssertionError(f"{filename} case {index}: expected {case['match']}, got {result}")
            count += 1
    return count

if __name__ == "__main__":
    print(f"Validated {validate()} synthetic fixture cases")
