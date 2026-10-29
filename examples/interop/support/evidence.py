"""Write readable JSON evidence without importing another experiment."""

import json


def write_record(path, record, *, sequence_key="rows"):
    lines = ["{"]
    entries = list(record.items())
    for index, (key, value) in enumerate(entries):
        suffix = "," if index + 1 < len(entries) else ""
        if key == sequence_key:
            lines.append("  " + json.dumps(key) + ": [")
            lines.extend(
                "    " + json.dumps(row) + ("," if i + 1 < len(value) else "")
                for i, row in enumerate(value)
            )
            lines.append("  ]" + suffix)
        else:
            lines.append("  " + json.dumps(key) + ": " + json.dumps(value) + suffix)
    lines.append("}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")
