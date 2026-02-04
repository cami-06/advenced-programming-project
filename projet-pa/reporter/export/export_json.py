import json
from pathlib import Path


class JSONExporter:
    def export(self, context):
        output_path = Path("data/scans/report.json")

        # ← Add this BEFORE writing
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(context, f, indent=4)
