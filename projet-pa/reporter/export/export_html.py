from pathlib import Path
from jinja2 import Environment, FileSystemLoader


class HTMLExporter:
    def export(self, context):
        templates_dir = Path(__file__).parent.parent / "templates"
        env = Environment(loader=FileSystemLoader(templates_dir))

        template = env.get_template("report.html")
        output = template.render(context)

        output_path = Path("data/scans/report.html")

        # ← Add this BEFORE writing
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        output_path.write_text(output, encoding="utf-8")
