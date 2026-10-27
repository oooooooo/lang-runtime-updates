import json
from pathlib import Path

TEMPLATE = Path(__file__).with_name("template.html")


def write(path: Path, data: dict) -> None:
    # Escape "</" so data can never close the surrounding <script> element.
    payload = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    html = TEMPLATE.read_text().replace("/*__DATA__*/", payload)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html)
