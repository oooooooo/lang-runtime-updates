import re

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def strip_tags(html: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


def find_cves(text: str) -> list[str]:
    return sorted(set(CVE_RE.findall(text)))


def split_sections(html: str, pattern: str) -> dict[str, str]:
    """Split html at each match of pattern (one capture group = key)."""
    marks = [(m.start(), m.group(1)) for m in re.finditer(pattern, html)]
    out = {}
    for i, (pos, key) in enumerate(marks):
        end = marks[i + 1][0] if i + 1 < len(marks) else len(html)
        out[key] = html[pos:end]
    return out


def collectors():
    from . import dotnet, go, java, node, php, python, ruby, rust
    return {
        "PHP": php.collect,
        "Python": python.collect,
        "Ruby": ruby.collect,
        "Node.js": node.collect,
        "Java": java.collect,
        "Go": go.collect,
        "Rust": rust.collect,
        ".NET": dotnet.collect,
    }
