from dataclasses import dataclass, field

LANGUAGES = ["PHP", "Python", "Ruby", "Node.js", "Java", "Go", "Rust", ".NET"]


@dataclass
class Release:
    language: str
    version: str
    branch: str
    date: str  # YYYY-MM-DD
    security: bool
    url: str
    cves: list[str] = field(default_factory=list)


def is_feature(version: str) -> bool:
    """True for x.y.0 style versions."""
    parts = version.split(".")
    return len(parts) == 3 and parts[2] == "0"


def branch_of(version: str) -> str:
    return version.rsplit(".", 1)[0]
