"""Verify local relative Markdown links in portfolio docs and root README."""
import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
FILES = [ROOT / "README.md", ROOT / "CHANGELOG.md", *sorted((ROOT / "docs").glob("*.md"))]
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")

def check():
    bad = []
    count = 0
    for page in FILES:
        content = page.read_text(encoding="utf-8")
        for href in LINK.findall(content):
            if href.startswith(("https://", "http://", "mailto:", "#")):
                continue
            target = unquote(href.split("#", 1)[0])
            if not target:
                continue
            count += 1
            if not (page.parent / target).exists():
                bad.append(f"{page.relative_to(ROOT)} -> {href}")
    return count, bad

if __name__ == "__main__":
    count, bad = check()
    if bad:
        raise SystemExit("Broken links:\n" + "\n".join(bad))
    print(f"Checked {count} local documentation links")
