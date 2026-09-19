import inspect
import re
from pathlib import Path
from typing import Final

import litellm


def extract_documented_router_keys(content: str) -> frozenset[str]:
    section: Final = re.search(
        r"^### router_settings - Reference\s*\n(.*?)(?=^### |\Z)",
        content,
        re.MULTILINE | re.DOTALL,
    )
    if section is None:
        raise ValueError("Missing router_settings - Reference section")
    return frozenset(re.findall(r"^\s*\|\s*`?([a-z][a-z0-9_]*)`?\s*\|", section.group(1), re.MULTILINE))


def main() -> None:
    parameters: Final = frozenset(inspect.signature(litellm.router.Router.__init__).parameters) - {"self", "model_list"}
    docs_path: Final = Path(__file__).resolve().parents[2] / "docs/my-website/docs/proxy/config_settings.md"
    documented: Final = extract_documented_router_keys(docs_path.read_text(encoding="utf-8"))
    missing: Final = parameters - documented
    if missing:
        raise ValueError(f"Keys not documented in 'router settings - Reference': {sorted(missing)}")
    print(f"All {len(parameters)} router settings are documented")


if __name__ == "__main__":
    main()
