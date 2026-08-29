from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAUNCH_GUIDE = PROJECT_ROOT / "docs" / "credential-launch.md"
ROTATION_GUIDE = PROJECT_ROOT / "docs" / "credential-rotation.md"


@dataclass(frozen=True)
class FencedBlock:
    section: str
    language: str
    code: str


@dataclass(frozen=True)
class ParsedGuide:
    headings: tuple[str, ...]
    blocks: tuple[FencedBlock, ...]
    text: str


def _parse_guide(path: Path) -> ParsedGuide:
    text = path.read_text(encoding="utf-8")
    headings: list[str] = []
    blocks: list[FencedBlock] = []
    current_section = ""
    language: str | None = None
    body: list[str] = []

    for line in text.splitlines():
        heading = re.fullmatch(r"#{2,3}\s+(.+)", line)
        if heading and language is None:
            current_section = heading.group(1).strip()
            headings.append(current_section)
            continue
        opening = re.fullmatch(r"```([A-Za-z0-9_-]+)", line)
        if opening and language is None:
            language = opening.group(1).casefold()
            body = []
            continue
        if line == "```" and language is not None:
            blocks.append(FencedBlock(current_section, language, "\n".join(body)))
            language = None
            body = []
            continue
        if language is not None:
            body.append(line)

    assert language is None, f"unclosed fenced block in {path}"
    return ParsedGuide(tuple(headings), tuple(blocks), text)


def _blocks_for(guide: ParsedGuide, section: str) -> dict[str, str]:
    return {block.language: block.code for block in guide.blocks if block.section == section}


def test_canonical_guides_have_structured_sections_and_shell_blocks() -> None:
    launch = _parse_guide(LAUNCH_GUIDE)
    rotation = _parse_guide(ROTATION_GUIDE)

    assert {
        "Dependencies and setup",
        "Linux: Secret Service",
        "Provisioning check",
        "Launch",
        "Quarantine administration",
        "Windows: Credential Manager compatibility",
        "Troubleshooting and restart",
    } <= set(launch.headings)
    assert {
        "Rotation",
        "Dependency checks",
        "Setup and platform contracts",
        "Result and rollback",
        "Restart and troubleshooting",
    } <= set(rotation.headings)

    setup = _blocks_for(launch, "Dependencies and setup")
    assert set(setup) == {"bash", "powershell"}
    assert all("uv sync --locked" in code for code in setup.values())

    provisioning = _blocks_for(launch, "Provisioning check")
    assert set(provisioning) == {"bash"}
    assert '_run_worker_operation("availability", None)' in provisioning["bash"]
    assert "get_secret" not in provisioning["bash"]

    launch_blocks = _blocks_for(launch, "Launch")
    assert set(launch_blocks) == {"bash", "powershell"}
    assert all("forgejo-api-mcp-launch" in code for code in launch_blocks.values())

    quarantine = _blocks_for(launch, "Quarantine administration")
    assert set(quarantine) == {"bash"}
    assert "forgejo-api-mcp-quarantine check" in quarantine["bash"]
    assert "clear --operator-verified" in quarantine["bash"]

    rotation_blocks = _blocks_for(rotation, "Rotation")
    assert set(rotation_blocks) == {"bash", "powershell"}
    assert all("<token-placeholder>" in code for code in rotation_blocks.values())
    assert all("forgejo-api-mcp-rotate" in code for code in rotation_blocks.values())

    dependency_blocks = _blocks_for(rotation, "Dependency checks")
    assert set(dependency_blocks) == {"bash", "powershell"}
    assert all("uv run python -c" in code for code in dependency_blocks.values())

    all_blocks = (*launch.blocks, *rotation.blocks)
    assert all(block.language in {"bash", "powershell"} for block in all_blocks)
    assert "restart" in launch.text.casefold() and "troubleshoot" in launch.text.casefold()
    assert "restart" in rotation.text.casefold() and "troubleshoot" in rotation.text.casefold()


def test_canonical_examples_are_placeholder_only_and_reject_real_credentials() -> None:
    guides = (_parse_guide(LAUNCH_GUIDE), _parse_guide(ROTATION_GUIDE))
    code = "\n".join(block.code for guide in guides for block in guide.blocks)

    assert {"<token-placeholder>", "<forgejo-host>", "<username>", "<project-path>"} <= set(
        re.findall(r"<[^>]+>", code)
    )
    assert all(
        "<forgejo-host>" in host
        for host in re.findall(r"https://([^/\"'\s]+)", code)
    )
    forbidden_patterns = (
        r"\bghp_[A-Za-z0-9]{16,}\b",
        r"\bgithub_pat_[A-Za-z0-9_]{16,}\b",
        r"\bglpat-[A-Za-z0-9_-]{16,}\b",
        r"\b(?:forgejo|gitea)_[A-Za-z0-9_-]{16,}\b",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
    )
    assert not any(re.search(pattern, code) for pattern in forbidden_patterns)
    assert "secret-tool" not in code
    assert "cmdkey /pass" not in code.casefold()


def test_canonical_links_resolve_and_summary_documents_link_both_guides() -> None:
    for guide_path, other_name in (
        (LAUNCH_GUIDE, "credential-rotation.md"),
        (ROTATION_GUIDE, "credential-launch.md"),
    ):
        text = guide_path.read_text(encoding="utf-8")
        links = re.findall(r"\[[^]]+\]\(([^)]+)\)", text)
        assert other_name in links
        for target in links:
            if target.startswith(("https://", "http://", "#")):
                continue
            assert (guide_path.parent / target.split("#", 1)[0]).exists()

    for summary_path in (
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "AGENTS.md",
        PROJECT_ROOT / "ARCHITECTURE.md",
    ):
        summary = summary_path.read_text(encoding="utf-8")
        assert "docs/credential-launch.md" in summary
        assert "docs/credential-rotation.md" in summary
