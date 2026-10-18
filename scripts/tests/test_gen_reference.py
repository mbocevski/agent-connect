import importlib.util
import shutil
import sys
from pathlib import Path
from typing import Annotated

import pytest
import typer

_spec = importlib.util.spec_from_file_location(
    "gen_reference", Path(__file__).resolve().parents[1] / "gen_reference.py"
)
assert _spec is not None
assert _spec.loader is not None
gen = importlib.util.module_from_spec(_spec)
sys.modules["gen_reference"] = gen
_spec.loader.exec_module(gen)

REPO = gen.REPO


def test_committed_docs_match_the_code() -> None:
    """The drift test: the generated sections must be up to date."""
    stale = [str(p.relative_to(REPO)) for p in gen.stale()]
    assert not stale, f"{', '.join(stale)} are stale: run `just docs-gen` and commit the result"


def test_splice_replaces_only_between_the_markers() -> None:
    text = "intro\n\n<!-- generated:x:start -->\n\nold\n\n<!-- generated:x:end -->\n\nouter\n"
    out = gen.splice(text, "x", "new\n")
    assert (
        out == "intro\n\n<!-- generated:x:start -->\n\nnew\n\n<!-- generated:x:end -->\n\nouter\n"
    )
    assert gen.splice(out, "x", "new") == out  # idempotent


@pytest.mark.parametrize(
    "text",
    [
        "no markers",
        "<!-- generated:x:start -->\n",
        "<!-- generated:x:end -->\n<!-- generated:x:start -->\n",
        "<!-- generated:x:start -->\n<!-- generated:x:end -->\n<!-- generated:x:end -->\n",
    ],
)
def test_splice_needs_ordered_markers(text: str) -> None:
    with pytest.raises(gen.MarkerError):
        gen.splice(text, "x", "body")


def test_every_section_has_markers_in_its_doc() -> None:
    for section in gen.SECTIONS:
        start, end = gen.markers(section.name)
        text = (REPO / section.doc).read_text(encoding="utf-8")
        assert text.count(start) == 1
        assert text.count(end) == 1


def test_missing_markers_name_the_doc(tmp_path: Path) -> None:
    for doc in {s.doc for s in gen.SECTIONS}:
        (tmp_path / doc).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / doc).write_text("no markers\n", encoding="utf-8")
    with pytest.raises(gen.MarkerError, match=r"docs/cli\.md"):
        gen.generate(tmp_path)


def copy_docs(root: Path) -> None:
    for doc in {s.doc for s in gen.SECTIONS}:
        (root / doc).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(REPO / doc, root / doc)


def test_main_writes_then_checks(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    copy_docs(tmp_path)
    cli_doc = tmp_path / "docs/cli.md"
    cli_doc.write_text(cli_doc.read_text().replace("`leave`", "`LEAVE`"), encoding="utf-8")
    assert gen.main(["--check"], tmp_path) == 1
    assert "just docs-gen" in capsys.readouterr().err
    assert gen.main([], tmp_path) == 0
    assert "`LEAVE`" not in cli_doc.read_text()
    assert gen.main(["--check"], tmp_path) == 0


def test_main_rejects_unknown_arguments() -> None:
    assert gen.main(["--nope"]) == 2


def test_prose_outside_the_markers_survives(tmp_path: Path) -> None:
    copy_docs(tmp_path)
    doc = tmp_path / "docs/config.md"
    doc.write_text(doc.read_text() + "\nA hand-written closing paragraph.\n", encoding="utf-8")
    gen.main([], tmp_path)
    assert "A hand-written closing paragraph." in doc.read_text()


def small_app() -> typer.Typer:
    app = typer.Typer()
    sub = typer.Typer(help="Things.")
    app.add_typer(sub, name="thing")

    @sub.command("make")
    def make(
        name: str,
        size: Annotated[int, typer.Option("--size", min=1, max=9, help="How big.")] = 3,
        tag: Annotated[list[str] | None, typer.Option("--tag", help="Labels | many.")] = None,
        loud: Annotated[bool, typer.Option("--loud", help="Shout.")] = False,
    ) -> None:
        """Make a thing.

        Longer text.
        """

    @app.command()
    def top() -> None:
        """Top level."""

    return app


def test_cli_reference_follows_the_typer_app() -> None:
    text = gen.render_cli_commands(small_app())
    assert "| `thing make` | api | Make a thing. |" in text
    assert "| `top` | api | Top level. |" in text
    assert "agentconnect thing make [OPTIONS] NAME" in text
    assert "| `NAME` | yes |" in text
    assert "| `--size` | integer 1..9 | `3` | How big. |" in text
    assert "| `--tag` | text, repeatable | none | Labels \\| many. |" in text
    assert "| `--loud` | flag | off | Shout. |" in text
    assert "Longer text." in text


def test_real_cli_reference_lists_every_command() -> None:
    text = gen.render_cli_commands()
    for name in ("accept", "verify", "daemon run", "invite create", "approvals approve", "groups"):
        assert f"### `agentconnect {name}`" in text
    human = [c.name for c in gen.walk_cli() if c.human]
    assert human == [
        "verify",
        "remove",
        "audit",
        "transcript",
        "listing publish",
        "approvals approve",
        "approvals reject",
        "safety set",
    ]


def test_api_reference_lists_every_route() -> None:
    from agentconnect.runtime import api  # noqa: PLC0415

    text = gen.render_api_routes()
    for spec in api.ROUTE_SPECS:
        assert f"### `{spec.method} {spec.path}`" in text
    assert text.count("Needs the **human token**.") == sum(s.human for s in api.ROUTE_SPECS)


def test_shape_text() -> None:
    from agentconnect.shapes import Opt  # noqa: PLC0415

    shape = {"a": "int", "b?": Opt(["str"]), "c": {"d": "bool"}}
    assert gen.shape_text(shape) == (
        '{\n  "a": int,\n  "b"?: [str] | null,\n  "c": {\n    "d": bool\n  }\n}'
    )


def test_table_escapes_pipes_and_newlines() -> None:
    assert gen.table(["A"], [["x | y\nz"]]) == "| A |\n|---|\n| x \\| y z |"
