from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGES = REPO_ROOT / "python-sdk" / "packages"
EXAMPLES = REPO_ROOT / "examples"


def _source_paths() -> str:
    """Every package's source directory, so the namespace resolves."""
    paths = [
        str(package / "src" / "open_extensions")
        for package in sorted(PACKAGES.iterdir())
        if package.is_dir()
    ]
    return ";".join(paths)


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    """Invoke the CLI in a subprocess so an unhandled error is visible."""
    return subprocess.run(
        [sys.executable, "-m", "open_extensions.cli", *args],
        capture_output=True,
        text=True,
        cwd=str(cwd),
        env={
            "PYTHONPATH": _source_paths(),
            "PATH": "",
            "SystemRoot": "",
            "COMSPEC": "",
        },
    )


def test_a_missing_file_gives_a_clean_error_not_a_traceback(tmp_path: Path):
    """A missing input must be reported, never dumped as a traceback."""
    proc = _run("memx", "inspect", "does-not-exist.memx", cwd=tmp_path)
    assert "Traceback (most recent call last)" not in proc.stderr
    assert "does not exist" in proc.stderr
    assert proc.returncode == 2


def test_a_missing_file_does_not_prompt_for_a_password(tmp_path: Path):
    """The file must be checked before the password prompt."""
    proc = _run("memx", "validate", "--verify", "does-not-exist.memx", cwd=tmp_path)
    assert "MEMX password" not in proc.stdout
    assert "does not exist" in proc.stderr
    assert proc.returncode == 2


@pytest.mark.parametrize("format_name", ["memx", "stepx", "gridv", "podx", "wapp", "tlock"])
def test_the_examples_command_lists_files(format_name: str, tmp_path: Path):
    proc = _run("examples", format_name, cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert format_name in proc.stdout


@pytest.mark.parametrize("format_name", ["memx", "stepx", "gridv", "podx", "wapp", "tlock"])
def test_the_examples_command_can_copy_files(format_name: str, tmp_path: Path):
    proc = _run("examples", format_name, "--write", ".", cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    written = list(tmp_path.rglob("*"))
    assert any(path.is_file() for path in written), "no example files were written"


def test_the_bundled_examples_are_the_repository_examples(tmp_path: Path):
    """The packaged examples must match the ones in the repository.

    The examples ship inside the package so that the documented commands
    work for a plain pip install, so the two copies must not drift.
    """
    bundled_root = (
        REPO_ROOT
        / "python-sdk"
        / "packages"
        / "open-extensions-core"
        / "src"
        / "open_extensions"
        / "examples"
    )
    repository_files = {
        path.relative_to(EXAMPLES): path for path in EXAMPLES.rglob("*") if path.is_file()
    }
    bundled_files = {
        path.relative_to(bundled_root): path
        for path in bundled_root.rglob("*")
        if path.is_file()
    }
    assert set(repository_files) == set(bundled_files), "the bundled examples have drifted"
    for relative, repository_path in repository_files.items():
        assert repository_path.read_bytes() == bundled_files[relative].read_bytes(), (
            f"the bundled copy of {relative} has drifted from examples/"
        )


def test_the_examples_command_rejects_an_unknown_format(tmp_path: Path):
    proc = _run("examples", "nope", cwd=tmp_path)
    assert proc.returncode != 0
