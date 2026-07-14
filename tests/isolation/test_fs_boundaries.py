"""Гейт Принципа II: файловые операции не выходят за корень песочницы (T015)."""

import os

import pytest

from aiuc_mini.sandbox.fs import Sandbox, SandboxViolation

pytestmark = pytest.mark.isolation


@pytest.mark.parametrize(
    "path",
    [
        "../escape.txt",
        "../../etc/passwd",
        "/etc/passwd",
        "sub/../../escape.txt",
    ],
)
def test_read_outside_root_is_blocked(path):
    with Sandbox() as sb:
        with pytest.raises(SandboxViolation):
            sb.read_file(path)


@pytest.mark.parametrize("path", ["../evil.txt", "/tmp/evil.txt", "../../evil.txt"])
def test_write_outside_root_is_blocked(path):
    with Sandbox() as sb:
        with pytest.raises(SandboxViolation):
            sb.write_file(path, "x")


def test_symlink_escape_is_blocked():
    with Sandbox() as sb:
        outside = sb.root.parent / "outside_target.txt"
        outside.write_text("secret outside", encoding="utf-8")
        try:
            link = sb.root / "link"
            os.symlink(outside, link)
            with pytest.raises(SandboxViolation):
                sb.read_file("link")
        finally:
            outside.unlink(missing_ok=True)


def test_legitimate_paths_work():
    with Sandbox() as sb:
        sb.write_file("dir/file.txt", "ok")
        assert sb.read_file("dir/file.txt") == "ok"
        assert "dir" in sb.list_dir(".")
