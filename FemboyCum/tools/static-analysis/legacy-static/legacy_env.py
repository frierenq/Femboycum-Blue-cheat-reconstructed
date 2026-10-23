"""Explicit paths for optional static verifiers; no reference files are shipped."""

import os
from pathlib import Path


def required_path(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"{name} must point to a locally supplied reference path")
    path = Path(value).expanduser().resolve()
    if not path.exists():
        raise SystemExit(f"{name} path does not exist: {path}")
    return path


def research_root() -> Path:
    path = required_path("FC_RESEARCH_ROOT")
    if not path.is_dir():
        raise SystemExit("FC_RESEARCH_ROOT must be a directory")
    return path


def workspace_root() -> Path:
    path = required_path("FC_WORKSPACE_ROOT")
    if not path.is_dir():
        raise SystemExit("FC_WORKSPACE_ROOT must be a directory")
    return path
