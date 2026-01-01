from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def _repo_root_from_cwd() -> Path:
    """Find repo root by walking upward until ./ledger exists."""

    p = Path.cwd().resolve()
    for _ in range(20):
        if (p / "ledger").exists():
            return p
        if p.parent == p:
            break
        p = p.parent
    raise SystemExit("Could not find repo root (missing ./ledger directory). Run from inside the repo.")


def _git_dir(repo_root: Path) -> Path:
    """Resolve the git directory (supports worktrees)."""

    out = subprocess.check_output(["git", "rev-parse", "--git-dir"], cwd=str(repo_root), text=True).strip()
    gd = Path(out)
    if not gd.is_absolute():
        gd = (repo_root / gd).resolve()
    return gd


def main() -> int:
    repo_root = _repo_root_from_cwd()
    src = repo_root / "tools" / "hooks" / "pre-commit"
    if not src.exists():
        raise SystemExit(f"missing hook template: {src}")

    gd = _git_dir(repo_root)
    hooks_dir = gd / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    dst = hooks_dir / "pre-commit"
    shutil.copyfile(src, dst)

    # Make executable (POSIX). On Windows this is a no-op.
    try:
        st = os.stat(dst)
        os.chmod(dst, st.st_mode | 0o111)
    except Exception:
        pass

    print(f"installed: {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
