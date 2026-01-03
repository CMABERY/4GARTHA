#!/usr/bin/env python3
"""
insert_fix_tools_imports.py

This script handles dependency improvements by fixing and inserting
necessary imports in tools and source files. It ensures that all
Python modules have proper import statements for their dependencies.

Usage:
    python scripts/insert_fix_tools_imports.py [--dry-run]
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path
from typing import Set


def find_python_files(root_dir: Path) -> list[Path]:
    """Find all Python files in the given directory."""
    python_files = list(root_dir.glob("**/*.py"))
    return [f for f in python_files if f.is_file() and not f.name.startswith(".")]


def check_missing_imports(file_path: Path) -> list[str]:
    """Check for common missing imports that should be added."""
    missing = []
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        
        # Check for common patterns that require specific imports
        if "typing." in content or "List[" in content or "Dict[" in content:
            if "from typing import" not in content and "import typing" not in content:
                missing.append("from typing import List, Dict, Optional, Any")
        
        if "Path(" in content or "Path." in content:
            if "from pathlib import Path" not in content and "import pathlib" not in content:
                missing.append("from pathlib import Path")
        
        return missing
    except Exception as e:
        print(f"Warning: Could not check {file_path}: {e}", file=sys.stderr)
        return []


def fix_imports(file_path: Path, dry_run: bool = False) -> bool:
    """Fix imports in a Python file."""
    missing = check_missing_imports(file_path)
    
    if not missing:
        return False
    
    if dry_run:
        print(f"Would add imports to {file_path}:")
        for imp in missing:
            print(f"  {imp}")
        return True
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        # Find insertion point (after any existing imports or docstring)
        insert_idx = 0
        in_docstring = False
        
        for i, line in enumerate(lines):
            if line.strip().startswith('"""') or line.strip().startswith("'''"):
                if in_docstring:
                    in_docstring = False
                    insert_idx = i + 1
                else:
                    in_docstring = True
            elif not in_docstring and (line.strip().startswith("import ") or 
                                      line.strip().startswith("from ")):
                insert_idx = i + 1
        
        # Insert missing imports
        for imp in reversed(missing):
            lines.insert(insert_idx, f"{imp}\n")
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
        
        print(f"Fixed imports in {file_path}")
        return True
    except Exception as e:
        print(f"Error: Could not fix {file_path}: {e}", file=sys.stderr)
        return False


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Fix and insert necessary imports in Python files"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be changed without modifying files",
    )
    parser.add_argument(
        "--dir",
        type=Path,
        default=Path("."),
        help="Root directory to scan (default: current directory)",
    )
    
    args = parser.parse_args()
    
    root_dir = args.dir.resolve()
    if not root_dir.is_dir():
        print(f"Error: {root_dir} is not a directory", file=sys.stderr)
        return 1
    
    # Focus on tools and src directories
    target_dirs = []
    for subdir in ["tools", "src", "transforms"]:
        path = root_dir / subdir
        if path.is_dir():
            target_dirs.append(path)
    
    if not target_dirs:
        print("No target directories found (tools, src, transforms)", file=sys.stderr)
        return 1
    
    files_fixed = 0
    for target_dir in target_dirs:
        python_files = find_python_files(target_dir)
        print(f"Scanning {len(python_files)} files in {target_dir.name}/")
        
        for py_file in python_files:
            if fix_imports(py_file, dry_run=args.dry_run):
                files_fixed += 1
    
    if files_fixed > 0:
        status = "Would fix" if args.dry_run else "Fixed"
        print(f"\n{status} imports in {files_fixed} file(s)")
    else:
        print("\nNo import fixes needed")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
