"""Bind evidence to explicit inputs and their static local Python imports."""

import ast
import hashlib
from pathlib import Path


def harness_sources(root, inputs):
    """Return relative inputs, including imported local helpers, once each.

    Dynamic inputs and non-Python fixtures must still be supplied explicitly.
    Third-party modules are not read from the interpreter's environment.
    """
    root = Path(root).resolve()
    modules = root / "examples/interop"
    if not modules.is_dir():
        modules = root
    pending = [
        Path(item) if Path(item).is_absolute() else root / item for item in inputs
    ]
    found = set()

    def add_module(base, parts):
        module = base.joinpath(*parts)
        for candidate in (module.with_suffix(".py"), module / "__init__.py"):
            if candidate.is_file():
                pending.append(candidate)

    while pending:
        path = pending.pop().resolve()
        path.relative_to(root)  # An evidence capsule must not escape its root.
        if path in found:
            continue
        if not path.is_file():
            raise FileNotFoundError(path)
        found.add(path)
        if path.suffix != ".py":
            continue
        for parent in path.parents:
            if parent == root:
                break
            initializer = parent / "__init__.py"
            if initializer.is_file():
                pending.append(initializer)
        for node in ast.walk(ast.parse(path.read_text(), filename=str(path))):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".") for alias in node.names]
                bases = (path.parent, modules, modules / "python")
            elif isinstance(node, ast.ImportFrom):
                parts = node.module.split(".") if node.module else []
                names = [parts] + [
                    parts + alias.name.split(".") for alias in node.names
                ]
                if node.level:
                    bases = (path.parents[node.level - 1],)
                else:
                    bases = (path.parent, modules, modules / "python")
            else:
                continue
            for base in bases:
                for parts in names:
                    add_module(base, parts)
    return sorted(str(path.relative_to(root)) for path in found)


def harness_hashes(root, inputs):
    root = Path(root)
    return {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in harness_sources(root, inputs)
    }
