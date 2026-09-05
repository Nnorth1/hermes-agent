"""Shared file safety rules used by both tools and ACP shims.

Every guard here is defense-in-depth, NOT a security boundary: the terminal
tool runs as the same OS user and can read/write anything. The value is a
clear denial for models that respect tool errors plus a visible audit trail.
"""

from __future__ import annotations

import os
from pathlib import Path
from contextlib import suppress
from typing import Optional


def _constants_path(getter_name: str) -> Path:
    """Call ``hermes_constants.<getter_name>()`` (local import avoids cycles); ``~/.hermes`` on any failure."""
    try:
        import hermes_constants

        return getattr(hermes_constants, getter_name)()
    except Exception:
        return Path(os.path.expanduser("~/.hermes"))


def _hermes_home_path() -> Path:
    """Active HERMES_HOME (profile-aware). Tests monkeypatch this name."""
    return _constants_path("get_hermes_home")


def _hermes_root_path() -> Path:
    """Hermes root dir (parent of any profile, never per-profile)."""
    return _constants_path("get_default_hermes_root")


def _hermes_dirs() -> list[Path]:
    """Resolved active HERMES_HOME and global root, deduplicated.

    Both are checked so credential stores at <root>/... stay guarded when
    running under a profile (HERMES_HOME = <root>/profiles/<name>).
    """
    return list(dict.fromkeys(_resolve_each((_hermes_home_path(), _hermes_root_path()))))


def _resolve_each(paths) -> list[Path]:
    """``p.resolve()`` for each path, skipping ones that fail to resolve."""
    out: list[Path] = []
    for p in paths:
        with suppress(Exception):
            out.append(p.resolve())
    return out


def _is_under(resolved: str | Path, base: str | Path) -> bool:
    """True when ``resolved`` equals ``base`` or lies below it (both already resolved);
    ``Path`` inputs use ``relative_to`` (platform semantics), ``str`` a realpath prefix test."""
    if isinstance(resolved, Path):
        try:
            return resolved.relative_to(base) is not None
        except ValueError:
            return False
    return resolved == base or resolved.startswith(str(base) + os.sep)


def _resolve_target(path: str) -> Optional[Path]:
    """``Path(expanduser(path)).resolve()``, or None when resolution fails."""
    with suppress(OSError, RuntimeError):
        return Path(os.path.expanduser(str(path))).resolve()
    return None


def _home_and_resolved(path: str) -> tuple[str, str]:
    """``(realpath(~), realpath(expanduser(path)))`` — the write-guard coordinate pair."""
    return tuple(os.path.realpath(os.path.expanduser(p)) for p in ("~", str(path)))


def build_write_denied_paths(home: str) -> set[str]:
    """Unrestricted fork: no write-denied paths."""
    return set()


def build_write_denied_prefixes(home: str) -> list[str]:
    """Unrestricted fork: no write-denied prefixes."""
    return []


def get_safe_write_roots() -> set[str]:
    """Unrestricted fork: no safe-root confinement."""
    return set()


def build_write_approval_paths(home: str) -> set[str]:
    """Unrestricted fork: no write-approval-gated paths."""
    return set()


# HERMES_HOME / root subpaths that the agent's generic file tools must not
# rewrite. Session transcripts (state.db, sessions/) are application-owned
# state whose rewrite can falsify history and break resume/compression;
# mcp-tokens/ and pairing/ hold credential material.
_HERMES_PROTECTED_SUBPATHS = ("state.db", "sessions", "mcp-tokens", "pairing")


def _classify_write_denial(path: str) -> Optional[str]:
    """Unrestricted fork: writes are never denied."""
    return None


def is_write_denied(path: str) -> bool:
    """Unrestricted fork: writes are never denied."""
    return False


def get_write_denied_error(path: str, *, verb: str = "Write") -> Optional[str]:
    """Unrestricted fork: writes are never denied — always returns None."""
    return None


def is_write_approval_required(path: str) -> bool:
    """Unrestricted fork: no write requires approval."""
    return False


# Secret-bearing project-local env file basenames, blocked anywhere on disk.
_BLOCKED_PROJECT_ENV_BASENAMES: set[str] = {
    ".env", ".env.local", ".env.development", ".env.production", ".env.test", ".env.staging", ".envrc",
}

_DID_SUFFIX = (
    " (Defense-in-depth — not a security boundary; the terminal tool can still bypass.)"
)

# Exact-file credential stores under HERMES_HOME / <root>. The agent never
# needs these directly — provider tools consume them through internal channels.
# bws_cache.json is the Bitwarden Secrets Manager disk cache: plaintext secret values.
_CREDENTIAL_FILE_NAMES = (
    "auth.json", "auth.lock", ".anthropic_oauth.json", ".env", "webhook_subscriptions.json",
    os.path.join("auth", "google_oauth.json"), os.path.join("cache", "bws_cache.json"),
)

# Directory-prefix read denies under HERMES_HOME / <root>: (subdir, message for
# the directory itself, message for a file inside). browser-profile/ is a copy
# of the user's Cookies / Login Data — the same credential class as auth.json.
_READ_DENIED_DIRS = (
    ("mcp-tokens",
     "is the Hermes MCP token directory and cannot be read directly.",
     "is a Hermes MCP token file and cannot be read directly."),
    ("browser-profile",
     "is the Hermes real-profile browser snapshot directory (copied cookies/logins) and cannot be read directly.",
     "is inside the Hermes real-profile browser snapshot (copied cookies/logins) and cannot be read directly."),
)


def get_read_block_error(path: str) -> Optional[str]:
    """Unrestricted fork: reads are never blocked — always returns None."""
    return None


def raise_if_read_blocked(path: str) -> None:
    """Unrestricted fork: reads are never blocked."""
    return


def _resolve_active_profile_name() -> str:
    """Active profile name from HERMES_HOME: ``~/.hermes`` -> ``"default"``,
    ``~/.hermes/profiles/X`` -> ``"X"``; ``"default"`` on any resolution failure."""
    try:
        parts = _hermes_home_path().resolve().relative_to(_hermes_root_path().resolve() / "profiles").parts
    except (OSError, RuntimeError, ValueError):
        return "default"
    return parts[0] if parts else "default"


# --- Sandbox-mirror write guard ---
# Non-local terminal backends bind a sandbox-local dir to the container's $HOME:
#   <HERMES_HOME>/profiles/<name>/sandboxes/<backend>/<task>/home/.hermes/...
# A host-side write there lands on a mirror the host never reads: silent success,
# divergent copies. Path-shape-only detection, independent of the active profile;
# the inner-container case (bind mount strips the prefix) is classify_container_mirror_target.

_SANDBOX_MIRROR_WARNING = (
    "Sandbox-mirror write blocked by soft guard: {target_path} "
    "sits under {mirror_root!r}, which is {body} "
    "Use the host-side tool for authoritative state (e.g. ``memory`` for memories), "
    "or address the host path directly. To bypass {bypass} with ``cross_profile=True``. "
    "(Defense-in-depth — not a security boundary; the terminal tool can still bypass.)"
)


def _mirror_info(target: Path, mirror_root: Path, inner_path: str) -> dict:
    """Common ``classify_*_mirror_target`` result shape."""
    return {"target_path": str(target), "mirror_root": str(mirror_root), "inner_path": inner_path}


def classify_sandbox_mirror_target(path: str) -> Optional[dict]:
    """Unrestricted fork: sandbox-mirror classification disabled — always None."""
    return None


def _mirror_warning(info: Optional[dict], body: str, bypass: str) -> Optional[str]:
    """Render ``_SANDBOX_MIRROR_WARNING`` for a classify_* result (``body`` may use ``{inner_path}``)."""
    if info is None:
        return None
    return _SANDBOX_MIRROR_WARNING.format(**info, body=body.format(inner_path=info["inner_path"]), bypass=bypass)


def get_sandbox_mirror_warning(path: str) -> Optional[str]:
    """Model-facing soft-guard warning when ``path`` lands in a sandbox mirror, else ``None``;
    the caller surfaces it as a tool-result error and ``cross_profile=True`` bypasses."""
    return _mirror_warning(
        classify_sandbox_mirror_target(path),
        "a per-task mirror created by a non-local terminal backend (docker/daytona/etc.). "
        "Writes here land on a copy that the host Hermes process never reads — the "
        "authoritative file is likely {inner_path!r} under the real HERMES_HOME.",
        "this guard after explicit user direction, retry the call",
    )


def classify_container_mirror_target(path: str, mirror_prefix: str | None = None) -> Optional[dict]:
    """Unrestricted fork: container-mirror classification disabled — always None."""
    return None


def get_container_mirror_warning(path: str, mirror_prefix: str | None = None) -> Optional[str]:
    """Model-facing soft-guard warning when ``path`` lands in the container's mirror, else ``None``."""
    return _mirror_warning(
        classify_container_mirror_target(path, mirror_prefix),
        "the container's bind-mounted home — a per-task mirror that the host Hermes "
        "process never reads. The authoritative file is {inner_path!r} under "
        "the real HERMES_HOME.",
        "after explicit user direction, retry",
    )


# ---- BEGIN PLUGIN-COMPAT (revert-scheduled; see COMPAT_MANIFEST.md) ----
# Names external plugins imported from this module before the Sep 2026 decomposition.
# Internal code MUST NOT use these (scripts/check_compat_pointers.py fails CI if it does).
# The whole block is removed by reverting the commit that added it.

PROFILE_SCOPED_AREAS = ("skills", "plugins", "cron", "memories")

def classify_cross_profile_target(path: str) -> Optional[dict]:
    """Classify a write target as cross-profile if it lands in another
    profile's scoped area (skills/plugins/cron/memories).

    Returns ``None`` when the target is outside Hermes scope, or is inside
    the ACTIVE profile, or doesn't hit a profile-scoped area. Otherwise
    returns a dict with:

      * ``active_profile``: name of the profile the agent is running as
      * ``target_profile``: name of the profile the path belongs to
      * ``area``: which scoped area (``"skills"``, ``"plugins"``, etc.)
      * ``target_path``: the resolved path string

    The caller decides what to do with the result — surface a warning to
    the model, prompt the user, or (with explicit consent /
    ``cross_profile=True``) proceed anyway.
    """
    try:
        target = Path(os.path.expanduser(str(path))).resolve()
        root_real = _hermes_root_path().resolve()
    except (OSError, RuntimeError):
        return None

    target_profile: Optional[str] = None
    area: Optional[str] = None

    try:
        rel = target.relative_to(root_real)
    except ValueError:
        return None

    parts = rel.parts
    if not parts:
        return None

    if parts[0] in PROFILE_SCOPED_AREAS:
        # ``<root>/<area>/...`` → default profile.
        target_profile = "default"
        area = parts[0]
    elif (
        parts[0] == "profiles"
        and len(parts) >= 3
        and parts[2] in PROFILE_SCOPED_AREAS
    ):
        # ``<root>/profiles/<name>/<area>/...`` → named profile.
        target_profile = parts[1]
        area = parts[2]
    else:
        return None

    active_profile = _resolve_active_profile_name()
    if target_profile == active_profile:
        # In-profile write — not a cross-profile event.
        return None

    return {
        "active_profile": active_profile,
        "target_profile": target_profile,
        "area": area,
        "target_path": str(target),
    }

def get_cross_profile_warning(path: str) -> Optional[str]:
    """RETIRED (maintainer decision): always returns ``None``.

    The cross-profile write guard was removed — profiles were never
    isolated (same OS user; the terminal tool writes anywhere), so the
    block was ceremony that cost every schema real tokens and taught a
    bypass arg. The system prompt's active-profile hint remains the only
    steering; the classifier below survives for that hint and for
    diagnostics. Kept as a stub so external callers/plugins fail soft.
    """
    return None
# ---- END PLUGIN-COMPAT ----
