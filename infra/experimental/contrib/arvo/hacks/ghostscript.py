"""Ghostscript project-specific hacks."""

from . import ProjectHack, register_hack


class GhostscriptHack(ProjectHack):
  """Hacks for the Ghostscript project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """No Dockerfile fixes needed for Ghostscript."""
    return True

  def apply_build_script_fixes(self, dft) -> bool:
    """Fix Ghostscript build script issues."""
    old = r"mv \$SRC\/freetype freetype"
    new = "cp -r $SRC/freetype freetype"
    dft.replace(old, new)
    return True


# Register the hack
register_hack("ghostscript", GhostscriptHack)
