"""LibHeif project-specific hacks."""

from . import ProjectHack, register_hack, x265_fix


class LibHeifHack(ProjectHack):
  """Hacks for the LibHeif project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix LibHeif Dockerfile issues."""
    # Apply x265 fixes
    x265_fix(dft)
    return True


# Register the hack
register_hack("libheif", LibHeifHack)
