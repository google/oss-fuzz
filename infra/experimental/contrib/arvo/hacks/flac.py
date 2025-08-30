"""FLAC project-specific hacks."""

from . import ProjectHack, register_hack


class FLACHack(ProjectHack):
  """Hacks for the FLAC project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix FLAC Dockerfile issues."""
    # Check if the problematic repository is referenced
    if dft.locate_str('guidovranken/flac-fuzzers') is not False:
      return False  # Not fixable since the repo is removed and there is no mirror
    return True


# Register the hack
register_hack("flac", FLACHack)
