"""LCMS project-specific hacks."""

from . import ProjectHack, register_hack


class LCMSHack(ProjectHack):
  """Hacks for the LCMS project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix LCMS Dockerfile issues."""
    # TODO: improve this tmp patch
    dft.replace(r'#add more seeds from the testbed dir.*\n', "")
    return True


# Register the hack
register_hack("lcms", LCMSHack)
