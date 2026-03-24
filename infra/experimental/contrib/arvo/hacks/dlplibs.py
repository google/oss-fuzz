"""DLPLibs project-specific hacks."""

from . import ProjectHack


class DLPLibsHack(ProjectHack):
  """Hacks for the DLPLibs project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix DLPLibs Dockerfile issues."""
    dft.replace(r"ADD", '# ADD')
    dft.replace(r"RUN wget", '#RUN wget')
    return True
