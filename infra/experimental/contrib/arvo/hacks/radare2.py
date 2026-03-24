"""Radare2 project-specific hacks."""

from . import ProjectHack


class Radare2Hack(ProjectHack):
  """Hacks for the Radare2 project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix Radare2 Dockerfile issues."""
    dft.str_replace("https://github.com/radare/radare2-regressions",
                    'https://github.com/rlaemmert/radare2-regressions.git')
    return True
