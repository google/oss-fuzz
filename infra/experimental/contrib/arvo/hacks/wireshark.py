"""Wireshark project-specific hacks."""

from . import ProjectHack


class WiresharkHack(ProjectHack):
  """Hacks for the Wireshark project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix Wireshark Dockerfile issues."""
    dft.replace(r"RUN git clone .*wireshark.*", "")
    return True
