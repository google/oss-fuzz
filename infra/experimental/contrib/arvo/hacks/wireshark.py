"""Wireshark project-specific hacks."""

from . import ProjectHack, register_hack


class WiresharkHack(ProjectHack):
  """Hacks for the Wireshark project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix Wireshark Dockerfile issues."""
    dft.replace(r"RUN git clone .*wireshark.*", "")
    return True


# Register the hack
register_hack("wireshark", WiresharkHack)
