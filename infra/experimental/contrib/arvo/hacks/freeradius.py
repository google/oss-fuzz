"""FreeRADIUS project-specific hacks."""

from . import ProjectHack, register_hack


class FreeRADIUSHack(ProjectHack):
  """Hacks for the FreeRADIUS project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix FreeRADIUS Dockerfile issues."""
    dft.str_replace('sha256sum -c', 'pwd')
    dft.str_replace("curl -s -O ", 'curl -s -O -L ')
    return True


# Register the hack
register_hack("freeradius", FreeRADIUSHack)
