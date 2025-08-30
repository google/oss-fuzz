"""Lwan project-specific hacks."""

from . import ProjectHack, register_hack


class LwanHack(ProjectHack):
  """Hacks for the Lwan project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix Lwan Dockerfile issues."""
    dft.str_replace('git://github.com/lpereira/lwan',
                    'https://github.com/lpereira/lwan.git')
    return True


# Register the hack
register_hack("lwan", LwanHack)
