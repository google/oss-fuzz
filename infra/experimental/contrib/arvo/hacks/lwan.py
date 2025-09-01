"""Lwan project-specific hacks."""

from . import ProjectHack


class LwanHack(ProjectHack):
  """Hacks for the Lwan project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix Lwan Dockerfile issues."""
    dft.str_replace('git://github.com/lpereira/lwan',
                    'https://github.com/lpereira/lwan.git')
    return True
