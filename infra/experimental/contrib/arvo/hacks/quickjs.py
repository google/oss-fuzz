"""QuickJS project-specific hacks."""

from . import ProjectHack


class QuickJSHack(ProjectHack):
  """Hacks for the QuickJS project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix QuickJS Dockerfile issues."""
    dft.str_replace('https://github.com/horhof/quickjs',
                    'https://github.com/bellard/quickjs')
    return True
