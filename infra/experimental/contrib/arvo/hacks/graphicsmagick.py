"""GraphicsMagick project-specific hacks."""

from . import ProjectHack, x265_fix


class GraphicsMagickHack(ProjectHack):
  """Hacks for the GraphicsMagick project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix GraphicsMagick Dockerfile issues."""
    # Fix mercurial clone with retry logic
    dft.replace(
        r'RUN hg clone .* graphicsmagick', 'RUN (CMD="hg clone --insecure '
        'https://foss.heptapod.net/graphicsmagick/graphicsmagick '
        'graphicsmagick" && '
        'for x in `seq 1 100`; do $($CMD); '
        'if [ $? -eq 0 ]; then break; fi; done)')

    # Apply x265 fixes
    x265_fix(dft)
    return True
