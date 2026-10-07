"""JBIG2DEC project-specific hacks."""

from . import ProjectHack


class JBIG2DECHack(ProjectHack):
  """Hacks for the JBIG2DEC project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix JBIG2DEC Dockerfile issues."""
    dft.replace(r'RUN cd tests .*', "")
    return True

  def apply_build_script_fixes(self, dft) -> bool:
    """Fix JBIG2DEC build script issues."""
    dft.replace('unzip.*', 'exit 0')
    return True
