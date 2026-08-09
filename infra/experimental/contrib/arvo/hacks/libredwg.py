"""LibreDWG project-specific hacks."""

from . import ProjectHack


class LibreDWGHack(ProjectHack):
  """Hacks for the LibreDWG project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """No Dockerfile fixes needed for LibreDWG."""
    return True

  def apply_build_script_fixes(self, dft) -> bool:
    """Fix LibreDWG build script issues."""
    dft.replace(r'^make$', 'make -j`nproc`\n')
    return True
