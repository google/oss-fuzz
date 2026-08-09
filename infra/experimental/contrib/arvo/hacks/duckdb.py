"""DuckDB project-specific hacks."""

from . import ProjectHack


class DuckDBHack(ProjectHack):
  """Hacks for the DuckDB project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """No Dockerfile fixes needed for DuckDB."""
    return True

  def apply_build_script_fixes(self, dft) -> bool:
    """Fix DuckDB build script issues."""
    dft.replace(r'^make$', 'make -j`nproc`\n')
    return True
