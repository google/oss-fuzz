"""uWebSockets project-specific hacks."""

from . import ProjectHack


class UWebSocketsHack(ProjectHack):
  """Hacks for the uWebSockets project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """No Dockerfile fixes needed for uWebSockets."""
    return True

  def apply_build_script_fixes(self, dft) -> bool:
    """Fix uWebSockets build script issues."""
    # https://github.com/alexhultman/zlib -> https://github.com/madler/zlib.git
    script = "sed -i 's/alexhultman/madler/g' fuzzing/Makefile"
    dft.insert_line_at(0, script)
    return True
