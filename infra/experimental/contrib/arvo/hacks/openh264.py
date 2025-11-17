"""OpenH264 project-specific hacks."""

from . import ProjectHack


class OpenH264Hack(ProjectHack):
  """Hacks for the OpenH264 project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """No Dockerfile fixes needed for OpenH264."""
    return True

  def apply_build_script_fixes(self, dft) -> bool:
    """Fix OpenH264 build script issues."""
    lines = dft.content.split("\n")
    starts = -1
    ends = -1
    for num, line in enumerate(lines):
      if "# prepare corpus" in line:
        starts = num
      elif "# build" in line:
        ends = num
        break
    if starts != -1 and ends != -1:
      dft.remove_range(starts, ends)
    return True
