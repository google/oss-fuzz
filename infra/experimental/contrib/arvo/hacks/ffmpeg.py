"""FFmpeg project-specific hacks."""

from . import ProjectHack, register_hack, x265_fix


class FFmpegHack(ProjectHack):
  """Hacks for the FFmpeg project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix FFmpeg Dockerfile issues."""
    # Apply x265 fixes
    x265_fix(dft)
    return True


# Register the hack
register_hack("ffmpeg", FFmpegHack)
