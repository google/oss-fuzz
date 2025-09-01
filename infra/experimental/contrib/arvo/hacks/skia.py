"""Skia project-specific hacks."""

from . import ProjectHack


class SkiaHack(ProjectHack):
  """Hacks for the Skia project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix Skia Dockerfile issues."""
    # Comment out wget commands and fix build script
    dft.str_replace('RUN wget', "# RUN wget")
    dft.insert_line_after('COPY build.sh $SRC/',
                          "RUN sed -i 's/cp.*zip.*//g' $SRC/build.sh")
    return True
