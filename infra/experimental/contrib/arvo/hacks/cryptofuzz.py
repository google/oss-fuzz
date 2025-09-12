"""Cryptofuzz project-specific hacks."""

from . import ProjectHack


class CryptofuzzHack(ProjectHack):
  """Hacks for the Cryptofuzz project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix Cryptofuzz Dockerfile issues."""
    # Fix libressl update script
    dft.insert_line_before(
        "RUN cd $SRC/libressl && ./update.sh",
        "RUN sed -n -i '/^# setup source paths$/,$p' $SRC/libressl/update.sh")

    return True
