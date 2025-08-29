"""Cryptofuzz project-specific hacks."""

from . import ProjectHack, register_hack


class CryptofuzzHack(ProjectHack):
  """Hacks for the Cryptofuzz project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix Cryptofuzz Dockerfile issues."""
    # Fix libressl update script
    dft.insert_line_before(
        "RUN cd $SRC/libressl && ./update.sh",
        "RUN sed -n -i '/^# setup source paths$/,$p' $SRC/libressl/update.sh")

    # Remove cryptofuzz-corpora line (from old implementation)
    dft.replace(r".*https://github.com/guidovranken/cryptofuzz-corpora.*", "")
    return True


# Register the hack
register_hack("cryptofuzz", CryptofuzzHack)
