"""ImageMagick project-specific hacks."""

from pathlib import Path
from . import ProjectHack


class ImageMagickHack(ProjectHack):
  """Hacks for the ImageMagick project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix ImageMagick Dockerfile issues."""
    # Fix heic corpus download issue
    dft.replace(r'RUN svn .*heic_corpus.*',
                "RUN mkdir /src/heic_corpus && touch /src/heic_corpus/XxX")
    return True

  def apply_extra_fixes(self, source_dir: Path) -> bool:
    """Apply extra ImageMagick-specific fixes."""
    # TODO: Improve this hack
    target = (source_dir / "src" / "imagemagick" / "Magick++" / "fuzz" /
              "build.sh")
    if target.exists():
      with open(target, encoding='utf-8') as f:
        lines = f.readlines()
      for x in range(3):
        if lines and "zip" in lines[-x - 1]:
          del lines[-x - 1]
      with open(target, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))
    return True
