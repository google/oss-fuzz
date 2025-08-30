"""Curl project-specific hacks."""

from . import ProjectHack, register_hack


class CurlHack(ProjectHack):
  """Hacks for the Curl project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix Curl Dockerfile issues."""
    # Check if download_zlib.sh exists and replace zlib URL
    dft.append_line(
        'RUN [ -f "/src/curl_fuzzer/scripts/download_zlib.sh" ] && sed -i \'s|https://www.zlib.net/zlib-1.2.11.tar.gz|https://www.zlib.net/fossils/zlib-1.2.11.tar.gz|g\' /src/curl_fuzzer/scripts/download_zlib.sh || true'
    )
    return True


# Register the hack
register_hack("curl", CurlHack)
