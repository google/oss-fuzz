"""WolfSSL project-specific hacks."""
"""http://www.apache.org/licenses/LICENSE-2.0"""

from . import ProjectHack


class WolfSSLHack(ProjectHack):
  """Hacks for the WolfSSL project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix WolfSSL Dockerfile issues."""
    dft.str_replace(
        'RUN wget '
        'gs://wolfssl-backup.clusterfuzz-external.appspot.com/'
        'corpus/libFuzzer/wolfssl_cryptofuzz-disable-fastmath/public.zip '
        '$SRC/corpus_wolfssl_disable-fastmath.zip', "RUN touch 0xdeadbeef && "
        "zip $SRC/corpus_wolfssl_disable-fastmath.zip 0xdeadbeef")
    return True
