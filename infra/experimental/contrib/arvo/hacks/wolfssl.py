"""WolfSSL project-specific hacks."""

from . import ProjectHack


class WolfSSLHack(ProjectHack):
  """Hacks for the WolfSSL project."""

  def apply_dockerfile_fixes(self, dft) -> bool:
    """Fix WolfSSL Dockerfile issues."""
    # Replace gsutil cp command with a simple touch and zip
    dft.str_replace(
        'RUN gsutil cp '
        'gs://wolfssl-backup.clusterfuzz-external.appspot.com/'
        'corpus/libFuzzer/wolfssl_cryptofuzz-disable-fastmath/public.zip '
        '$SRC/corpus_wolfssl_disable-fastmath.zip', "RUN touch 0xdeadbeef && "
        "zip $SRC/corpus_wolfssl_disable-fastmath.zip 0xdeadbeef")
    return True
