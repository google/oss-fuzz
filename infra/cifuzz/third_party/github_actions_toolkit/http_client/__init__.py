"""Module for HTTP code.
Based on https://github.com/actions/http-client/blob/main/index.ts"""

import enum


class HTTPCode(enum.Enum):
  """Enum representing meaning of HTTP codes."""
  BAD_REQUEST = 400
  FORBIDDEN = 403
  NOT_FOUND = 404
