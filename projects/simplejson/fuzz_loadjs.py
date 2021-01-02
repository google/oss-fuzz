import atheris
import sys
import simplejson

# Fuzz simplejson.loads 
def TestOneInput(data):
  fdp = atheris.FuzzedDataProvider(data)
  original = fdp.ConsumeUnicode(sys.maxsize)
  try:
    simplejson.loads(original)
  except (simplejson.JSONDecodeError,
          simplejson.JSONDecodeError,
          ValueError,
          RecursionError):
    None
  return

atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()

