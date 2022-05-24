import atheris
with atheris.instrument_imports():
  import grpc

def TestInput(input_bytes):
   fdp = atheris.FuzzedDataProvider(input_bytes)
   grpc.access_token_call_credentials('abc')

def main():
   atheris.Setup(sys.argv, TestInput, enable_python_coverage=True)
   atheris.Fuzz()

if __name__ == "__main__":
   main()
