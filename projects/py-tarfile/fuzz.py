import tarfile
import io
import sys
import atheris

@atheris.instrument_func
def test_one_input(data):
    try:
        # Use the data as an in-memory tar file
        with tarfile.open(fileobj=io.BytesIO(data), mode='r') as tar:
            # Try to list the contents
            tar.getnames()
    except tarfile.TarError:
        pass
    except EOFError:
        pass
    except Exception as e:
        raise e

def main():
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
