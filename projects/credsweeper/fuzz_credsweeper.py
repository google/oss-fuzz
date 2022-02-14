#!/usr/bin/python3

import sys

import atheris

with atheris.instrument_imports(enable_loader_override=False):
    import credsweeper


def fuzz_credsweeper_scan(data):
    fdp = atheris.FuzzedDataProvider(data)
    to_scan = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 1000))
    cred_sweeper = credsweeper.app.CredSweeper()
    provider = credsweeper.file_handler.byte_content_provider.ByteContentProvider(to_scan)
    cred_sweeper.file_scan(provider)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, fuzz_credsweeper_scan, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
