#!/usr/bin/env python3
import sys
import atheris

@atheris.instrument_func
def test_notebook_cell(data):
    try:
        exec(data.decode('utf-8', errors='ignore'))
    except:
        pass

def main():
    atheris.Setup(sys.argv, test_notebook_cell)
    atheris.Fuzz()

if __name__ == '__main__':
    main()
