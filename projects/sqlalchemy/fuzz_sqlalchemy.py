#!/usr/bin/env python3
"""Fuzz harness for SQLAlchemy — Python ORM (3 GHSA advisories)."""
import sys
import atheris

with atheris.instrument_imports():
    from sqlalchemy import text
    from sqlalchemy.exc import SQLAlchemyError


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    try:
        sql = fdp.ConsumeString(512)
        if sql.strip():
            text(sql)
    except SQLAlchemyError:
        pass
    except Exception:
        pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
