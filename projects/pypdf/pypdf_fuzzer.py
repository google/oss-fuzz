#!/usr/bin/env python3
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Deep-state fuzzer for pypdf.
Targets XRef resolution, Stream decoding, Object graphs, and Metadata parsing.
"""

import io
import sys
import logging
import atheris
import pypdf
from pypdf.generic import IndirectObject
from pypdf import PdfWriter

try:
    from pypdf import PdfMerger
except ImportError:
    PdfMerger = None

logging.getLogger("pypdf").setLevel(logging.CRITICAL)
logging.getLogger("PIL").setLevel(logging.CRITICAL)

sys.setrecursionlimit(5000)

try:
    from pypdf.errors import LimitReachedError
    HAS_LIMIT_ERROR = True
except ImportError:
    HAS_LIMIT_ERROR = False

EXPECTED_PARSE_EXCEPTIONS = (
    pypdf.errors.PdfReadError,
    pypdf.errors.PdfStreamError,
    pypdf.errors.DependencyError,
    KeyError,
    IndexError,
    ValueError,
    OSError,
    TypeError,
    AttributeError,
    NotImplementedError,
)

if HAS_LIMIT_ERROR:
    EXPECTED_PARSE_EXCEPTIONS = (*EXPECTED_PARSE_EXCEPTIONS, LimitReachedError)


def _safe_call(callable_fn, *args, **kwargs):
    """
    Invokes a function. If an expected error occurs, returns None.
    If a crash/DoS bug occurs, re-raises it for Atheris to catch.
    """
    try:
        return callable_fn(*args, **kwargs)
    except EXPECTED_PARSE_EXCEPTIONS:
        return None
    except (RecursionError, MemoryError) as exc:
        raise exc
    except Exception as exc:
        # Catch-all for SystemError or other crashes
        raise exc


def _resolve_indirect_objects(reader):
    """
    Forces resolution of the object graph by iterating the XRef table
    and decoding all streams.
    """
    try:
        if not reader.xref:
            return
        for gen in reader.xref.values():
            if isinstance(gen, dict):
                for obj_num in gen.keys():
                    ref = IndirectObject(obj_num, 0, reader)
                    obj = _safe_call(reader.get_object, ref)
                    if obj is not None and hasattr(obj, "get_data"):
                        _safe_call(obj.get_data)
    except EXPECTED_PARSE_EXCEPTIONS:
        pass


def _deep_page_traversal(reader):
    """
    Traverses pages, extracts text, and dives into resources (fonts/xobjects).
    """
    try:
        pages = _safe_call(lambda: reader.pages)
        if not pages:
            return
        num_pages = _safe_call(len, pages)
        if not num_pages:
            return
        for idx in range(min(num_pages, 20)):
            page = _safe_call(pages.__getitem__, idx)
            if not page:
                continue
            _safe_call(page.extract_text)
            resources = _safe_call(page.get, "/Resources")
            if resources:
                xobjects = _safe_call(resources.get, "/XObject")
                if xobjects:
                    for xobj in list(xobjects.values())[:5]:
                        if hasattr(xobj, "get_data"):
                            _safe_call(xobj.get_data)
                fonts = _safe_call(resources.get, "/Font")
                if fonts:
                    for font in list(fonts.values())[:5]:
                        if hasattr(font, "get_data"):
                            _safe_call(font.get_data)
    except EXPECTED_PARSE_EXCEPTIONS:
        pass


def _fuzz_writer(reader):
    """
    Tests PDF creation and serialization.
    Triggers bugs in object copying and stream writing.
    """
    try:
        writer = PdfWriter()
        writer.append(reader)
        _safe_call(writer.write, io.BytesIO())
        writer.add_blank_page(width=200, height=200)
        _safe_call(writer.write, io.BytesIO())
    except EXPECTED_PARSE_EXCEPTIONS:
        pass


def _fuzz_merger(reader):
    """
    Tests merging multiple documents.
    Exercises xref table combination and object number remapping.
    """
    # SAFETY CHECK: If PdfMerger is not available, skip this path.
    if PdfMerger is None:
        return
    try:
        merger = PdfMerger()
        merger.append(reader)
        _safe_call(merger.write, io.BytesIO())
        merger.close()
    except EXPECTED_PARSE_EXCEPTIONS:
        pass


def _test_one_input(input_bytes):
    """Main fuzzer entry point."""
    fdp = atheris.FuzzedDataProvider(input_bytes)

    # 1. Initial Parse
    data_length = fdp.ConsumeIntInRange(1, max(1, len(input_bytes)))
    data = fdp.ConsumeBytes(data_length)

    if len(data) < 8:
        return

    reader = _safe_call(pypdf.PdfReader, io.BytesIO(data))
    if reader is None:
        return

    # 2. Deep Exploration (FDP-guided)
    branch = fdp.ConsumeIntInRange(0, 4)

    if branch == 0:
        _resolve_indirect_objects(reader)
    elif branch == 1:
        _deep_page_traversal(reader)
    elif branch == 2:
        _safe_call(lambda: reader.metadata)
        _safe_call(reader.get_fields)
    elif branch == 3:
        _fuzz_writer(reader)
    else:
        _fuzz_merger(reader)


def main():
    if hasattr(atheris, 'instrument_lib'):
        atheris.instrument_lib()
    else:
        atheris.instrument_all()

    atheris.Setup(sys.argv, _test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()