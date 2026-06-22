#!/usr/bin/python3
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
#
################################################################################

import sys
import atheris
import io
with atheris.instrument_imports():
    from pypdf import PdfReader, PdfWriter
    from pypdf.errors import PdfReadError, PdfStreamError, ParseError

def TestOneInput(data):
    if len(data) < 15 or not data.startswith(b"%PDF-"):
        return
    
    try:
        stream = io.BytesIO(data)
        
        # 1. Test Reader
        reader = PdfReader(stream, strict=False)
        
        # Test Encryption / Decryption routines
        if reader.is_encrypted:
            reader.decrypt("")
            reader.decrypt("password")
            
        # Test Metadata & Outlines
        _ = reader.metadata
        _ = reader.xmp_metadata
        try:
            _ = reader.threads
        except Exception:
            pass
        
        # 2. Test Deep Page Extraction
        for page in reader.pages:
            # Text extraction modes
            try:
                _ = page.extract_text(extraction_mode="layout")
                _ = page.extract_text(extraction_mode="plain")
            except Exception:
                pass
            
            # Image & Object extraction
            try:
                for _ in page.images: pass
            except Exception:
                pass
            
            # Form Fields & Annotations
            try:
                _ = page.annotations
            except Exception:
                pass

        # 3. Test Writer (which also handles Merging now)
        writer = PdfWriter()
        writer.append_pages_from_reader(reader)
        writer.write(io.BytesIO())
        
        # Test the newer merging API directly on PdfWriter
        writer2 = PdfWriter()
        writer2.append(io.BytesIO(data))
        writer2.write(io.BytesIO())

    except Exception:
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()