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
        # We catch all standard Python exceptions (ValueError, AttributeError, OverflowError, etc.)
        # We are strictly hunting for DoS (Timeouts, OOM) and Native crashes.
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()