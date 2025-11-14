#!/usr/bin/env python3
import struct, os, zipfile, io

def u16(x, be=False): return struct.pack('>H' if be else '<H', x)
def u32(x, be=False): return struct.pack('>I' if be else '<I', x)
LONG_VR = {b'OB', b'OW', b'OF', b'SQ', b'UC', b'UR', b'UT', b'UN', b'OD', b'OL', b'OV'}

def pad(vr: bytes, s: str, text_enc='latin-1') -> bytes:
    if vr == b'UI':
        b = s.encode('ascii')
        if len(b) % 2: b += b'\x00'
    else:
        b = s.encode(text_enc, 'replace')
        if len(b) % 2: b += b' '
    return b

def el_explicit(g,e,vr,val,be=False):
    if isinstance(vr, str): vr = vr.encode('ascii')
    out = io.BytesIO()
    out.write(u16(g,be)); out.write(u16(e,be))
    out.write(vr)
    if vr in LONG_VR:
        out.write(b'\x00\x00'); out.write(u32(len(val), be)); out.write(val)
    else:
        out.write(u16(len(val), be)); out.write(val)
    return out.getvalue()

def el_implicit(g,e,val,be=False):
    out = io.BytesIO()
    out.write(u16(g,be)); out.write(u16(e,be))
    out.write(u32(len(val), be)); out.write(val)
    return out.getvalue()

def item_defined(payload, be=False):
    return u16(0xFFFE,be) + u16(0xE000,be) + u32(len(payload),be) + payload

def item_undef(payload, be=False):
    return (u16(0xFFFE,be) + u16(0xE000,be) + u32(0xFFFFFFFF,be) + payload +
            u16(0xFFFE,be) + u16(0xE00D,be) + u32(0,be))

def seq_defined_explicit(g,e,items, be=False):
    body = b''.join(item_defined(p, be) for p in items)
    return el_explicit(g,e,b'SQ', body, be)

def seq_undef_explicit(g,e,items, be=False):
    body = b''.join(item_undef(p, be) for p in items) + (u16(0xFFFE,be)+u16(0xE0DD,be)+u32(0,be))
    hdr = u16(g,be)+u16(e,be)+b'SQ'+b'\x00\x00'+u32(0xFFFFFFFF,be)
    return hdr + body

def seq_defined_implicit(g,e,items, be=False):
    body = b''.join(item_defined(p, be) for p in items)
    return el_implicit(g,e, body, be)

def seq_undef_implicit(g,e,items, be=False):
    body = b''.join(item_undef(p, be) for p in items) + (u16(0xFFFE,be)+u16(0xE0DD,be)+u32(0,be))
    return u16(g,be)+u16(e,be)+u32(0xFFFFFFFF,be)+body

def meta_group(ts_uid: str, with_gl=True):
    parts = []
    parts.append(el_explicit(0x0002,0x0001,b'OB', b'\x00\x01', be=False))
    parts.append(el_explicit(0x0002,0x0002,b'UI', pad(b'UI','1.2.840.10008.5.1.4.1.1.2'), be=False))
    parts.append(el_explicit(0x0002,0x0003,b'UI', pad(b'UI','1.2.826.0.1.3680043.8.498.1000001'), be=False))
    parts.append(el_explicit(0x0002,0x0010,b'UI', pad(b'UI', ts_uid), be=False))
    parts.append(el_explicit(0x0002,0x0012,b'UI', pad(b'UI','1.2.826.0.1.3680043.8.498.1'), be=False))
    parts.append(el_explicit(0x0002,0x0016,b'AE', pad(b'AE','FUZZ'), be=False))
    body = b''.join(parts)
    if not with_gl:
        return body
    gl = el_explicit(0x0002,0x0000,b'UL', struct.pack('<I', len(body)), be=False)
    return gl + body

def part10(path, ts_uid: str, dataset: bytes, with_gl=True):
    with open(path, 'wb') as f:
        f.write(b'\x00'*128 + b'DICM')
        f.write(meta_group(ts_uid, with_gl))
        f.write(dataset)

def seed_explicit_le_basic(path):
    be=False
    ds = b''.join([
        el_explicit(0x0008,0x0020,b'DA', pad(b'DA','20250101'), be),
        el_explicit(0x0008,0x0031,b'TM', pad(b'TM','120101'), be),
        el_explicit(0x0010,0x0010,b'PN', pad(b'PN','FUZZ^TEST'), be),
        seq_defined_explicit(0x0010,0x1002, [
            el_explicit(0x0010,0x0020,b'LO', pad(b'LO','12345'), be)
        ], be),
    ])
    part10(path, '1.2.840.10008.1.2.1', ds, with_gl=True)

def seed_implicit_le_basic(path):
    be=False
    item = el_implicit(0x0010,0x0020, pad(b'LO','ABC123'))
    ds = b''.join([
        el_implicit(0x0010,0x0010, pad(b'PN','IMPL^LE')),
        seq_undef_implicit(0x0010,0x1002, [ item ], be),
    ])
    part10(path, '1.2.840.10008.1.2', ds, with_gl=True)

def seed_explicit_be(path):
    be=True
    ds = b''.join([
        el_explicit(0x0010,0x0010,b'PN', pad(b'PN','BIG^END'), be),
        el_explicit(0x0008,0x0020,b'DA', pad(b'DA','19991231'), be),
    ])
    part10(path, '1.2.840.10008.1.2.2', ds, with_gl=True)

def seed_sq_undef_explicit(path):
    be=False
    item_payload = b''.join([
        el_explicit(0x0008,0x0100,b'SH', pad(b'SH','CODE'), be),
        el_explicit(0x0008,0x0102,b'SH', pad(b'SH','SYS'), be),
    ])
    ds = seq_undef_explicit(0x0040,0x0275, [item_payload], be)
    part10(path, '1.2.840.10008.1.2.1', ds, with_gl=True)

def seed_pixel_ob_small(path):
    be=False
    ds = b''.join([
        el_explicit(0x0028,0x0010,b'US', struct.pack('<H',1), be),
        el_explicit(0x0028,0x0011,b'US', struct.pack('<H',1), be),
        el_explicit(0x7FE0,0x0010,b'OB', b'\x00\x01\x02\x03', be),
    ])
    part10(path, '1.2.840.10008.1.2.1', ds, with_gl=True)

def seed_private_tags(path):
    be=False
    ds = b''.join([
        el_explicit(0x0009,0x0010,b'LO', pad(b'LO','ACME 1.0'), be),
        el_explicit(0x0009,0x1001,b'UN', b'\x01\x02\x03\x04', be),
    ])
    part10(path, '1.2.840.10008.1.2.1', ds, with_gl=True)

def seed_charset_latin1(path):
    be=False
    name = 'MÖLLER^JÜRGEN'
    ds = b''.join([
        el_explicit(0x0008,0x0005,b'CS', pad(b'CS','ISO_IR 100'), be),
        el_explicit(0x0010,0x0010,b'PN', pad(b'PN',name,'latin-1'), be),
    ])
    part10(path, '1.2.840.10008.1.2.1', ds, with_gl=True)

def seed_zero_len_and_odd_pad(path):
    be=False
    ds = b''.join([
        el_explicit(0x0008,0x1030,b'LO', pad(b'LO','A'), be),
        el_explicit(0x0008,0x0018,b'UI', pad(b'UI',''), be),
    ])
    part10(path, '1.2.840.10008.1.2.1', ds, with_gl=True)

def seed_un_bytes(path):
    be=False
    ds = b''.join([
        el_explicit(0x0008,0x0008,b'CS', pad(b'CS','DERIVED\\SECONDARY'), be),
        el_explicit(0x0040,0xA160,b'UT', pad(b'UT','NOTE'), be),
        el_explicit(0x0008,0x9123,b'UN', b'\xDE\xAD\xBE\xEF', be),
    ])
    part10(path, '1.2.840.10008.1.2.1', ds, with_gl=True)

def seed_ul_us_extremes(path):
    be=False
    ds = b''.join([
        el_explicit(0x0020,0x0012,b'IS', pad(b'IS','1'), be),
        el_explicit(0x0028,0x0002,b'US', struct.pack('<H', 0xFFFF), be),
        el_explicit(0x0008,0x1312,b'UL', struct.pack('<I', 0xFFFFFFFF), be),
    ])
    part10(path, '1.2.840.10008.1.2.1', ds, with_gl=True)

def seed_meta_without_group_length(path):
    be=False
    ds = el_explicit(0x0010,0x0010,b'PN', pad(b'PN','NOGL^META'), be)
    part10(path, '1.2.840.10008.1.2.1', ds, with_gl=False)

out_dir = '/tmp/dcmtk_seeds'
os.makedirs(out_dir, exist_ok=True)
makers = [
  ('seed-exp-le.dcm', seed_explicit_le_basic),
  ('seed-impl-le.dcm', seed_implicit_le_basic),
  ('seed-exp-be.dcm', seed_explicit_be),
  ('seed-sq-undef.dcm', seed_sq_undef_explicit),
  ('seed-pixel-ob.dcm', seed_pixel_ob_small),
  ('seed-private.dcm', seed_private_tags),
  ('seed-charset-latin1.dcm', seed_charset_latin1),
  ('seed-zero-odd.dcm', seed_zero_len_and_odd_pad),
  ('seed-un-bytes.dcm', seed_un_bytes),
  ('seed-ul-us-max.dcm', seed_ul_us_extremes),
  ('seed-meta-nogl.dcm', seed_meta_without_group_length),
]
for name, fn in makers[:10]:
  fn(os.path.join(out_dir, name))

with zipfile.ZipFile('/out/dcmtk_dicom_fuzzer_seed_corpus.zip', 'w', zipfile.ZIP_DEFLATED) as z:
  for name, _ in makers[:10]:
    z.write(os.path.join(out_dir, name), arcname=name)
print("Seed corpus written to /out/dcmtk_dicom_fuzzer_seed_corpus.zip")
