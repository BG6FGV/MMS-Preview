"""Analyze 14200.mms binary structure."""
import struct

data = open(r'C:\Users\tirsm\Desktop\新建文件夹\MMS\14200.mms', 'rb').read()
print(f'File size: {len(data)} bytes')

# Look for MMS PDU markers
print('\n=== MMS PDU markers (8C xx) ===')
for i in range(len(data)):
    if data[i] == 0x8C and i+1 < len(data) and 0x80 <= data[i+1] <= 0x96:
        print(f'  0x{i:04X}: 8C {data[i+1]:02X}')

# Try to parse as WSP multipart
def read_uintvar(data, pos):
    result = 0
    while pos < len(data):
        b = data[pos]
        result = (result << 7) | (b & 0x7F)
        pos += 1
        if not (b & 0x80):
            return result, pos
    return result, pos

# Check first bytes as potential container header
print('\n=== First bytes analysis ===')
print(f'Bytes 0-3 (uint32 BE): 0x{struct.unpack(">I", data[:4])[0]:08X} = {struct.unpack(">I", data[:4])[0]}')
print(f'Bytes 4-7 (uint32 BE): 0x{struct.unpack(">I", data[4:8])[0]:08X} = {struct.unpack(">I", data[4:8])[0]}')

# Maybe the file has no MMS PDU header at all
# Let's check: does any other .mms in the same folder parse correctly?
import os
folder = r'C:\Users\tirsm\Desktop\新建文件夹\MMS'
for f in sorted(os.listdir(folder)):
    if f.endswith('.mms'):
        d = open(os.path.join(folder, f), 'rb').read()
        first_bytes = d[:4].hex(' ')
        starts_with_8c = d[0] == 0x8C
        print(f'  {f}: {len(d):>6} bytes, starts: {first_bytes}, mms_pdu={starts_with_8c}')

# Now try to understand 14200.mms structure
# It looks like it could be a WSP multipart body WITHOUT the MMS PDU header
# The structure at offset 0:
# 00 00 = uintvar value 0? That doesn't make sense for headers length
# Wait - maybe it starts with the Content-Type of the multipart itself?
# In WSP, multipart content-type starts with 0x3C (length) then "application/vnd.wap.multipart.mixed"
# Or it could be that this is just the raw body of a multipart/related

# Let's check if bytes at 0x13 form a valid uintvar for headers-length
# 0x13 = 19 -> no high bit set, so uintvar = 19
# That would mean: headers-length = 19, headers start at 0x14
print('\n=== Trying parse as raw WSP multipart body ===')
pos = 0
part_num = 0
parts_info = []

while pos < len(data) - 2 and part_num < 20:
    start_pos = pos
    hdr_len, after_hdr_len = read_uintvar(data, pos)
    
    if hdr_len == 0 or hdr_len > 10000:
        # Maybe this isn't a valid uintvar, or we've gone past the parts
        print(f'  Invalid hdr_len={hdr_len} at 0x{pos:04X}, stopping')
        # Show what's there
        print(f'  Bytes: {data[pos:pos+20].hex(" ")}')
        break
    
    hdr_start = after_hdr_len
    hdr_end = hdr_start + hdr_len
    
    if hdr_end >= len(data):
        print(f'  Headers extend beyond file at part {part_num} (0x{pos:04X})')
        break
    
    # Parse content-type from headers
    ct_bytes = data[hdr_start:hdr_end]
    content_type = "?"
    content_loc = ""
    
    # Try to decode content type
    if ct_bytes[0] < 0x80:
        # Well-known content type
        ct_code = ct_bytes[0]
        # Common WSP content types
        ct_map = {
            0x00: "application/vnd.wap.multipart.related",
            0x01: "application/vnd.wap.multipart.mixed",
            0x14: "text/plain",
            0x23: "application/smil",
            0x1E: "image/jpeg",
            0x1F: "image/gif",
            0x20: "image/png",
        }
        content_type = ct_map.get(ct_code, f"well-known(0x{ct_code:02X})")
    elif ct_bytes[0] >> 4 == 0x0A or ct_bytes[0] >> 4 == 0x0B:
        # Text string
        ct_end_pos = 1 + ct_bytes[0] & 0x1F
        content_type = ct_bytes[1:ct_end_pos].decode('ascii', errors='replace')
    elif ct_bytes[0] >> 4 == 0x0C or ct_bytes[0] >> 4 == 0x0D:
        # Extension media type (text string)
        tl = ct_bytes[0] & 0x1F
        content_type = ct_bytes[1:1+tl].decode('ascii', errors='replace')
    
    # Look for Content-Location (0x8E) and Content-ID (0x8C in body context)
    j = 1  # skip first content-type byte
    while j < len(ct_bytes) - 1:
        if ct_bytes[j] == 0x8E:
            # Content-Location: text-string
            loc_start = j + 1
            if ct_bytes[loc_start] < 0x80:
                loc_len = ct_bytes[loc_start]
                content_loc = ct_bytes[loc_start+1:loc_start+1+loc_len].decode('ascii', errors='replace')
                j = loc_start + 1 + loc_len
            else:
                # Text-string with charset marker
                j = loc_start + 1
        elif ct_bytes[j] == 0x8C and ct_bytes[j+1] != 0x84:
            # Content-ID: quoted-string or text-string
            cid_start = j + 1
            if ct_bytes[cid_start] < 0x80:
                cid_len = ct_bytes[cid_start]
                j = cid_start + 1 + cid_len
            else:
                j = cid_start + 1
        else:
            j += 1
    
    # Data starts after headers
    data_start = hdr_end
    
    # For the data length, we need to peek at the next part's uintvar
    # But that's hard - let's use the signature scanner approach instead
    # Just record where each part starts
    
    info = {
        'part': part_num,
        'offset': start_pos,
        'hdr_len': hdr_len,
        'hdr_start': hdr_start,
        'data_start': data_start,
        'content_type': content_type,
        'content_loc': content_loc,
        'hdr_hex': ct_bytes[:40].hex(' '),
    }
    parts_info.append(info)
    
    print(f'\n  Part {part_num}:')
    print(f'    Offset: 0x{start_pos:04X}')
    print(f'    Headers length: {hdr_len}')
    print(f'    Content-Type: {content_type}')
    print(f'    Content-Location: {content_loc}')
    print(f'    Data starts at: 0x{data_start:04X}')
    print(f'    Data preview: {repr(data[data_start:data_start+40])}')
    
    # Move to data area - we need to figure out data length
    # Strategy: look for the next valid uintvar that represents a headers length
    # This is tricky without knowing the data length
    
    # Heuristic: scan data for JPEG/GIF/PNG signatures or text patterns
    data_remaining = data[data_start:]
    
    # Find the end of this part's data by looking for the next WSP headers length
    # In practice, the next part starts with a small uintvar (headers length)
    # We can try to find the next valid boundary
    
    # Actually let's try a different approach:
    # Try each position as a potential next part start
    # A valid next part should have:
    #   - uintvar value between 10-200 (headers length)
    #   - Followed by a valid WSP content type
    
    found_next = False
    for try_pos in range(data_start + 1, min(data_start + 40000, len(data) - 2)):
        test_hdr_len, test_after = read_uintvar(data, try_pos)
        if test_hdr_len < 5 or test_hdr_len > 500:
            continue
        test_ct = data[test_after:test_after + test_hdr_len]
        if len(test_ct) < test_hdr_len:
            continue
        # Check if this could be a valid content type
        if test_ct[0] in (0x1E, 0x1F, 0x20, 0x14, 0x23, 0x01):
            # Looks like a valid part header
            # Verify by checking for Content-Location in the headers
            has_loc = False
            k = 1
            while k < len(test_ct) - 1:
                if test_ct[k] == 0x8E:
                    has_loc = True
                    break
                k += 1
            
            if has_loc:
                data_len = try_pos - data_start
                print(f'    Data length: {data_len} (found next part at 0x{try_pos:04X})')
                pos = try_pos
                found_next = True
                break
    
    if not found_next:
        # Last part - data goes to end of file
        data_len = len(data) - data_start
        print(f'    Data length: {data_len} (last part / no next part found)')
        break
    
    part_num += 1

print(f'\n=== Summary ===')
print(f'Total parts found: {part_num + 1}')
print(f'File size: {len(data)}')
for p in parts_info:
    print(f'  Part {p["part"]}: type={p["content_type"]}, loc={p["content_loc"]}, data@0x{p["data_start"]:04X}')
