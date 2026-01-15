import sys
import struct

def bit_reverse(n, bits):
    result = 0
    for i in range(bits):
        result = (result << 1) | (n & 1)
        n >>= 1
    return result

def decompress_msb(data, decomp_size):
    # MSB Implementation (matches my current Go code)
    if len(data) < 256: return None, "Data too short for table"
    table_bytes = data[:256]
    input_pos = 256
    
    lengths = []
    for b in table_bytes:
        lengths.append(b & 0xF)
        lengths.append(b >> 4)
        
    len_counts = [0]*17
    for l in lengths: len_counts[l] += 1
    len_counts[0] = 0
    
    next_code = [0]*17
    code = 0
    for i in range(1, 16):
        code = (code + len_counts[i-1]) << 1
        next_code[i] = code
        
    decode_table = {} # Map code -> (sym, len)
    # Using explicit matching for simplicity in Python (slow but fine for debug)
    
    # Actually, let's build the lookup table to match Go logic
    # MSB: Code is at top.
    
    TABLE_BITS = 15
    lookup = [None] * (1 << TABLE_BITS)
    
    for sym, l in enumerate(lengths):
        if l == 0: continue
        c = next_code[l]
        next_code[l] += 1
        
        # Fill table
        # Index starts at c << (15-l)
        start_idx = c << (TABLE_BITS - l)
        num_entries = 1 << (TABLE_BITS - l)
        for i in range(num_entries):
            lookup[start_idx + i] = (sym, l)
            
    output = bytearray()
    bit_buf = 0
    bits_left = 0
    
    # Helper to fill bits
    def fill():
        nonlocal bit_buf, bits_left, input_pos
        while bits_left <= 16:
            if input_pos + 2 > len(data): break
            val = struct.unpack_from('<H', data, input_pos)[0]
            input_pos += 2
            # MSB: Add to RIGHT of valid bits
            # valid bits are at top.
            shift = 32 - bits_left - 16
            if shift >= 0:
                bit_buf |= (val << shift)
                bits_left += 16
            else:
                break
                
    fill()
    
    while len(output) < decomp_size:
        if bits_left < 15: fill()
        if bits_left == 0 and input_pos >= len(data): break
        
        idx = bit_buf >> (32 - 15)
        entry = lookup[idx]
        if not entry: return None, f"Invalid code at output {len(output)}"
        sym, l = entry
        
        # Consume
        bit_buf <<= l
        bit_buf &= 0xFFFFFFFF
        bits_left -= l
        
        if sym < 256:
            output.append(sym)
        else:
            m = sym - 256
            val = m
            length = (m & 0xF) + 3
            offset_bits = m >> 4
            
            if bits_left < offset_bits: fill()
            
            if offset_bits > 0:
                off_val = bit_buf >> (32 - offset_bits)
                bit_buf <<= offset_bits
                bit_buf &= 0xFFFFFFFF
                bits_left -= offset_bits
            else:
                off_val = 0
                
            offset = (1 << offset_bits) | off_val
            
            src_idx = len(output) - offset
            
            for i in range(length):
                if src_idx + i < 0:
                    b = 0 # Assume zero-initialized history
                else:
                    b = output[src_idx + i] # Using absolute index now since we calc'd src_idx
                output.append(b)
                
    return output, None

def decompress_lsb(data, decomp_size):
    return None, "Skipped"

def main():
    path = "/Users/test/exploit/gtrace/test_demo/HAYABUSA-3.7.0-WIN-AARCH64.EX-64669604.pf"
    try:
        with open(path, 'rb') as f:
            raw = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # MAM header check
    if raw[:3] != b'MAM':
        print("Not MAM")
        return
        
    decomp_size = struct.unpack('<I', raw[4:8])[0]
    data = raw[8:]
    print(f"MAM Body Size: {len(data)}, Target Output: {decomp_size}")
    
    # Try MSB
    print("Trying MSB with Zero History...")
    try:
        out1, err1 = decompress_msb(data, decomp_size)
        if err1: 
            print(f"MSB Failed: {err1}")
            if out1:
                 # Print first 20 chars
                 print(f"Partial Hex: {out1[:32].hex()}")
                 print(f"Partial Ascii: {out1[:32]}")
        else: 
            print(f"MSB Success!")
            print(f"Head: {out1[:32].hex()}")
    except Exception as e:
        print(f"MSB Crash: {e}")


if __name__ == "__main__":
    main()
