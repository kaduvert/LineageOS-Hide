#!/usr/bin/env python3
"""gen_dex.py — generates hooks.dex (no Android SDK required)."""
import struct, hashlib, zlib, os

# ── helpers ────────────────────────────────────────────────────────────────
def uleb128(v):
    assert v >= 0, f"uleb128 got {v}"
    out = []
    while True:
        b = v & 0x7F; v >>= 7
        if v: b |= 0x80
        out.append(b)
        if not v: break
    return bytes(out)

def mutf8(s):
    out = bytearray()
    for ch in s:
        cp = ord(ch)
        if cp == 0:        out += b'\xc0\x80'
        elif cp < 0x80:    out.append(cp)
        elif cp < 0x800:   out += bytes([0xC0|(cp>>6), 0x80|(cp&0x3F)])
        else:              out += bytes([0xE0|(cp>>12), 0x80|((cp>>6)&0x3F), 0x80|(cp&0x3F)])
    return bytes(out)

def pad4(b):
    while len(b) % 4: b.append(0)
    return b

w4 = lambda v: struct.pack('<I', v & 0xFFFFFFFF)
w2 = lambda v: struct.pack('<H', v & 0xFFFF)

# ── opcodes ────────────────────────────────────────────────────────────────
def op_invoke_static(regs, midx):
    A = len(regs)
    assert A <= 5
    G = regs[4] if A==5 else 0
    C,D,E,F = [(regs[i] if A>i else 0) for i in range(4)]
    return struct.pack('<HHH', 0x71|(A<<12)|(G<<8), midx&0xFFFF, C|(D<<4)|(E<<8)|(F<<12))

def op_invoke_static_range(first, n, midx):
    return struct.pack('<HHH', 0x77|(n<<8), midx&0xFFFF, first&0xFFFF)

def op_move_result_obj(r): return struct.pack('<H', 0x0c|(r<<8))
def op_move_result(r):     return struct.pack('<H', 0x0a|(r<<8))
def op_return_obj(r):      return struct.pack('<H', 0x11|(r<<8))
def op_return_int(r):      return struct.pack('<H', 0x0f|(r<<8))
def op_return_void():      return struct.pack('<H', 0x000e)

# ── data classes ───────────────────────────────────────────────────────────
ACC_PUBLIC = 0x0001; ACC_STATIC = 0x0008; ACC_NATIVE = 0x0100
T_OBJ='Ljava/lang/Object;'; T_STR='Ljava/lang/String;'; T_INT='I'
CLS_N='Lio/github/lineagehide/Native;'; CLS_H='Lio/github/lineagehide/Hooks;'

METHODS = [
    ('smGetService',           'LL',   T_OBJ, (T_STR,)),
    ('smCheckService',         'LL',   T_OBJ, (T_STR,)),
    ('smListServices',         'L',    T_OBJ, ()),
    ('smListServicesInt',      'LI',   T_OBJ, (T_INT,)),
    ('pmGetPackageInfo',       'LLLI', T_OBJ, (T_OBJ, T_STR, T_INT)),
    ('pmGetApplicationInfo',   'LLLI', T_OBJ, (T_OBJ, T_STR, T_INT)),
    ('pmGetInstalledPackages', 'LLI',  T_OBJ, (T_OBJ, T_INT)),
    ('pmGetInstalledApps',     'LLI',  T_OBJ, (T_OBJ, T_INT)),
    ('pmGetPackagesForUid',    'LLI',  T_OBJ, (T_OBJ, T_INT)),
]

# ── two-pass DEX builder ───────────────────────────────────────────────────
def sorted_strs(all_strs):
    return sorted(all_strs, key=lambda s: [ord(c) for c in s])

def build_dex_from_raw(native_methods, hooks_insns_map):
    """
    native_methods: list of (nm,sh,r,ps) — native class methods (no code)
    hooks_insns_map: dict (nm,sh,r,ps) -> bytes — hooks class bytecode
    """
    # collect all IDs
    all_strs = set(); all_types = set(); all_protos = set(); all_meths = set()

    def reg(cls, nm, sh, r, ps):
        all_strs.update([sh, nm, cls, r] + list(ps))
        all_types.update([cls, r] + list(ps))
        all_protos.add((sh, r, ps))
        all_meths.add((cls, nm, sh, r, ps))

    all_types.add(T_OBJ); all_strs.add(T_OBJ)
    all_types.add(CLS_N); all_strs.add(CLS_N)
    all_types.add(CLS_H); all_strs.add(CLS_H)

    for nm,sh,r,ps in native_methods:
        reg(CLS_N, nm, sh, r, ps)
        reg(CLS_H, nm, sh, r, ps)

    # sort
    str_list  = sorted_strs(all_strs)
    SI = {s:i for i,s in enumerate(str_list)}

    type_list = sorted(all_types, key=lambda d: SI[d])
    TI = {d:i for i,d in enumerate(type_list)}

    proto_list = sorted(all_protos, key=lambda p: (TI[p[1]],)+tuple(TI[x] for x in p[2]))
    PI = {p:i for i,p in enumerate(proto_list)}

    method_list = sorted(all_meths,
        key=lambda m: (TI[m[0]], PI[(m[2],m[3],m[4])], SI[m[1]]))
    MI = {m:i for i,m in enumerate(method_list)}

    # ── data section ──────────────────────────────────────────────────────
    data = bytearray()

    # string data
    str_data_offs = []
    for s in str_list:
        str_data_offs.append(len(data))
        data += uleb128(len(s)) + mutf8(s) + b'\x00'

    # type_lists
    tl_cache = {}; proto_param_offs = []
    for sh,r,ps in proto_list:
        if not ps: proto_param_offs.append(0); continue
        if ps not in tl_cache:
            pad4(data); off = len(data)
            data += w4(len(ps))
            for p in ps: data += w2(TI[p])
            if len(ps)%2: data += b'\x00\x00'
            tl_cache[ps] = off
        proto_param_offs.append(tl_cache[ps])

    # code items for Hooks methods
    code_offs = {}
    for nm,sh,r,ps in native_methods:
        key = (CLS_H, nm, sh, r, ps)
        if key not in hooks_insns_map: continue
        insns = bytearray(hooks_insns_map[key])
        if len(insns)%4: insns += b'\x00\x00'
        k = len(ps)
        pad4(data); off = len(data)
        # code_item: registers, ins, outs, tries_size, debug_info_off, insns_size, insns
        data += struct.pack('<HHHHI', max(1,k), k, k, 0, 0)  # 10 bytes
        data += w4(len(insns)//2)                              # insns_size
        data += bytes(insns)
        code_offs[key] = off

    # class_data items
    classes_specs = [
        (CLS_N, native_methods, 'native'),
        (CLS_H, native_methods, 'hooks'),
    ]
    class_data_offs = {}
    for cls_desc, methods, kind in classes_specs:
        # sort methods by their MI index (required for diff encoding)
        mlist = sorted(methods, key=lambda m: MI[(cls_desc, m[0], m[1], m[2], m[3])])
        pad4(data); off = len(data)
        data += uleb128(0)           # static_fields_size
        data += uleb128(0)           # instance_fields_size
        data += uleb128(len(mlist))  # direct_methods_size (all static = direct)
        data += uleb128(0)           # virtual_methods_size
        prev_idx = 0
        for nm,sh,r,ps in mlist:
            key = (cls_desc, nm, sh, r, ps)
            idx = MI[key]
            diff = idx - prev_idx; prev_idx = idx
            assert diff >= 0, f"negative diff {diff} for {key}"
            data += uleb128(diff)
            if kind == 'native':
                data += uleb128(ACC_PUBLIC|ACC_STATIC|ACC_NATIVE)
                data += uleb128(0)  # code_off = 0 (native)
            else:
                data += uleb128(ACC_PUBLIC|ACC_STATIC)
                data += uleb128(code_offs.get(key, 0))
        class_data_offs[cls_desc] = off

    # ── calculate offsets ─────────────────────────────────────────────────
    HDR=0x70
    off_strs   = HDR
    off_types  = off_strs   + 4*len(str_list)
    off_protos = off_types  + 4*len(type_list)
    off_fields = off_protos + 12*len(proto_list)
    off_meths  = off_fields                          # no fields
    off_cdefs  = off_meths  + 8*len(method_list)
    off_data   = off_cdefs  + 32*2                   # 2 classes

    def doff(x): return (x+off_data) if x else 0

    # ── sections ──────────────────────────────────────────────────────────
    sec = bytearray()
    for o in str_data_offs: sec += w4(o+off_data)
    pad4(sec)
    for d in type_list: sec += w4(SI[d])
    pad4(sec)
    for i,(sh,r,ps) in enumerate(proto_list):
        sec += w4(SI[sh]); sec += w4(TI[r]); sec += w4(doff(proto_param_offs[i]))
    pad4(sec)
    # (no fields)
    pad4(sec)
    for cls,nm,sh,r,ps in method_list:
        sec += w2(TI[cls]); sec += w2(PI[(sh,r,ps)]); sec += w4(SI[nm])
    pad4(sec)
    for cls_desc in [CLS_N, CLS_H]:
        sec += w4(TI[cls_desc])
        sec += w4(ACC_PUBLIC)
        sec += w4(TI[T_OBJ])    # superclass = Object
        sec += w4(0)             # interfaces_off
        sec += w4(0xFFFFFFFF)   # source_file_idx
        sec += w4(0)             # annotations_off
        sec += w4(doff(class_data_offs[cls_desc]))
        sec += w4(0)             # static_values_off

    # map_list
    pad4(data)
    map_off = off_data + len(data)
    entries = [(t,c,o) for t,c,o in [
        (0x0001,1,HDR),
        (0x0002,len(str_list), off_strs),
        (0x0003,len(type_list),off_types),
        (0x0004,len(proto_list),off_protos),
        (0x0006,len(method_list),off_meths),
        (0x0007,2,off_cdefs),
        (0x2002,len(str_list),off_data),
        (0x1001,1,map_off),
    ] if c>0]
    data += w4(len(entries))
    for t,c,o in entries: data += struct.pack('<HHII',t,0,c,o)

    fsize = HDR + len(sec) + len(data)
    hdr = bytearray(HDR)
    hdr[:8] = b'dex\n035\x00'
    struct.pack_into('<I',hdr,32,fsize); struct.pack_into('<I',hdr,36,HDR)
    struct.pack_into('<I',hdr,40,0x12345678); struct.pack_into('<I',hdr,52,map_off)
    struct.pack_into('<I',hdr,56,len(str_list));  struct.pack_into('<I',hdr,60,off_strs)
    struct.pack_into('<I',hdr,64,len(type_list)); struct.pack_into('<I',hdr,68,off_types)
    struct.pack_into('<I',hdr,72,len(proto_list));struct.pack_into('<I',hdr,76,off_protos)
    struct.pack_into('<I',hdr,80,0);              struct.pack_into('<I',hdr,84,0)
    struct.pack_into('<I',hdr,88,len(method_list));struct.pack_into('<I',hdr,92,off_meths)
    struct.pack_into('<I',hdr,96,2);              struct.pack_into('<I',hdr,100,off_cdefs)
    struct.pack_into('<I',hdr,104,fsize-off_data);struct.pack_into('<I',hdr,108,off_data)

    body = bytes(hdr)+bytes(sec)+bytes(data)
    sha1 = hashlib.sha1(body[32:]).digest()
    body = body[:12]+sha1+body[32:]
    adler = zlib.adler32(body[12:])&0xFFFFFFFF
    body = body[:8]+struct.pack('<I',adler)+body[12:]
    return body, MI

# ── main ───────────────────────────────────────────────────────────────────
def main():
    # Pass 1: get stable MI (method index map) with placeholder bytecode
    placeholder = b'\x0e\x00'  # return-void
    ph_map = {(CLS_H, nm, sh, r, ps): placeholder for nm,sh,r,ps in METHODS}
    _, MI = build_dex_from_raw(METHODS, ph_map)

    # Pass 2: real bytecode using MI from pass 1
    def make_insns(nm, sh, r, ps):
        k = len(ps); regs = list(range(k))
        n_idx = MI[(CLS_N, nm, sh, r, ps)]
        insns = bytearray()
        if k <= 5: insns += op_invoke_static(regs, n_idx)
        else:       insns += op_invoke_static_range(0, k, n_idx)
        if r == T_INT:
            insns += op_move_result(0); insns += op_return_int(0)
        else:
            insns += op_move_result_obj(0); insns += op_return_obj(0)
        return bytes(insns)

    insns_map = {(CLS_H,nm,sh,r,ps): make_insns(nm,sh,r,ps) for nm,sh,r,ps in METHODS}
    dex_bytes, _ = build_dex_from_raw(METHODS, insns_map)

    out = os.path.join(os.path.dirname(__file__),'..','module','assets','hooks.dex')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out,'wb') as f: f.write(dex_bytes)
    assert dex_bytes[:8] == b'dex\n035\x00'
    print(f'[gen_dex] {len(dex_bytes)} bytes → {os.path.abspath(out)}  ✓')

if __name__=='__main__': main()
