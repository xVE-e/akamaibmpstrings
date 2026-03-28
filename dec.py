"""
Emulates .init_proc -> sub_2CBF50 (Speck-like block cipher)
  python3 dec.py [input.so] [output.so]
"""

import struct 
import sys
import os
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN, UC_HOOK_MEM_UNMAPPED
from unicorn.arm64_const import (UC_ARM64_REG_SP, UC_ARM64_REG_LR,
                                 UC_ARM64_REG_FP, UC_ARM64_REG_PC)

class ElfMapper:
    def __init__(self, data):
        self.data = data
        self.segments = []
        self._parse(data)

    def _parse(self, data):
        e_phoff = struct.unpack_from('<Q', data, 32)[0]
        e_phentsize = struct.unpack_from('<H', data, 54)[0]
        e_phnum = struct.unpack_from('<H', data, 56)[0]
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type = struct.unpack_from('<I', data, off)[0]
            if p_type != 1:
                continue
            p_offset = struct.unpack_from('<Q', data, off + 8)[0]
            p_vaddr = struct.unpack_from('<Q', data, off + 16)[0]
            p_filesz = struct.unpack_from('<Q', data, off + 32)[0]
            p_memsz = struct.unpack_from('<Q', data, off + 40)[0]
            self.segments.append((p_vaddr, p_offset, p_filesz, p_memsz))

    def va_to_offset(self, va):
        for vaddr, foff, fsz, msz in self.segments:
            if vaddr <= va < vaddr + msz:
                delta = va - vaddr
                if delta < fsz:
                    return foff + delta
                return None
        return None


def decrypt(so_path):
    with open(so_path, 'rb') as f:
        so_data = bytearray(f.read())

    elf = ElfMapper(so_data)
    max_va = max(vaddr + msz for vaddr, _, _, msz in elf.segments)

    IMG_SIZE = ((max_va + 0x10000) & ~0xFFF)
    STACK_BASE = 0x7F000000
    STACK_SIZE = 0x200000

    mu = Uc(UC_ARCH_ARM64, UC_MODE_LITTLE_ENDIAN)
    mu.mem_map(0, IMG_SIZE)
    mu.mem_map(STACK_BASE, STACK_SIZE)

    for vaddr, foff, fsz, msz in elf.segments:
        mu.mem_write(vaddr, bytes(so_data[foff:foff + fsz]))
        print(f"  Mapped LOAD: file 0x{foff:x} -> VA 0x{vaddr:x} (0x{fsz:x} bytes)")

    mu.reg_write(UC_ARM64_REG_SP, STACK_BASE + STACK_SIZE - 0x1000)
    mu.reg_write(UC_ARM64_REG_FP, STACK_BASE + STACK_SIZE - 0x2000)

    RET_INSN = b'\xC0\x03\x5F\xD6'
    mu.mem_write(0x254314, RET_INSN)  # stub mprotect
    mu.mem_write(0x25429C, RET_INSN)  # stub cache flush

    RET_ADDR = STACK_BASE + STACK_SIZE - 0x100
    mu.mem_write(RET_ADDR, RET_INSN)
    mu.reg_write(UC_ARM64_REG_LR, RET_ADDR)

    def hook_unmapped(mu, access, address, size, value, user_data):
        pc = mu.reg_read(UC_ARM64_REG_PC)
        print(f"  [!] Unmapped access @ 0x{address:x} size={size} from PC=0x{pc:x}")
        return False
    mu.hook_add(UC_HOOK_MEM_UNMAPPED, hook_unmapped)

    print("\n[*] Emulating sub_2CBF50 @ 0x2CBF50...")
    try:
        mu.emu_start(0x2CBF50, RET_ADDR, timeout=120_000_000)
        print("[+] Emulation completed successfully!")
    except Exception as e:
        pc = mu.reg_read(UC_ARM64_REG_PC)
        print(f"[!] Emulation stopped: {e} (PC=0x{pc:x})")

    output = bytearray(so_data)
    patched = 0
    for vaddr, foff, fsz, msz in elf.segments:
        decrypted = bytes(mu.mem_read(vaddr, fsz))
        if decrypted != so_data[foff:foff + fsz]:
            output[foff:foff + fsz] = decrypted
            patched += 1
            print(f"  Patched segment VA 0x{vaddr:x} (0x{fsz:x} bytes)")

    print(f"[+] {patched} segments patched")
    return bytes(output)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        script_dir, "libakamaibmp.so")
    output_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        script_dir, "libakamaibmp_dec.so")

    print(f"[*] Akamai BMP 4.1.3")
    print(f"[*] Input:  {input_path}")
    print(f"[*] Output: {output_path}\n")

    result = decrypt(input_path)

    with open(output_path, 'wb') as f:
        f.write(result)

    print(f"\n[+] Written: {output_path} ({len(result)} bytes)")

    elf = ElfMapper(result)
    for name, va in [("initializeKeyN", 0x9d060), ("encryptKeyN", 0x9d074),
                     ("decryptN", 0x9d18c), ("buildN", 0x9d394)]:
        foff = elf.va_to_offset(va)
        if foff and foff + 4 <= len(result):
            word = struct.unpack_from('<I', result, foff)[0]
            ok = (word >> 24) in (0xA9, 0xD1, 0xF8, 0xAA, 0x6D, 0xD5, 0x37, 0x36, 0xB4, 0xB5, 0x14, 0x94)
            status = "VALID ARM64" if ok else f"raw: {result[foff:foff+4].hex()}"
            print(f"  {name:20s} @ VA 0x{va:x} -> file 0x{foff:x}: {status}")


if __name__ == '__main__':
    main()
