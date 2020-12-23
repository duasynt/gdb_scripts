# Get the PTE for a given virtual address
#
# ARM64 support only for now
#
# Author: Vitaly Nikolenko
# vnik@duasynt.com

import gdb
import sys
import ctypes

# --- Default 39-bit VA / 4k config ---

KERN_PGD_OFFSET = -0x2000
VA_SIZE = 39
PGD_MASK = 0x7fc0000000
PGD_SHIFT = 30
PMD_MASK = 0x3fe00000
PMD_SHIFT = 21
PTE_MASK = 0x1ff000
PTE_SHIFT = 12
DESCRIPTOR_SIZE = 8

# Start of the linear map. TODO: randomised physmap
PAGE_OFFSET = 0xffffffffffffffff - (1 << (VA_SIZE - 1)) + 1

def read_qword(addr):
    m = gdb.selected_inferior().read_memory(addr, 8);
    return int.from_bytes(m.tobytes(), byteorder='little')

def phys_to_virt(addr):
    memstart_addr_s = gdb.parse_and_eval("memstart_addr")
    memstart_addr = ctypes.c_ulong(memstart_addr_s)
    
    return PAGE_OFFSET + addr - memstart_addr.value

def get_bit(val, bit):
    base = int(bit // 8)
    shift = int(bit % 8)
    return (val[base] & (1 << shift)) >> shift

def find_kern_pgd():
    # Assuming _text is loaded with the right KASLR offset
    _text_s = gdb.parse_and_eval("_text").address
    _text = ctypes.c_ulong(_text_s)

    # Read the 3rd qword    
    kern_img_size = read_qword(_text.value + 16)
    print("Kernel image size = 0x%lx" % kern_img_size)

    return _text.value + kern_img_size + KERN_PGD_OFFSET

def pte_dump(val):
    print("--- PTE dump ---")
    _bytes = val.to_bytes(8, byteorder='little')
    print("PTE value = 0x%lx" % val)
    #print(bin(val))

    # -- Lower attributes --
    print("AttrIndx = %d%d%d" % (get_bit(_bytes, 4), get_bit(_bytes, 3),
          get_bit(_bytes, 2)))
    print("NS = %d" % (get_bit(_bytes, 5)))

    if get_bit(_bytes, 6) == 0 and get_bit(_bytes, 7) == 0:
        print("AP = 00: R/W (EL1) and None (EL0)")
    if get_bit(_bytes, 6) == 1 and get_bit(_bytes, 7) == 0:
        print("AP = 01: R/W (EL1) and R/W (EL0)")
    if get_bit(_bytes, 6) == 0 and get_bit(_bytes, 7) == 1:
        print("AP = 10: R (EL1) and None (EL0)")
    if get_bit(_bytes, 6) == 1 and get_bit(_bytes, 7) == 1:
        print("AP = 11: R (EL1) and R (EL0)")

    print("SH = %d%d" % (get_bit(_bytes, 9), get_bit(_bytes, 8)))
    print("AF = %d" % get_bit(_bytes, 10))
    print("nG = %d" % get_bit(_bytes, 11))

    # -- Upper attributes --
    print("Contiguous = %d" % get_bit(_bytes, 52))
    print("PXN = %d" % get_bit(_bytes, 53))
    print("UXN = %d" % get_bit(_bytes, 54))

def is_block(val):
    if val % 3 == 1:
        return True

    return False
    
def get_pgd_offset(addr):
    return ((addr & PGD_MASK) >> PGD_SHIFT) * DESCRIPTOR_SIZE

def get_pmd_offset(addr):
    return ((addr & PMD_MASK) >> PMD_SHIFT) * DESCRIPTOR_SIZE

def get_pte_offset(addr):
    return ((addr & PTE_MASK) >> PTE_SHIFT) * DESCRIPTOR_SIZE

def get_pte(addr):
    addr = int(addr, 16)

    kern_pgd = find_kern_pgd()
    print("Kernel PGD = 0x%lx" % kern_pgd)

    pgd_offset = get_pgd_offset(addr)
    print("PGD offset = %lx" % pgd_offset)
    phys_pmd_addr = read_qword(kern_pgd + pgd_offset) 

    if is_block(phys_pmd_addr):
        pte_dump(phys_pmd_addr)
        return

    # Clear the least-significant 12 bits, i.e. page size
    phys_pmd_addr &= ~((1 << 12) - 1)
    print("PMD physical address = 0x%lx" % phys_pmd_addr)

    # Compute the PMD virt address
    pmd_addr = phys_to_virt(phys_pmd_addr)
    print("PMD virtual address = 0x%lx" % pmd_addr)

    pmd_offset = get_pmd_offset(addr)
    phys_pte_addr = read_qword(pmd_addr + pmd_offset)

    if is_block(phys_pte_addr):
        pte_dump(phys_pte_addr)
        return

    phys_pte_addr &= ~((1 << 12) - 1)

    # Compute the PTE virt address
    pte_offset = get_pte_offset(addr)
    pte_addr = phys_to_virt(phys_pte_addr + pte_offset)
    pte = read_qword(pte_addr)

    pte_dump(pte)

class MM(gdb.Command):
    def __init__(self):
        super(MM, self).__init__("get_pte", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        if arg == "":
            print("get_pte virtual_address")
            return

        get_pte(arg)
    
MM()
