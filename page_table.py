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

def get_pid():
    pid = gdb.selected_thread().ptid[1]
    return pid

def offsetof(_type, member):
    return (gdb.Value(0).cast(_type)[member]).address

def container_of(ptr, _type, member):
    ulong = gdb.lookup_type("unsigned long")

    top = ptr.cast(ulong) - offsetof(_type, member).cast(ulong)
    return top.cast(_type)

def find_by_pid(pid):
    task_struct_ptr = gdb.lookup_type("struct task_struct").pointer()
    
    init_task_s = gdb.parse_and_eval("init_task").address
    init_task = init_task_s.cast(task_struct_ptr)

    curr_task = container_of(init_task['tasks']['next'], task_struct_ptr, 'tasks')

    while curr_task != init_task:
        if curr_task['pid'] == pid:
            break

        curr_task = container_of(curr_task['tasks']['next'], task_struct_ptr, 'tasks')

    if curr_task == init_task:
        print('Failed to find the backing task_struct')
        return None

    return curr_task

def get_current():
    pid = get_pid()
    curr_task = find_by_pid(pid)
    print(curr_task['cpu'])
    
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

def lookup_sym(sym):
    # Address lookup or value? 
    try:
        if sym[0] == '&':
            _sym_str = gdb.parse_and_eval(sym[1:]).address
        else:
            _sym_str = gdb.parse_and_eval(sym)
    except gdb.error:
        print("Couldn't resolve symbol: %s" % sym)
        return None

    return (ctypes.c_ulong(_sym_str)).value

def find_kern_pgd():
    # Assuming _text is loaded with the right KASLR offset
    _text = lookup_sym("&_text")

    # Read the 3rd qword    
    kern_img_size = read_qword(_text + 16)
    print("Kernel image size = 0x%lx" % kern_img_size)

    return _text + kern_img_size + KERN_PGD_OFFSET

def software_bits(_bytes):
    print("-- Software defined PTE bits --")
    print("VALID = %d" % get_bit(_bytes, 0))
    print("WRITE/DBM = %d" % get_bit(_bytes, 51))
    print("DIRTY = %d" % get_bit(_bytes, 55))
    print("SPECIAL = %d" % get_bit(_bytes, 56))
    print("PROT_NONE = %d" % get_bit(_bytes, 58))

def hardware_bits(_bytes):
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

def pte_dump(val):
    print("--- PTE dump ---")
    _bytes = val.to_bytes(8, byteorder='little')
    print("PTE value = 0x%lx" % val)

    hardware_bits(_bytes)
    software_bits(_bytes)
   
def is_block(val):
    if val & 3 == 1:
        return True

    return False
    
def get_pgd_offset(addr):
    return ((addr & PGD_MASK) >> PGD_SHIFT) * DESCRIPTOR_SIZE

def get_pmd_offset(addr):
    return ((addr & PMD_MASK) >> PMD_SHIFT) * DESCRIPTOR_SIZE

def get_pte_offset(addr):
    return ((addr & PTE_MASK) >> PTE_SHIFT) * DESCRIPTOR_SIZE

def get_pte(addr):
    try:
        addr = int(addr, 16)
    except ValueError:
        addr = lookup_sym(addr)
        if addr == None: 
            print("Input addr needs to be either in hex or a symbol name")
            return

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
    pmd_offset = get_pmd_offset(addr)
    print("PMD virtual address = 0x%lx" % (pmd_addr + pmd_offset))
    phys_pte_addr = read_qword(pmd_addr + pmd_offset)

    if is_block(phys_pte_addr):
        pte_dump(phys_pte_addr)
        return

    phys_pte_addr &= ~((1 << 12) - 1)

    # Compute the PTE virt address
    pte_offset = get_pte_offset(addr)
    pte_addr = phys_to_virt(phys_pte_addr + pte_offset)
    print("PTE virtual address = 0x%lx" % pte_addr)
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
