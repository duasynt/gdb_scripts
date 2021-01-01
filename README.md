## ARM64 Android/Linux kernel gdb scripts

Helper scripts for kernel debugging.

`page_table.py` implements a manual page walk for aarch64 in `get_pte()`.
There's currently no support for randomised physmap, so compile your kernel
without KASLR.

```
(gdb) source page_table.py
(gdb) p/x &selinux_enforcing
$3 = 0xffffff8009c83770
(gdb) get_pte 0xffffff8009c83770
Kernel image size = 0x2086000
Kernel PGD = 0xffffff800a104000
PGD offset = 0
PMD physical address = 0x1fa7fe000
PMD virtual address = 0xffffffc17a7fe000
--- PTE dump ---
PTE value = 0xe8000081c00711
AttrIndx = 100
NS = 0
AP = 00: R/W (EL1) and None (EL0)
SH = 11
AF = 1
nG = 0
Contiguous = 0
PXN = 1
UXN = 1
(gdb) 
```

If the passed address / symbol is in kernel space, the walk is performed using
the kernel PGD. Otherwise, the PGD of the backing process
(`task_struct->mm->pgd`) is used to resolve the mapping.

In theory, it's possible to add KASLR support but due to some major differences
in KASLR implementations between different vendors (e.g., AOSP/MSM and Samsung),
I've decided not to. And why would you want to debug with KASLR enabled anyway?
