/* Higher-half reference kernel: linked at -2 GiB (0xffffffff80000000), the
 * canonical top-of-address-space kernel base Warden maps it to. One PT_LOAD
 * segment keeps the loader trivial. */
ENTRY(_start)

SECTIONS {
    . = 0xffffffff80000000;
    __kernel_start = .;

    .text   : ALIGN(0x1000) { *(.text .text.*) }
    .rodata : ALIGN(0x1000) { *(.rodata .rodata.*) }
    .data   : ALIGN(0x1000) { *(.data .data.*) }
    .bss    : ALIGN(0x1000) { *(.bss .bss.*) *(COMMON) }

    __kernel_end = .;

    /DISCARD/ : { *(.eh_frame) *(.note .note.*) *(.comment) }
}
