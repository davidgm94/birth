org 0x7c00
bits 16

start:
    jmp .skip_bpb
    nop

.bpb:
times 3-($-$$) db 0
.bpb_oem_id:            db "RISE    "
.bpb_sector_size:       dw 512
.bpb_sects_per_cluster: db 0
.bpb_reserved_sects:    dw 0
.bpb_fat_count:         db 0
.bpb_root_dir_entries:  dw 0
.bpb_sector_count:      dw 0
.bpb_media_type:        db 0
.bpb_sects_per_fat:     dw 0
.bpb_sects_per_track:   dw 18
.bpb_heads_count:       dw 2
.bpb_hidden_sects:      dd 0
.bpb_sector_count_big:  dd 0
.bpb_drive_num:         db 0
.bpb_reserved:          db 0
.bpb_signature:         db 0
.bpb_volume_id:         dd 0
.bpb_volume_label:      db "RISE       "
.bpb_filesystem_type:   times 8 db 0

.skip_bpb:
    cli
    cld
    jmp 0x0000:initialize_cs

initialize_cs:
    xor si, si
    mov ds, si
    mov es, si
    mov ss, si
    mov sp, 0x7c00
    sti
    
    mov ah, 0x41
    mov bx, 0x55aa
    int 0x13
    jc error16
    cmp bx, 0xaa55
    jne error16

read_sectors:
    mov ah, 0x42
    mov si, dap
    clc
    int 0x13
    jc error16

    lgdt [gdt]

    cli
    mov eax, cr0
    or eax, 1
    mov cr0, eax

    jmp 0x08:protected_mode

error16:
    cli
    hlt

gdt:
    dw .size - 1 + 8  ; GDT size
    dd .start - 8     ; GDT start address

  .start:
    ; 32-bit code
    dw 0xffff       ; Limit
    dw 0x0000       ; Base (low 16 bits)
    db 0x00         ; Base (mid 8 bits)
    db 10011010b    ; Access
    db 11001111b    ; Granularity
    db 0x00         ; Base (high 8 bits)

    ; 32-bit data
    dw 0xffff       ; Limit
    dw 0x0000       ; Base (low 16 bits)
    db 0x00         ; Base (mid 8 bits)
    db 10010010b    ; Access
    db 11001111b    ; Granularity
    db 0x00         ; Base (high 8 bits)

  .end:

  .size: equ .end - .start

bits 32
protected_mode:
    mov eax, 0x10
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax

    xor eax, ecx
    xor ebx, ebx
    mov ebp, dword [dap.pointer]
    mov bx, [ebp + 0x2a] ; ph entry size
    mov ax, [ebp + 0x2c] ; ph entry count
    mov edx, [ebp + 0x1c] ; ph offset
    add edx, ebp
    .loop:
    cmp dword [edx], 1
    jne .continue
    mov esi, ebp
    add esi, dword [edx + 0x4] ; elf-in-memory-source
    mov edi, dword [edx + 0xc] ; segment physical address
    mov ecx, dword [edx + 0x10] ; segment file size
    rep movsb
    .continue:
    add edx, ebx
    dec ax
    jnz .loop
    mov ebx, [ebp + 0x18]
    jmp ebx
    
times 0x1a8-($-$$) db 0
dap:
    .size: db 0
    .unused: db 0
    .sector_count: dw 0
    .pointer: dw 0
    .lba: dq 0

times 0x1b8-($-$$) db 0 ; metadata
times 0x1fe-($-$$) db 0 ; 2 bytes less now
db 0x55
db 0xAA
