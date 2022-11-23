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


;xor ax, ax
;mov ds, ax
;mov es, ax
;mov fs, ax
;mov gs, ax
;mov ss, ax
;mov sp, 0x7c00
;jmp 0x0:.reload_cs
;.reload_cs:

;check_int13_ext:
;; query int 0x13 extensions support
;push dx
;mov ah, 0x41
;mov bx, 0x55aa
;int 0x13
;jc error16
;cmp bx, 0xaa55
;jne error16
;continue:
;mov al, 1 ; sector count
;mov cl, 3 ; sector index (starts at 1)
;mov bx, 0x7c00 + 0x200 ; address
;call load_sectors16
;; disable a20
;mov ax, 0x2400
;int 0x15
;switch_to_protected_mode:
;lgdt [gdtr]
;mov eax, cr0
;or al, 1
;mov cr0, eax
;jmp 0x08:protected_mode_main

;error16:
;cli
;jmp $

;; al: sector count
;; cl: sector number (starting by 1)
;; bx: address
;; es segment is supposed to be loaded properly
;load_sectors16:
;mov ah, 0x02
;xor ch, ch
;xor dh, dh
;clc
;int 0x13
;jc error16
;ret

;unreal_mode_read_sectors:
;mov di, 0x20
;mov ds, di
;mov es, di
;mov fs, di
;mov gs, di
;mov ss, di
;jmp 0x0:.continue

;.continue:
;call load_sectors16
;cli
;hlt

;[bits 32]
;protected_mode_main:
;mov ax, 0x10
;mov ds, ax
;mov es, ax
;mov fs, ax
;mov gs, ax
;mov ss, ax
;xor ebp, ebp
;mov esp, 0x7c00
;mov ebx, 0x7c00 + 0x200
;xor ecx, ecx
;xor edx, edx
;mov cx, [ebx + 0x2a] ; cx: ph entry size
;mov dx, [ebx + 0x2c] ; cx: ph entry count
;add ebx, [ebx + 0x1c] ; ebx: ph pointer
;.loop:
;and dword [ebx], 1
;jz .continue
;push ecx
;mov ecx, [ebx + 0xc] ; ecx: address
;mov eax, [ebx + 0x10] ; esi: size
;push ebx
;lea eax, [eax + 0x1ff]
;and eax, 0xfffffe00 ; aligned size
;shr eax, 9 ; sector count
;cmp eax, 0xff
;jg error32 ; sector count too big
;mov ebx, ecx
;sub ecx, 0x8000
;shr ecx, 9
;add ecx, 4 ;0x7c00 - 1;--- 2; 0x7e00 - 3; 0x8000 - 4;
;mov edi, cr0
;and edi, 0xfffffffe
;mov cr0, edi
;jmp 0x0:unreal_mode_read_sectors
;.continue:
;add ebx, ecx ; add entry size to ph pointer
;dec dx ; dec an entry processed
;jnz .loop

;;.continue:
;;add ebx, edi
;;dec si
;;jnz .loop
;;jmp error32

;error32:
;cli
;jmp $


;gdtr:
    ;dw .end - .start - 1
    ;dd .start

;.start:
    ;; null segment
    ;dq 0

    ;; 32-bit code segment
    ;dw 0xffff                   ; limit (bits 0-15)
    ;dw 0                        ; base (bits 0-15)
    ;db 0                        ; base (bits 16-23)
    ;db 0b10011010               ; access (present(bit 7) | code_or_data_segment(bit 4) | executable(bit 3) | readable(bit 0))
    ;; flags: 4k pages | 32bit segment
    ;db (0b1100 << 4) | 0b1111   ; flags | limit (bits 16-19)
    ;db 0                        ; base (bits 24-31)

    ;; 32-bit data segment
    ;dw 0xffff                   ; limit (bits 0-15)
    ;dw 0                        ; base (bits 0-15) 
    ;db 0                        ; base (bits 16-23)
    ;db 0b10010010               ; access (present(bit 7) | code_or_data_segment(bit 4) | writeable(bit 1))
    ;; 4k pages | 32bit segment
    ;db (0b1100 << 4) | 0b1111   ; flags | limit (bits 16-19)
    ;db 0                        ; base (bits 24-31)

    ;; 16-bit code segment
    ;dw 0xffff                   ; limit (bits 0-15)
    ;dw 0                        ; base (bits 0-15)
    ;db 0                        ; base (bits 16-23)
    ;db 0b10011010               ; access (present(bit 7) | code_or_data_segment(bit 4) | executable(bit 3) | readable(bit 0))
    ;db (0b0000 << 4) | 0b1111   ; flags | limit
    ;db 0                        ; base (bits 24-31)

    ;; 16-bit data segment
    ;dw 0xffff                   ; limit (bits 0-15)
    ;dw 0                        ; base (bits 0-15)
    ;db 0                        ; base (bits 16-23)
    ;db 0b10010010               ; access (present(bit 7) | code_or_data_segment(bit 4) | writeable(bit 1))
    ;db (0b0000 << 4) | 0b1111   ; flags | limit
    ;db 0                        ; base (bits 24-31)
;.end:

