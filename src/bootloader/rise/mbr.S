[bits 16]
[org 0x7c00]

start:
cli
xor ax, ax
mov ds, ax
mov es, ax
mov fs, ax
mov gs, ax
mov ss, ax
mov sp, 0x7c00
jmp 0x0:.reload_cs
.reload_cs:

check_int13_ext:
; query int 0x13 extensions support
push dx
mov ah, 0x41
mov bx, 0x55aa
int 0x13
jc error16
cmp bx, 0xaa55
jne error16
continue:
mov ah, 0x02
mov al, 1
xor ch, ch
mov cl, 3
mov dh, 0
mov bx, 0x7c00 + 0x200
mov di, 0
mov es, di
int 0x13
jc error16
; disable a20
mov ax, 0x2400
int 0x15
switch_to_protected_mode:
lgdt [gdtr]
mov eax, cr0
or al, 1
mov cr0, eax
jmp 0x08:protected_mode_main

[bits 32]
protected_mode_main:
mov ax, 0x10
mov ds, ax
mov es, ax
mov fs, ax
mov gs, ax
mov ss, ax
xor ebp, ebp
mov esp, 0x7c00
jmp 0x7c00 + 0x200 + 0xb4

[bits 16]
error16:
cli
jmp $

gdtr:
    dw .end - .start - 1
    dd .start

.start:
    ; null segment
    dq 0

    ; 32-bit code segment
    dw 0xffff                   ; limit (bits 0-15)
    dw 0                        ; base (bits 0-15)
    db 0                        ; base (bits 16-23)
    db 0b10011010               ; access (present(bit 7) | code_or_data_segment(bit 4) | executable(bit 3) | readable(bit 0))
    ; flags: 4k pages | 32bit segment
    db (0b1100 << 4) | 0b1111   ; flags | limit (bits 16-19)
    db 0                        ; base (bits 24-31)

    ; 32-bit data segment
    dw 0xffff                   ; limit (bits 0-15)
    dw 0                        ; base (bits 0-15) 
    db 0                        ; base (bits 16-23)
    db 0b10010010               ; access (present(bit 7) | code_or_data_segment(bit 4) | writeable(bit 1))
    ; 4k pages | 32bit segment
    db (0b1100 << 4) | 0b1111   ; flags | limit (bits 16-19)
    db 0                        ; base (bits 24-31)

    ; 16-bit code segment
    dw 0xffff                   ; limit (bits 0-15)
    dw 0                        ; base (bits 0-15)
    db 0                        ; base (bits 16-23)
    db 0b10011010               ; access (present(bit 7) | code_or_data_segment(bit 4) | executable(bit 3) | readable(bit 0))
    db (0b0000 << 4) | 0b1111   ; flags | limit
    db 0                        ; base (bits 24-31)

    ; 16-bit data segment
    dw 0xffff                   ; limit (bits 0-15)
    dw 0                        ; base (bits 0-15)
    db 0                        ; base (bits 16-23)
    db 0b10010010               ; access (present(bit 7) | code_or_data_segment(bit 4) | writeable(bit 1))
    db (0b0000 << 4) | 0b1111   ; flags | limit
    db 0                        ; base (bits 24-31)
.end:

times 510-($-$$) db 0 ; 2 bytes less now
db 0x55
db 0xAA
