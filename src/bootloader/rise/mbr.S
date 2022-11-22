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
mov al, 1 ; sector count
mov cl, 3 ; sector index (starts at 1)
mov bx, 0x7c00 + 0x200 ; address
call load_sectors16
; disable a20
mov ax, 0x2400
int 0x15
switch_to_protected_mode:
lgdt [gdtr]
mov eax, cr0
or al, 1
mov cr0, eax
jmp 0x08:protected_mode_main

error16:
cli
jmp $

; al: sector count
; cl: sector number (starting by 1)
; bx: address
; es segment is supposed to be loaded properly
load_sectors16:
mov ah, 0x02
xor ch, ch
xor dh, dh
clc
int 0x13
jc error16
ret

unreal_mode_read_sectors:
mov di, 0x20
mov ds, di
mov es, di
mov fs, di
mov gs, di
mov ss, di
jmp 0x0:.continue

.continue:
call load_sectors16
cli
hlt

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
mov ebx, 0x7c00 + 0x200
xor ecx, ecx
xor edx, edx
mov cx, [ebx + 0x2a] ; cx: ph entry size
mov dx, [ebx + 0x2c] ; cx: ph entry count
add ebx, [ebx + 0x1c] ; ebx: ph pointer
.loop:
and dword [ebx], 1
jz .continue
push ecx
mov ecx, [ebx + 0xc] ; ecx: address
mov eax, [ebx + 0x10] ; esi: size
push ebx
lea eax, [eax + 0x1ff]
and eax, 0xfffffe00 ; aligned size
shr eax, 9 ; sector count
cmp eax, 0xff
jg error32 ; sector count too big
mov ebx, ecx
sub ecx, 0x8000
shr ecx, 9
add ecx, 4 ;0x7c00 - 1;--- 2; 0x7e00 - 3; 0x8000 - 4;
mov edi, cr0
and edi, 0xfffffffe
mov cr0, edi
jmp 0x0:unreal_mode_read_sectors
.continue:
add ebx, ecx ; add entry size to ph pointer
dec dx ; dec an entry processed
jnz .loop

;.continue:
;add ebx, edi
;dec si
;jnz .loop
;jmp error32

error32:
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
