[bits 16]
[org 0x600]

start:

    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov sp, 0x7c00

    cmp dl, 0x80
    mov si, error_floppy_dl
    jb error
    mov si, error_weird_dl
    cmp dl, 0x8f
    ja error

    ; Relocate to 0x600
    cld
    mov si, 0x7c00
    mov di, 0x600
    mov cx, 0x200
    rep movsb
    jmp 0x0:main
main:
    mov [drive], dl
    ; Check for 0x13 extensions
    sti
    ; Clear the screen
    mov ax, 3
    int 0x10
    mov ah, 0x41
    mov bx, 0x55aa
    int 0x13
    mov si, error_int13
    jc error
    cmp bx, 0xaa55
    jne error

    ; Check device parameters
    mov ah, 0x08
    xor di, di
    int 0x13
    mov si, error_disk_check
    jc error
    and cx, 0b111111
    mov [max_sectors], cx
    inc dh
    shr dx, 8
    mov [max_heads], dx
    mov si, error_bad_geometry
    or cx, cx
    jz error
    or dx, dx
    jz error

    ; TODO: check for bootable partitions
    push bx
    mov di, 1
    mov bx, 0x7c00
    call load_sector

    mov dl, [drive] ; drive number
    mov si, 0 ; partition
    mov dh, 0x1 ; use emulator
    jmp 0x0:0x7c00

; di - LBA.
; es:bx - buffer
load_sector:
	; Calculate cylinder and head.
	mov	ax,di
	xor	dx,dx
	div	word [max_sectors]
	xor	dx,dx
	div	word [max_heads]
	push	dx ; remainder - head
	mov	ch,al ; quotient - cylinder
	shl	ah,6
	mov	cl,ah

	; Calculate sector.
	mov	ax,di
	xor	dx,dx
	div	word [max_sectors]
	inc	dx
	or	cl,dl

	; Load the sector.
	pop	dx
	mov	dh,dl
	mov	dl,[drive]
	mov	ax,0x0201
	int	0x13
	mov	si,error_disk
	jc	error

	ret

error:
    sti
.error_loop:
    ; Print an error message
    lodsb
    or  al,al
    jz  .halt
    mov ah,0xE
    int 0x10
    jmp .error_loop

    ; Break indefinitely
    .halt:
    cli
    hlt

success:
    mov si, success_string
    jmp error

error_floppy_dl: db "Error: Floppy DL",0
error_weird_dl: db "Error: Weird DL",0
error_int13: db "Error: Weird DL",0
error_disk_check: db "Error: cannot read disk parameters", 0
error_disk: db "Error: cannot read disk", 0
error_bad_geometry: db "Error: bad disk geometry", 0

success_string: db "Success", 0

drive: db 0
max_sectors: dw 0
max_heads: dw 0

times 510-($-$$) db 0
db 0x55
db 0xaa
