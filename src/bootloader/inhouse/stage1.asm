[bits 16]
[org 0x7c00]

%define stage2_location 0x1000
%define temporary_load_buffer 0x9000

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov sp, 0x7c00
    jmp 0x0:main

main:
    sti

    mov [drive], dl
    mov [partition], si
    mov [is_emulator], dh

    or dh, dh
    jz .skip_parameters
    mov ah, 0x08
    xor di, di
    int 0x13
    mov si, error_disk
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

    .skip_parameters:
	; Print a startup message
	mov	si,startup_message
	.loop:
	lodsb
	or	al,al
	jz	.end
	mov	ah,0xE
	int	0x10
	jmp	.loop
	.end:

    ; Load stage 2
    mov cx, 15
    mov eax, 1
    mov edi, stage2_location ; stage 2 location
    call load_sectors

    mov dl, [drive]
    mov si, [partition]
    mov dh, [is_emulator]
    mov bx, [max_sectors]
    mov cx, [max_heads]

    jmp $

load_sectors:
	; Load CX sectors from sector EAX to buffer [EDI]. Returns end of buffer in EDI.
	pusha
	push	edi

	; Add the partition offset to EAX
	mov	bx,[partition]
	mov	ebx,[bx + 8]
	add	eax,ebx

	; Load 1 sector
	mov	[read_structure.lba],eax
	mov	ah,0x42
	mov	dl,[drive]
	mov	si,read_structure
	cmp	byte [is_emulator],1
	je	.use_emu
	int	0x13
	jmp	.done_read
	.use_emu:
	call	load_sector_emu
	.done_read:

	; Check for error
	mov	si,error_disk
	jc	error

	; Copy the data to its destination
	pop	edi
	mov	cx,0x200
	mov	eax,edi
	shr	eax,4
	and	eax,0xF000
	mov	es,ax
	mov	si,temporary_load_buffer
	rep	movsb

	; Go to the next sector
	popa
	add	edi,0x200
	inc	eax
	loop	load_sectors
	ret

load_sector_emu:
	mov	di,[read_structure.lba]
	xor	ax,ax
	mov	es,ax
	mov	bx,0x9000
	
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

	ret

error:
    lodsb
    or al, al
    jz .break
    mov ah, 0xe
    int 0x10
    jmp error

    .break:
    cli
    hlt

startup_message: db "Booting operating system...",10,13,0

error_disk: db "Error: cannot read disk",0
error_bad_geometry: db "Error: bad geometry",0

max_sectors: dw 0
max_heads: dw 0
partition: dw 0
drive: db 0
is_emulator: db 0


read_structure: ; Data for the extended read calls
	dw	0x10
	dw	1
	dd 	temporary_load_buffer
	.lba:	dq 0

times (0x200 - ($-$$)) nop
