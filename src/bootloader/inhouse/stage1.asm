[bits 16]
[org 0x7c00]

%define stage2_location 0x1000
%define temporary_load_buffer 0x9000
%define page_directory 0x40000
%define page_directory_length 0x20000
%define memory_map 0x60000

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, 0x7c00
    jmp 0x0:main

main:
    sti

    mov [drive], dl
    mov [partition], si
    mov [is_emulator], dh
    mov [max_sectors], bx
    mov [max_heads], cx

    .skip_parameters:
    ; Print a startup message
    mov si,startup_message
    .loop:
    lodsb
    or  al,al
    jz  .end
    mov ah,0xE
    int 0x10
    jmp .loop
    .end:

check_pci:
    mov ax, 0xb101
    xor edi, edi
    int 0x1a
    mov si, error_no_pci
    jc error
    or ah, ah
    jnz error

check_cpuid:
    mov dword [24], .no_cpuid
    xor eax, eax
    cpuid
    jmp .has_cpuid
    .no_cpuid:
    mov si, error_no_cpuid
    jmp error
    .has_cpuid:

check_msr:
    mov dword [24], .no_msr
    mov ecx, 0xc0000080
    rdmsr
    jmp .has_msr
    .no_msr:
    mov si, error_no_msr
    jmp error
    .has_msr:

enable_a20:
    cli
    call check_a20
    jc .a20_enabled
    mov ax, 0x2401
    int 0x15
    call check_a20
    jc .a20_enabled
    mov si, error_a20
    jmp error
    .a20_enabled:
    sti

identity_paging:
    mov eax, page_directory / 16
    mov es, ax
    
    ; Clear the page directory
    xor eax, eax
    mov ecx, 0x400
    xor di, di
    rep stosd

    mov dword [es:0x3ff * 4], page_directory | 3

    mov dword [es:0], (page_directory + 0x1000) | 3

    ; Fill the table
    mov edi, 0x1000
    mov cx, 0x400
    mov eax, 3

    .loop:
    mov [es:edi], eax
    add edi, 4
    add eax, 0x1000
    loop .loop

    mov eax, page_directory
    mov cr3, eax

load_gdt:
    lgdt [gdt_data.gdt]

inform_bios_mixed_mode:
    mov eax, 0xec00
    mov ebx, 3
    int 0x15

load_memory_map:
    xor ebx, ebx

    xor eax, eax
    mov es, ax
    mov ax, memory_map / 16
    mov fs, ax

    .loop:
    mov di, .entry
    mov edx, 0x534D4150
    mov ecx, 24
    mov eax, 0xe820
    mov byte [.acpi], 1
    int 0x15
    jc .finished

    cmp eax, 0x534D4150
    jne .fail

    cmp dword [.type], 1
    jne .try_next
    cmp dword [.size], 0
    je .try_next
    cmp dword [.acpi], 0
    je .try_next

    mov eax, [.size]
    and eax, ~0x3fff
    or eax, eax
    jz .try_next

    cmp dword [.base + 4], 0
    jne .base_good
    cmp dword [.base], 0x100000
    jl .try_next

    .base_good:
    mov eax, [.base]
    and eax, 0xfff
    or eax, eax
    jz .base_aligned
    mov eax, [.base]
    and eax, ~0xfff
    add eax, 0x1000
    mov [.base], eax
    sub dword [.size], 0x1000
    sbb dword [.size + 4], 0

    .base_aligned:
    mov eax, [.size]
    and eax, ~0xfff
    mov [.size], eax

    mov eax, [.size]
    shr eax, 12
    push ebx
    mov ebx, [.size + 4]
    shl ebx, 20
    add eax, ebx
    pop ebx
    mov [.size], eax
    mov dword [.size + 4], 0

    ; Store the entry
    push ebx

    mov ebx, [.pointer]
    mov eax, [.base]
    mov [fs:bx], eax
    mov eax, [.base + 4]
    mov [fs:bx + 4], eax
    mov eax, [.size]
    mov [fs:bx + 8], eax
    add [.total_memory], eax
    mov eax, [.size + 4]
    adc [.total_memory + 4], eax
    mov [fs:bx + 12], eax
    add dword [.pointer], 16

    pop ebx

    .try_next:
    or ebx, ebx
    jnz .loop

    .finished:
    mov eax, [.pointer]
    shr eax, 4
    or eax, eax
    jz .fail

    ; Clear the base value for the entry after last
    mov ebx, [.pointer]
    mov dword [fs:bx], 0
    mov dword [fs:bx + 4], 0

    mov eax, [.total_memory]
    mov dword [fs:bx + 8], eax
    mov eax, [.total_memory + 4]
    mov dword [fs:bx + 12], eax

    jmp load_kernel

    .fail:
    mov si, error_memory_map
    jmp error

    .pointer: dd 0
    .entry: 
    .base:    dq 0
    .size:    dq 0
    .type:    dd 0
    .acpi:    dd 0
    .total_memory:    dq 0

load_kernel:
    mov di, 20 ; sector offset for the kernel
    mov si, 1
    mov bx, 0x8000
    call load_sectors

    xor ecx, ecx
    mov edx, [0x8020]
    .ph_loop:
    xor eax, eax
    mov ax, [0x8038]
    cmp ecx, eax
    jge .finished
    cmp dword [edx], 1
    jne .inc
    mov eax, [edx + 0x20]
    cmp eax, 0
    je .inc

    and eax, 0xfff
    mov ebx, [edx + 4] ; file offset of the segment

    .inc:
    jmp .ph_loop
    
    .finished:
    jmp success

; si - sector count
; di - LBA.
; es:bx - buffer
load_sectors:
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
	mov	ax,0x0215
	int	0x13
	mov	si,error_disk
	jc	error

	ret

check_a20:
    xor ax, ax
    mov es, ax
    mov ax, 0xffff
    mov fs, ax
    mov byte [es:0x600], 0
    mov byte [fs:0x610], 0xff
    cmp byte [es:0x600], 0xff
    je .enabled
    stc
    ret
    .enabled:
    clc
    ret

success:
    cli
    hlt

error:
    xor ax, ax
    mov es, ax
    mov gs, ax
    mov fs, ax
    mov ss, ax
    lodsb
    or al, al
    jz .break
    mov ah, 0xe
    int 0x10
    jmp error

    .break:
    cli
    hlt

read_structure:
    dw 0x10
    dw 1
    dd temporary_load_buffer
    .lba: dq 0

gdt_data:
    .null_entry:    dq 0
    .code_entry:    dd 0xFFFF   ; 0x08
            db 0
            dw 0xCF9A
            db 0
    .data_entry:    dd 0xFFFF   ; 0x10
            db 0
            dw 0xCF92
            db 0
    .code_entry_16: dd 0xFFFF   ; 0x18
            db 0
            dw 0x0F9A
            db 0
    .data_entry_16: dd 0xFFFF   ; 0x20
            db 0
            dw 0x0F92
            db 0
    .user_code: dd 0xFFFF   ; 0x2B
            db 0
            dw 0xCFFA
            db 0
    .user_data: dd 0xFFFF   ; 0x33
            db 0
            dw 0xCFF2
            db 0
    .tss:       dd 0x68     ; 0x38
            db 0
            dw 0xE9
            db 0
            dq 0
    .code_entry64:  dd 0xFFFF   ; 0x48
            db 0
            dw 0xAF9A
            db 0
    .data_entry64:  dd 0xFFFF   ; 0x50
            db 0
            dw 0xAF92
            db 0
    .user_code64:   dd 0xFFFF   ; 0x5B
            db 0
            dw 0xAFFA
            db 0
    .user_data64:   dd 0xFFFF   ; 0x63
            db 0
            dw 0xAFF2
            db 0
    .user_code64c:  dd 0xFFFF   ; 0x6B
            db 0
            dw 0xAFFA
            db 0
    .gdt:       dw (gdt_data.gdt - gdt_data - 1)
    .gdt2:      dq gdt_data

error_no_pci: db "Error: PCI not found",0
error_no_cpuid: db "Error: CPUID not found",0
error_no_msr: db "Error: MSR not found",0
error_a20: db "Error: Cannot enable A20",0
error_memory_map: db "Error: Cannot get memory map",0
error_disk: db "Error: Cannot read disk",0
error_elf: db "Error: ELF", 0
error_kernel_too_big: db "Error: kernel executable too big", 0

startup_message: db "Booting RNU...",10,13,0

max_sectors: dw 0
max_heads: dw 0
partition: dw 0
drive: db 0
is_emulator: db 0
