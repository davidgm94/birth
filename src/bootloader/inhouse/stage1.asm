%include "src/bootloader/inhouse/common.asm"

[bits 16]
[org stage1_location]

start:
    cli
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    mov esp, stack_top
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
    mov ax, 0x2403
    int 0x15
    mov si, error_a20
    jb error
    cmp ah, 0
    jnz error
    mov ax, 0x2402
    int 0x15
    jb error
    cmp ah, 0
    jnz error

    cmp al, 1
    jz .activated

    mov ax, 0x2401
    int 0x15
    jb error
    cmp ah, 0
    jnz error
    .activated:
    sti

load_gdt:
    lgdt [gdt_data.gdt]

inform_bios_mixed_mode:
    mov eax, 0xec00
    mov ebx, 3
    int 0x15

;load_memory_map:
   ;; Load the memory map
   ;xor   ebx,ebx

   ;; Set FS to access the memory map
   ;xor ax, ax
   ;mov   es,ax
   ;mov   ax, memory_map / 16
   ;mov   fs,ax

   ;; Loop through each memory map entry
   ;.loop:
   ;mov   di,.entry
   ;mov   edx,0x534D4150
   ;mov   ecx,24
   ;mov   eax,0xE820
   ;mov   byte [.acpi],1
   ;int   0x15
   ;jc   .finished

   ;; Check the BIOS call worked
   ;cmp   eax,0x534D4150
   ;jne   .fail

;;   pusha   
;;   mov   di,.entry
;;   call   .print_bytes
;;   popa

   ;; Check if this is usable memory
   ;cmp   dword [.type],1
   ;jne   .try_next
   ;cmp   dword [.size],0
   ;je   .try_next
   ;cmp   dword [.acpi],0
   ;je   .try_next

   ;; Check that the region is big enough
   ;mov   eax,[.size]
   ;and   eax,~0x3FFF
   ;or   eax,eax
   ;jz   .try_next

   ;; Check that the base is above 1MB
   ;cmp   dword [.base + 4],0
   ;jne   .base_good
   ;cmp   dword [.base],0x100000
   ;jl   .try_next
   ;.base_good:

   ;; Align the base to the nearest page
   ;mov   eax,[.base]
   ;and   eax,0xFFF
   ;or   eax,eax
   ;jz   .base_aligned
   ;mov   eax,[.base]
   ;and   eax,~0xFFF
   ;add   eax,0x1000
   ;mov   [.base],eax
   ;sub   dword [.size],0x1000
   ;sbb   dword [.size + 4],0
   ;.base_aligned:

   ;; Align the size to the nearest page
   ;mov   eax,[.size]
   ;and   eax,~0xFFF
   ;mov   [.size],eax

   ;; Convert the size from bytes to 4KB pages
   ;mov   eax,[.size]
   ;shr   eax,12
   ;push   ebx
   ;mov   ebx,[.size + 4]
   ;shl   ebx,20
   ;add   eax,ebx
   ;pop   ebx
   ;mov   [.size],eax
   ;mov   dword [.size + 4],0

   ;; Store the entry
   ;push   ebx
   ;mov   ebx,[.pointer]
   ;mov   eax,[.base]
   ;mov   [fs:bx],eax
   ;mov   eax,[.base + 4]
   ;mov   [fs:bx + 4],eax
   ;mov   eax,[.size]
   ;mov   [fs:bx + 8],eax
   ;add   [.total_memory],eax
   ;mov   eax,[.size + 4]
   ;adc   [.total_memory + 4],eax
   ;mov   [fs:bx + 12],eax
   ;add   dword [.pointer],16
   ;pop   ebx

   ;; Continue to the next entry
   ;.try_next:
   ;or   ebx,ebx
   ;jnz   .loop

   ;; Make sure that there were enough entries
   ;.finished:
   ;mov   eax,[.pointer]
   ;shr   eax,4
   ;or   eax,eax
   ;jz   .fail

   ;; Clear the base value for the entry after last
   ;mov   ebx,[.pointer]
   ;mov   dword [fs:bx],0
   ;mov   dword [fs:bx + 4],0

   ;; Store the total memory
   ;mov   eax,[.total_memory]
   ;mov   dword [fs:bx + 8],eax
   ;mov   eax,[.total_memory + 4]
   ;mov   dword [fs:bx + 12],eax

   ;; Load the kernel!
   ;jmp   load_kernel

   ;; Display an error message if we could not load the memory map
   ;.fail:
   ;mov   si,error_memory_map
   ;jmp   error

   ;.pointer:   dd 0
   ;.entry: 
      ;.base:   dq 0
      ;.size:   dq 0
      ;.type:   dd 0
      ;.acpi:   dd 0
   ;.total_memory:   dq 0

load_kernel:
    push ds
    push es
    push ss
    cli
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp 0x8:.protected_mode 

    [bits 32]
    .protected_mode:
	mov	ax,0x10
	mov	ds,ax
	mov	es,ax
	mov	ss,ax
    jmp $

    ;mov edi, end
    ;call align_u32_to_sector_size
    ;mov word [kernel_elf_prologue_buffer], di
    
    ;mov bx, di ; sector-aligned temporary buffer after this file
    ;mov di, kernel_file_sector_offset ; sector offset for the kernel
    ;mov si, 1
    ;call load_sectors

    ;xor ecx, ecx
    ;mov eax, [kernel_elf_prologue_buffer]
    ;mov edx, [eax + 0x20]
    ;add edx, eax
    ;.ph_loop:
    ;xor ebx, ebx
    ;mov bx, [eax + 0x38]
    ;cmp ecx, ebx
    ;jge .finished
    ;cmp dword [edx], 1 ; check if the segment is PT_LOAD
    ;jne .inc
    ;mov si, error_kernel_too_big
    ;mov eax, [edx + 0x12]
    ;cmp eax, 0
    ;je error
    ;mov eax, [edx + 0x24]
    ;cmp eax, 0
    ;je error
    ;mov eax, [edx + 0x20]
    ;cmp eax, 0 ; check if filesize is 0
    ;je .inc

    ;xor ebx, ebx
    ;mov bx, [kernel_segment_count]
    ;inc word [kernel_segment_count]
    ;shl ebx, 5 ; multiply by 32, assert that kernel_segment_size == 32
    ;mov eax, [edx + 0x10] ; copy p_vaddr to the kernel segment element
    ;mov [kernel_segments], eax
    ;mov eax, [edx + 0x14]
    ;mov [kernel_segments + 4], eax
    ;mov edi, [edx + 0x20] ; kernel file size
    ;mov esi, 0x1000
    ;call align_u32
    ;mov [kernel_segments + 8], eax
    ;shr eax, 9 ; segment sectors
    ;and eax, 0xffff0000
    ;cmp eax, 0
    ;mov si, error_kernel_too_big
    ;jne error
    ;push eax

    ;mov edi, [edx + 0x08]
    ;shr edi, 9
    ;add edi, kernel_file_sector_offset ; sector offset of the segment

    ;push esi
    ;mov bx, kernel_segments
    ;call load_sectors


    

    ;and eax, 0xfff
    ;mov ebx, [edx + 4] ; file offset of the segment

    ;.inc:
    ;jmp .ph_loop
    
    ;.finished:
    ;jmp success

; edi: value to align
; esi: alignment
; eax: result
align_u32_to_sector_size:
    lea eax, [edi + 0x1ff]
    and eax, 0xfffffe00
    ret
align_u32_to_page_size:
    lea eax, [edi + 0xfff]
    and eax, 0xfffff000
    ret
    
; si: sector count
; di: LBA
load_many_sectors:
    .loop:
    cmp si, 6
    jl .do_less_than_6
    push si
    push di
    mov si, 6
    call load_sectors
    pop di
    pop si
    sub si, 6
    add di, 6
    jmp .loop
    .do_less_than_6:
    call load_sectors
    ret
    

; si - sector count
; di - LBA.
load_sectors:
    .loop:
    ; Calculate cylinder and head.
    mov   ax,di
    xor   dx,dx
    div   word [max_sectors]
    xor   dx,dx
    div   word [max_heads]
    push   dx ; remainder - head
    mov   ch,al ; quotient - cylinder
    shl   ah,6
    mov   cl,ah

    ; Calculate sector.
    mov   ax,di
    xor   dx,dx
    div   word [max_sectors]
    inc   dx
    or   cl,dl

    ; Load the sector.
    pop   dx
    mov   dh,dl
    mov   dl,[drive]
    mov   ax, si
    mov ah, 0x02
    mov bx, temporary_buffer
    int   0x13
    mov   si,error_disk
    jc   error

    ret


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

kernel_elf_prologue_buffer: dw 0
kernel_segment_count: dw 0
max_sectors: dw 0
max_heads: dw 0
partition: dw 0
drive: db 0
is_emulator: db 0

success:
    cli
    hlt
end:
