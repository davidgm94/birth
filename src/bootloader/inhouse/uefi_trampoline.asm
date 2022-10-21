[bits 64]
[section .text]

%define code_segment 0x28
%define data_segment 0x30


start:
    mov cr3, rdx
    lgdt [r8]
    mov rsp, rcx 
    mov rax, data_segment
    mov ds, rax
    mov es, rax
    mov fs, rax
    mov gs, rax
    mov ss, rax
    call set_cs
    jmp rsi

set_cs:
	pop	rax
	push	code_segment
	push	rax
	retfq
