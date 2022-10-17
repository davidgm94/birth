%define original_bootsector_location 0x7c00
%define bootsector_location 0x600
%define stage1_location 0x800
%define stack_top 0xfff0
%define memory_map 0x60000
%define kernel_segment_size 32
%define kernel_file_sector_offset 20
%define sector_size 0x200
%define page_size 0x1000
%define kernel_segments 0x2000
%define memory_map 0x3000
%define temporary_buffer 0x4000
%define temporary_buffer_len (0xf000 - temporary_buffer)
