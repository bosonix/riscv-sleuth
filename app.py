import streamlit as st
from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV64
import matplotlib.pyplot as plt
import io
import struct

def extract_elf_sections(data):
    """Extract code sections from ELF files for disassembly."""
    if len(data) < 64:
        st.error("File too small")
        return None
        
    if data[0:4] != b'\x7fELF':
        st.warning("Not an ELF file / no ELF signature")
        return data
    
    file_class = data[4]
    endianness = data[5]
    
    byte_order = '<' if endianness == 1 else '>'
    
    format_spec = f"{byte_order}{'Q' if file_class == 2 else 'I'}"
    section_table_offset = struct.unpack_from(format_spec, data, 40 if file_class == 2 else 32)[0]
    
    if section_table_offset == 0 or section_table_offset >= len(data):
        st.warning("Header table offset")
        return data
    
    section_entry_size = struct.unpack_from(f"{byte_order}H", data, 58 if file_class == 2 else 46)[0]
    section_count = struct.unpack_from(f"{byte_order}H", data, 60 if file_class == 2 else 48)[0]
    
    string_table_idx = struct.unpack_from(f"{byte_order}H", data, 62 if file_class == 2 else 50)[0]
    
    if section_count == 0 or section_entry_size == 0:
        st.warning("No sections found in the ELF file")
        return data
    
    section_ptr = section_table_offset
    executable_code = None
    
    string_table_header = section_table_offset + string_table_idx * section_entry_size
    
    offset_field_pos = 24 if file_class == 2 else 16
    size_field_pos = 32 if file_class == 2 else 20
    
    strings_offset = struct.unpack_from(f"{byte_order}{'Q' if file_class == 2 else 'I'}", 
                                       data, string_table_header + offset_field_pos)[0]
    strings_size = struct.unpack_from(f"{byte_order}{'Q' if file_class == 2 else 'I'}", 
                                     data, string_table_header + size_field_pos)[0]
    
    for idx in range(section_count):
        current_section = section_table_offset + idx * section_entry_size
        
        name_offset = struct.unpack_from(f"{byte_order}I", data, current_section)[0]
        
        name_position = strings_offset + name_offset
        
        section_name = ""
        pos = 0
        while name_position + pos < len(data) and data[name_position + pos] != 0:
            section_name += chr(data[name_position + pos])
            pos += 1
            
        if section_name == ".text":
            offset_field_pos = 24 if file_class == 2 else 16
            size_field_pos = 32 if file_class == 2 else 20
            
            code_offset = struct.unpack_from(f"{byte_order}{'Q' if file_class == 2 else 'I'}", 
                                           data, current_section + offset_field_pos)[0]
            code_size = struct.unpack_from(f"{byte_order}{'Q' if file_class == 2 else 'I'}", 
                                         data, current_section + size_field_pos)[0]
            
            if code_offset + code_size <= len(data):
                executable_code = data[code_offset:code_offset + code_size]
                st.success(f"Found .text section: {code_size} bytes")
                break
    
    if executable_code:
        return executable_code
    else:
        st.warning("No text section, trying to disas file")
        return data

def decode_binary(binary_data):
    code_data = extract_elf_sections(binary_data)
    
    decoder = Cs(CS_ARCH_RISCV, CS_MODE_RISCV64)
    decoded_instructions = []
    
    try:
        for instr in decoder.disasm(code_data, 0x1000):
            decoded_instructions.append(instr)
    except Exception as e:
        st.error(f"Disassembly error: {str(e)}")
    
    return decoded_instructions

def count_instruction_types(instr_list):
    instr_counts = {}
    
    for instr in instr_list:
        op = instr.mnemonic
        if op not in instr_counts:
            instr_counts[op] = 1
        else:
            instr_counts[op] += 1
    
    return instr_counts

def create_frequency_chart(instr_counts):
    if not instr_counts:
        st.warning("No instructions were disassembled successfully.")
        return
        
    op_names = list(instr_counts.keys())
    freq_values = list(instr_counts.values())
    
    plt.figure(figsize=(10, 6))
    plt.bar(op_names, freq_values, color='skyblue')
    plt.title("Opcode Frequency in RISC-V Binary")
    plt.xlabel("Opcodes")
    plt.ylabel("Frequency")
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    st.pyplot(plt)

def show_disassembly(instr_list):
    if not instr_list:
        st.warning("No instructions to display.")
        return
        
    disassembly_rows = []
    for i, instr in enumerate(instr_list):
        disassembly_rows.append({
            "Address": f"0x{instr.address:x}",
            "Bytes": "".join(f"{b:02x}" for b in instr.bytes),
            "Mnemonic": instr.mnemonic,
            "Operands": instr.op_str
        })
    
    st.dataframe(disassembly_rows)

def main():
    st.title("RISC-V Binary Disassembler")
    st.write("Upload a RISC-V binary file to see its opcode frequency.")
    
    uploaded_file = st.file_uploader("Choose a RISC-V Binary", type=["bin", "elf"])
    
    use_sample_file = st.checkbox("Use provided ELF file")
    
    file_content = None
    
    if uploaded_file is not None:
        file_content = uploaded_file.read()
        st.success(f"Uploaded file: {uploaded_file.name}, size: {len(file_content)} bytes")
    elif use_sample_file:
        st.info("Using the provided ELF file")
        file_content = b'ELF\xf3\xe8@\xf0@8@px\x0cLttttt\xc5\xef\xc0"\xd0s"@"c"o@"\x82\xf2\xff#"\x83\x33o\xf0\xdf\xee""\x73" cTo\x80\xb3\x9e\x8b"\x8b\xff\xff\x85""\x73o\xf0\x9f\xed"\xd0\x73AK\x72iscv\x41rv64i2p1_m2p0_a2p1_f2p2_d2p2_zicsr2p0_zifencei2p0_zmmul1p0\xe8t\xf1\xff\xe8Dt\x4eS\x59d$n@t\x48l\x89\xf1\xfft\x9bx\xf8\xe8\xabx\xb7x\xc3t\xd2xi\x78new.o$\x78rv64i2p1_m2p0_a2p1_f2p2_d2p2_zicsr2p0_zifencei2p0_zmmul1p0stack_top\x6dain\x6coop1\x6coop1_body\x6coop1_end\x6coop2\x6coop2_body\x6coop2_end__global_pointer$__SDATA_BEGIN____BSS_END____bss_start__DATA_BEGIN___edata.symtab.strtab.shstrtab.text.data.riscv.attributes\xe8\xe8\x8a!\x74t\'px\x0cL\xc8\t\xd8\xd9\xb1\x39'
    
    if file_content:
        instructions = decode_binary(file_content)
        
        if instructions:
            st.subheader(f"Disassembled Instructions ({len(instructions)} found)")
            show_disassembly(instructions)
            
            instruction_freq = count_instruction_types(instructions)
            
            st.subheader("Opcode Frequency")
            
            freq_table = {"Opcode": list(instruction_freq.keys()), 
                         "Frequency": list(instruction_freq.values())}
            st.dataframe(freq_table)
            
            st.subheader("Opcode Frequency Visualization")
            create_frequency_chart(instruction_freq)
        else:
            st.warning("""
            No instructions could be disassembled. This could be due to:
            1. The file is not a valid RISC-V binary
            2. The ELF file structure couldn't be properly parsed
            3. The .text section (containing code) couldn't be found
            
            Try uploading a different RISC-V binary file.
            """)

if __name__ == '__main__':
    main()