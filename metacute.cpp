#include <cstdio>
#include <iomanip>
#include <iostream>

#include <elf.h>
#include <getopt.h>
#include <string.h>
#include <sys/stat.h>

#include "metacute.h"


void print_usage(void)
{
    std::cout << "Usage: metacute <option> <file-path>" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "\t -e dump program elf-header" << std::endl;
    std::cout << "\t -S dump program sections" << std::endl;
    std::cout << "\t -p dump program segments" << std::endl;
    std::cout << "\t -s dump program symbols" << std::endl;
    std::cout << "\t -c <section> dump passed section" << std::endl;
}

Elf::Elf(std::vector<uint8_t> binary)
{
    if (check_magic_number(binary)) 
        ERROR("Invalid File!"); 

    if (binary[EI_CLASS] != 2)
        ERROR("Invalid File (64-bit files only)!");

    memcpy(&elf_hdr, binary.data(), sizeof(Elf64_Ehdr));

    elf_class = elf_hdr.e_ident[EI_CLASS];

    elf_endian = elf_hdr.e_ident[EI_DATA];

    switch (elf_endian) {
        case (ELFDATANONE):
            endian = "Invalid-Endian";
            break;
        case (ELFDATA2MSB):
            endian = "Big Endian, 2's complement";
            break;
        case (ELFDATA2LSB):
            endian = "Little Endian, 2's complement";
            break;
    }

    elf_osabi = elf_hdr.e_ident[EI_OSABI];

    switch (elf_hdr.e_type) {
        case (ET_NONE):
            type = "Unknown";
            break;
        case (ET_REL):
            type = "Relocatable";
            break;
        case (ET_EXEC):
            type = "Executable";
            break;
        case (ET_DYN):
            type = "Shared Object";
            break;
        case (ET_CORE):
            type = "Core";
            break;
    }

    switch (elf_hdr.e_machine) {
        case (EM_NONE):
            arch = "None";
            break;
        case (EM_M32):
            arch = "AT&T WE 32100";
            break;
        case (EM_SPARC):
            arch = "SUN SPARC";
            break;
        case (EM_386):
            arch = "Intel 80386";
            break;
        case (EM_68K):
            arch = "Motorola m68k";
            break;
        case (EM_PPC):
            arch = "PowerPC";
            break;
        case (EM_ARM):
            arch = "ARM";
            break;
        case (EM_X86_64):
            arch = "x86_64";
            break;
        case (EM_PDP10):
            arch = "PDP-10";
            break;
        case (EM_BPF):
            arch = "Linux BPF";
            break;
        default:
            arch = "Unknown";
    }
}

int Elf::check_magic_number(std::vector<uint8_t> binary)
{
    return memcmp(ELFMAG, binary.data(), SELFMAG);
}

Elf64_Ehdr Meta::get_elf(void)
{
    return elf.elf_hdr;
}

void Meta::print_elf(void)
{
    uint32_t addr = (uint32_t) elf.elf_hdr.e_entry;
    printf(ELF_PRINT_FORMAT, file.c_str(), elf.arch.c_str(), elf.type.c_str(),
                             elf.elf_hdr.e_ehsize, elf.endian.c_str(), 
                             addr, elf.elf_osabi, elf.elf_hdr.e_phnum, 
                             elf.elf_hdr.e_shnum, elf.elf_hdr.e_phoff, 
                             elf.elf_hdr.e_shoff);
}

void Meta::print_symbols(void)
{
    std::map<unsigned long, std::string> symbol_types = map_types(sym_names, 
                                                                &(sym_types[0]), 
                                                                      SY_TYPES);

    std::map<unsigned long, std::string> symbol_binds = map_types(sym_bind_names, 
                                                                &(sym_binds[0]), 
                                                                      SY_BINDS); 

    std::map<unsigned long, std::string> symbol_visi = map_types(sym_visi_names, 
                                                               &(sym_visi[0]), 
                                                                    SY_VISIS);

    Elf64_Shdr *symtab = sections[".symtab"];
    size_t sym_count = symtab->sh_size / SY_SIZE;

    Elf64_Sym *sym = (Elf64_Sym *) &(binary[symtab->sh_offset]);

    std::vector<Elf64_Sym *> symbols;

    while (sym_count--)
        symbols.push_back(sym++);

    Elf64_Shdr *strtab = sections[".strtab"];
    size_t str_offset = strtab->sh_offset;

    std::cout << SY_PRINT_FORMAT;
    std::cout << PRINT_TERM << std::endl;;

    for (auto sym : symbols) {

        size_t type = ELF64_ST_TYPE(sym->st_info);
        size_t bind = ELF64_ST_BIND(sym->st_info);
        size_t visi = ELF64_ST_VISIBILITY(sym->st_other);

        if (sym->st_value == 0)
            std::cout << "0x000000" << " ";
        else
            std::cout << std::showbase << std::hex << sym->st_value << " ";

        if (type != STT_SECTION)
            std::cout << symbol_types[type] << "\t\t";
        else
            std::cout << symbol_types[type] << "\t";

        std::cout << symbol_binds[bind] << "\t";
        std::cout << "  " << symbol_visi[visi] << "  ";

        switch (type) {
            case (STT_OBJECT):
            case (STT_FILE):
            case (STT_FUNC): {
                size_t name_offset = sym->st_name;
                std::cout << (char *) &(binary[name_offset + str_offset]);
                break;
            }
            default:
                break;
        }

        std::cout << std::endl;
    }
}

void Meta::print_dynamics(void)
{
    std::map<unsigned long, std::string> dynamic_tags = map_types(dt_names, 
                                                                &(dt_tags[0]), 
                                                                    DT_TYPES);
    Elf64_Shdr *dynsec = sections[".dynamic"];
    size_t dynamic_offset = dynsec->sh_offset;
    size_t dynamic_count = dynsec->sh_size / DH_SIZE;

    Elf64_Dyn *dynamic = (Elf64_Dyn *) &(binary[dynamic_offset]);

    std::vector<Elf64_Dyn *> dynamics;

    while (dynamic_count-- && dynamic->d_tag != DT_NULL)
        dynamics.push_back(dynamic++);

    int dynstr = sections[".dynstr"]->sh_offset;

    printf(DT_PRINT_FORMAT);
    printf(PRINT_TERM);
    std::cout << std::endl;

    std::map<unsigned long, std::string> flags = map_types(df_flag_names, 
                                                          &(df_flags[0]), 
                                                               DF_FLAGS);

    std::map<unsigned long, std::string> flags_1 = map_types(df_flags_1_names,
                                                             &(df_flags_1[0]),
                                                                  DF_FLAGS_1);

    std::map<unsigned long, std::string> flags_pos = map_types(
                                                     df_posflag_1_names,
                                                     &(df_posflag_1[0]),
                                                        DF_FLAGS_POS_1);

    for (auto dyn : dynamics) {

        std::cout << '\t' << dynamic_tags[dyn->d_tag];
        add_white_space(dynamic_tags[dyn->d_tag].size());

        switch (dyn->d_tag) {

            case DT_NEEDED:
            case DT_SONAME:
            case DT_RPATH:
            case DT_RUNPATH:
            case DT_AUXILIARY:
            case DT_FILTER:
            case DT_CONFIG:
            case DT_DEPAUDIT:
            case DT_AUDIT: {
                std::cout << (char *) &binary[dyn->d_un.d_val + dynstr];
                std::cout << std::endl;
                break;
            }

            case DT_PLTGOT:
            case DT_HASH:
            case DT_STRTAB:
            case DT_SYMTAB:
            case DT_RELA:
            case DT_INIT:
            case DT_FINI:
            case DT_REL:
            case DT_JMPREL:
            case DT_INIT_ARRAY:
            case DT_FINI_ARRAY:
            case DT_PREINIT_ARRAY:
            case DT_SYMINFO:
            case DT_VERDEF:
            case DT_VERSYM:
            case DT_VERNEED:
            case DT_MOVETAB: {
                std::cout << std::showbase << std::hex;
                std::cout << dyn->d_un.d_ptr << std::endl;
                break;
            }

            case DT_PLTRELSZ:
            case DT_RELASZ:
            case DT_RELAENT:
            case DT_STRSZ:
            case DT_SYMENT:
            case DT_RELSZ:
            case DT_RELENT:
            case DT_INIT_ARRAYSZ:
            case DT_FINI_ARRAYSZ:
            case DT_PREINIT_ARRAYSZ:
            case DT_SYMINENT:
            case DT_SYMINSZ:
            case DT_MOVEENT:
            case DT_MOVESZ: {
                std::cout << "(" << std::dec << dyn->d_un.d_val;
                std::cout << ") bytes" << std::endl;
                break;
            }

            case DT_SYMBOLIC:
            case DT_DEBUG:
            case DT_GNU_HASH: {
                std::cout << "0x0" << std::endl;
                break;
            }

            case DT_PLTREL: {
                const char *r_type = dyn->d_un.d_val == DT_REL ? "REL" : "RELA";
                std::cout << r_type << std::endl;
                break;
            }
                
            case DT_TEXTREL: {
                std::cout << std::endl;
                break; 
            }

            case DT_POSFLAG_1: {
                std::cout << flags_pos[dyn->d_un.d_val] << std::endl; 
                break;
            }

            case DT_BIND_NOW:
                break;
                
            case DT_VERDEFNUM:
            case DT_VERNEEDNUM:
            case DT_RELACOUNT:
            case DT_RELCOUNT: {
                std::cout << dyn->d_un.d_val << std::endl;
                break;
            }

            case DT_FLAGS_1: {
                std::cout << flags_1[dyn->d_un.d_val] << std::endl;
                break;
            }
        }
    }

    printf(PRINT_TERM);
    std::cout << std::endl;
}

void Meta::print_segments(void)
{
    std::map<unsigned long, std::string> segment_types = map_types(ph_names, 
                                                                 &(ph_types[0]),
                                                                      PH_TYPES);

    int phnum = elf.elf_hdr.e_phnum;

    Elf64_Phdr *segment_array = (Elf64_Phdr *) &binary[elf.elf_hdr.e_phoff];

    std::vector<Elf64_Phdr *> segments;

    while (phnum--)
        segments.push_back(segment_array++);

    for (auto segment : segments) {
        std::string name = segment_types[segment->p_type];
        printf(PH_PRINT_FORMAT, name.c_str(), segment->p_offset, 
                                 segment->p_filesz, segment->p_paddr, 
                                 segment->p_vaddr, segment->p_memsz, 
                                 segment->p_align);

        std::vector<std::string> flags = get_hdr_flags(ph_flag_names, 
                                        (unsigned long *) &(ph_flags[0]),
                                                        segment->p_flags, 
                                                        PH_FLAGS);

        for (auto flag : flags)
            std::cout << "[" << flag << "] ";

        printf(PRINT_TERM);
        std::cout << std::endl;
    } 
}

void Meta::print_section_hdr(Elf64_Shdr *section, std::string section_name)
{
    Elf64_Word type = section->sh_type;
    std::string link = section_links[section_name];
    std::string info = section_infos[section_name];

    printf(SH_PRINT_FORMAT, section_name.c_str(), section->sh_size, 
                             section->sh_offset, section_types[type].c_str(), 
                             link.c_str(), info.c_str());

    std::vector<std::string> flags = get_hdr_flags(sh_flag_names, sh_flags,
                                                   section->sh_flags, SH_FLAGS);
    for (auto flag : flags)
        std::cout << "[" << flag << "] ";

    printf(PRINT_TERM);
    print_section_data(section);
}

std::string Meta::get_section_str(size_t sh_idx, size_t str_tbl_offset)
{
    int sh_offset = elf.elf_hdr.e_shoff + (sh_idx * SH_SIZE);
    int str_offset = ((Elf64_Shdr *) &binary[sh_offset])->sh_name;
    return std::string((char *) &binary[str_offset + str_tbl_offset]);
}

void Meta::load_sections(void)
{
    int num_secs = elf.elf_hdr.e_shnum - 1;
    size_t str_sec_offset = elf.elf_hdr.e_shoff + 
                           (elf.elf_hdr.e_shstrndx * SH_SIZE);
    size_t str_tbl_offset = ((Elf64_Shdr *) &binary[str_sec_offset])->sh_offset;

    section_types = map_types(sh_names, sh_types, SH_TYPES);

    // Section-Header Table is 1-based table (not 0)
    // The first entry in the table is 0'd out
    for (Elf64_Shdr *shdr=(Elf64_Shdr *) &binary[elf.elf_hdr.e_shoff + SH_SIZE];
            num_secs; shdr++, num_secs--) {
        std::string name((char *) &binary[str_tbl_offset + shdr->sh_name]);

        section_links[name] = shdr->sh_link ? get_section_str(shdr->sh_link,
                                                              str_tbl_offset) :
                                                                        "None";

        section_infos[name] = shdr->sh_info && (shdr->sh_type == SHT_REL ||
                                                shdr->sh_type == SHT_RELA) ?
                              get_section_str(shdr->sh_info, str_tbl_offset) :
                                                                       "None";
        sections[name] = shdr;
    }
}

void Meta::display_section_chars(int idx, size_t sec_offset)
{
    std::cout << ' ';

    if (!(idx & ALIGN_OUTPUT)) {
        for (int j=idx-16; j < idx; j++) {
            if (binary[sec_offset + j] > 32 && binary[sec_offset + j] < 127)
                std::cout << (char) binary[sec_offset + j];
            else
                std::cout << '.';
        }
    } else {
        int trail_offset = idx & ALIGN_OUTPUT;
        int width = ALIGN_SECTION_WIDTH - (trail_offset * 2 + 
                                          (trail_offset - 1) / 4);
        std::cout << std::setw(width);        
        for (int j=idx-trail_offset; j < idx; j++) {
            if (binary[sec_offset + j] > 32 &&
                binary[sec_offset + j] < 127)
                std::cout << (char) binary[sec_offset + j];
            else
                std::cout << '.';
        }
    }
}

void Meta::print_section(const char *section)
{
    if (!section)
        ERROR("Provide section!");

    Elf64_Shdr *s = sections[section];
    
    if (!s)
        ERROR("Section not found!");

    print_section_hdr(s, section);
    std::cout << std::endl;
}

void Meta::print_sections(void)
{
    std::cout << std::endl << "File: " << file << std::endl << std::endl;

    Elf64_Shdr *bss_sec = sections[".bss"];
    sections.erase(".bss");
    print_section_hdr(bss_sec, ".bss");
    std::cout << std::endl;

    for (auto item : sections) {
        print_section_hdr(item.second, item.first);

        std::cout << std::endl << std::endl;
        std::cout << std::setw(0);
    }
}

void Meta::print_section_data(Elf64_Shdr *section)
{
    size_t sec_offset = section->sh_offset;
    int section_size = (int) section->sh_size;

    for (int idx=0; idx <= section_size; idx++) {
        if (!(idx & ALIGN_OUTPUT) || idx == section_size) {
            if (idx)
                display_section_chars(idx, sec_offset);
            if (idx != section_size) {
                if (section->sh_addr == 0)
                    std::cout << std::endl << "xxxxxx ";
                else {
                    std::cout << std::endl << std::setbase(16);
                    std::cout << section->sh_addr + idx;
                    std::cout << ' ';
                }
            }
        } else if (idx && !(idx % 4))
            std::cout << ' ';

        if (idx < section_size) {
            if (binary[sec_offset + idx] < 16) { 
                std::cout << '0' << std::setbase(16);
                std::cout << (int) binary[sec_offset + idx];
            } else {
                std::cout << std::setbase(16);
                std::cout << (int) binary[sec_offset + idx];
            }
        }
    }
}

std::map<unsigned long, std::string>
Meta::map_types(const char **type_names, unsigned long *type_values, 
                                                      long type_num)
{
    std::map<unsigned long, std::string> hdr_type_map;

    for (int i=0; i < type_num; i++) {
        long value = type_values[i];
        std::string name = type_names[i];
        hdr_type_map[value] = name;
    }

    return hdr_type_map;
}

std::vector<std::string>
Meta::get_hdr_flags(const char **flag_names, unsigned long *flag_values,
                    long hdr_flags, int flag_num)
{
    std::vector<std::string> flags;

    for (int flag=0; flag < flag_num; flag++) {
        if (flag_values[flag] & hdr_flags)
            flags.push_back(flag_names[flag]);
    } 

    if (flags.empty())
        flags.push_back("None");

    return flags;
}

void Meta::add_white_space(size_t length)
{
    for (int ws=ALIGN_DYNAMIC-length; ws; ws--)
        std::cout << ' ';
    std::cout << "\t\t\t";
}

Meta::Meta(const char *file, size_t file_size)
{
    this->file = file;
    file_handle.open(file, std::ios::binary | std::ios::in);

    if (!file_handle.is_open())
        ERROR(strerror(errno));

    binary.resize(file_size);
    file_handle.read((char *) &binary[0], file_size);
    file_handle.close();

    elf = Elf(binary);
    load_sections();
}

int main(int argc, char *argv[])
{
    const char *options = "deSpsc:";
    char opt = getopt(argc, argv, options);
    
    const char *file = argv[argc - 1];
    
    struct stat st;
    if (stat(file, &st) < 0)
        ERROR(strerror(errno));

    Meta metacute(file, st.st_size);

    switch (opt) {

        case ('d'):
            metacute.print_dynamics();
            break;
        case ('e'):
            metacute.print_elf();
            break;
        case ('S'):
            metacute.print_sections();
            break;
        case ('p'):
            metacute.print_segments();
            break;
        case ('s'):
            metacute.print_symbols();
            break;
        case ('c'):
            metacute.print_section(optarg);
            break;
        default:
            ERROR("Invalid options!");
    }

    return 0;
}

