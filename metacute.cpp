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
    std::cout << "\t -e dump elf-header" << std::endl;
    std::cout << "\t -s dump sections" << std::endl;
    std::cout << "\t -p dump program segments" << std::endl;
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

Section::Section(Elf64_Shdr *section)
{
    memcpy(&sec_hdr, section, SEC_SIZE);
    load_section_types();
}

void Section::load_section_types(void)
{
    for (int i=0; i < NUM_SEC_VALS; i++) {
        unsigned int value = section_values[i];
        std::string name = section_value_names[i];
        section_types[value] = name;
    }
}

void Section::print_section_hdr(std::string name)
{
    Elf64_Word type = sec_hdr.sh_type;

    printf(SEC_PRINT_FORMAT, name.c_str(), sec_hdr.sh_size, sec_hdr.sh_offset,
                             section_types[type].c_str(),
                             link.c_str(), info.c_str(), sec_hdr.sh_flags);
}

Segment::Segment(Elf64_Phdr *seg_hdr)
{
    this->seg_hdr = seg_hdr;
    load_segment_types();
}

void Segment::load_segment_types(void)
{
    for (int i=0; i < NUM_SEG_VALS; i++) {
        unsigned int value = segment_type_values[i];
        std::string name = segment_type_names[i];
        segment_types[value] = name;
    }
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

std::string Meta::get_section_str(size_t sh_idx, size_t str_tbl_offset)
{
    int sh_offset = elf.elf_hdr.e_shoff + (sh_idx * SEC_SIZE);
    int str_offset = ((Elf64_Shdr *) &binary[sh_offset])->sh_name;
    return std::string((char *) &binary[str_offset + str_tbl_offset]);
}

void Meta::print_segments(void)
{
    int phnum = elf.elf_hdr.e_phnum;
    size_t phsize = elf.elf_hdr.e_phentsize;
    size_t offset = elf.elf_hdr.e_phoff;

    segments.resize(phnum * phsize);

    for (int i=0; i < phnum; i++) {
        size_t current_offset = phsize * i;
        Elf64_Phdr *segment = (Elf64_Phdr *) &binary[current_offset + offset];
        segments[i] = new Segment(segment);
        int seg_type = segment->p_type;
        std::string name = segments[i]->segment_types[seg_type];
        printf(SEG_PRINT_FORMAT, name.c_str(), segment->p_offset, 
                                 segment->p_vaddr, segment->p_paddr, 
                                 segment->p_filesz, segment->p_memsz, 
                                 segment->p_flags, segment->p_align);
    } 
}

void Meta::load_sections(void)
{
    int num_secs = elf.elf_hdr.e_shnum;

    size_t str_sec_offset = elf.elf_hdr.e_shoff + 
                           (elf.elf_hdr.e_shstrndx * SEC_SIZE);
    size_t str_tbl_offset = ((Elf64_Shdr *) &binary[str_sec_offset])->sh_offset;

    size_t curr_offset = elf.elf_hdr.e_shoff;

    // Section-Header Table is 1-based table (not 0)
    // The first entry in the table is 0'd out
    for (int curr_sec_idx=1; curr_sec_idx < num_secs; curr_sec_idx++) {

        curr_offset += SEC_SIZE;
        Elf64_Shdr *section = (Elf64_Shdr *) &binary[curr_offset];

        Section *curr_sec = new Section(section);

        curr_sec->link = section->sh_link ? get_section_str(section->sh_link, 
                                                            str_tbl_offset) : 
                                                                      "None";

        curr_sec->info = section->sh_info && (section->sh_type == SHT_REL || 
                                              section->sh_type == SHT_RELA) 
                                          ? get_section_str(section->sh_info, 
                                                            str_tbl_offset) :
                                                                      "None";

        std::string name((char *) &binary[str_tbl_offset + section->sh_name]);
        sections[name] = curr_sec;
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

void Meta::print_sections(void)
{
    std::cout << std::endl << "File: " << file << std::endl << std::endl;
    load_sections();

    for (const auto& item : sections) {
        item.second->print_section_hdr(item.first);

        if (!(item.first.compare(".bss"))) {
            std::cout << std::endl;
            continue;
        }

        size_t sec_offset = item.second->sec_hdr.sh_offset;
        int section_size = (int) item.second->sec_hdr.sh_size;

        for (int idx=0; idx <= section_size; idx++) {
            if (!(idx & ALIGN_OUTPUT) || idx == section_size) {
                if (idx)
                    display_section_chars(idx, sec_offset);
                if (idx != section_size) {
                    if (item.second->sec_hdr.sh_addr == 0)
                        std::cout << std::endl << "xxxxxx ";
                    else {
                        std::cout << std::endl << std::setbase(16);
                        std::cout << item.second->sec_hdr.sh_addr + idx;
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

        std::cout << std::endl << std::endl;
        std::cout << std::setw(0);
    }
}

Elf64_Ehdr Meta::get_elf(void)
{
    return elf.elf_hdr;
}

int main(int argc, char *argv[])
{
    if (argc ^ 3)
        ERROR("Invalid options!");

    const char *options = "esp";
    char opt = getopt(argc, argv, options);
    
    const char *file = argv[2];
    
    struct stat st;
    if (stat(file, &st) < 0)
        ERROR(strerror(errno));

    Meta metacute(file, st.st_size);

    switch (opt) {

        case ('e'):
            metacute.print_elf();
            break;
        case ('s'):
            metacute.print_sections();
            break;
        case ('p'):
            metacute.print_segments();
            break;
        default:
            ERROR("Invalid options!");
    }

    return 0;
}

