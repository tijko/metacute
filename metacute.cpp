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
    memcpy(&sec_hdr, section, sizeof(Elf64_Shdr));
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
                             section_types[type].c_str(), type,
                             sec_hdr.sh_flags, sec_hdr.sh_link, 
                             sec_hdr.sh_info);
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

void Meta::load_sections(void)
{
    size_t offset = elf.elf_hdr.e_shoff + sizeof(Elf64_Ehdr);
    int num_secs = elf.elf_hdr.e_shnum;

    size_t str_sec_offset = elf.elf_hdr.e_shoff + (elf.elf_hdr.e_shstrndx * 
                                                        sizeof(Elf64_Shdr));

    Elf64_Shdr *str_sec = (Elf64_Shdr *) &binary[str_sec_offset];

    size_t str_offset = str_sec->sh_offset;

    for (int curr_sec_idx=0; curr_sec_idx < num_secs - 1; curr_sec_idx++) {

        size_t curr_offset = offset + (curr_sec_idx * sizeof(Elf64_Shdr));
        Elf64_Shdr *section = (Elf64_Shdr *) &binary[curr_offset];

        Section *curr_sec = new Section(section);
        std::string name((char *) &binary[str_offset + 
                                          curr_sec->sec_hdr.sh_name]);
        sections[name] = curr_sec;
    }
}

void Meta::display_section_chars(int idx, size_t sec_offset, int count)
{
    std::cout << ' ';

    if (count % 16 == 0) {
        for (int j=idx-16; j < idx; j++) {
            if (binary[sec_offset + j] > 32 && binary[sec_offset + j] < 127)
                std::cout << (char) binary[sec_offset + j];
            else
                std::cout << '.';
        }
    } else {
        int trail_offset = count % 16;
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
        size_t sec_offset = item.second->sec_hdr.sh_offset;
        int count = 0;

        for (int i=0; i <= (int) item.second->sec_hdr.sh_size; i++) {

            if (count % 16 == 0 || i == (int) item.second->sec_hdr.sh_size) {
                if (count)
                    display_section_chars(i, sec_offset, count);
                if (i != (int) item.second->sec_hdr.sh_size) {
                    if (item.second->sec_hdr.sh_addr == 0)
                        std::cout << std::endl << "xxxxxx ";
                    else {
                        std::cout << std::endl << std::setbase(16);
                        std::cout << item.second->sec_hdr.sh_addr + count;
                        std::cout << ' ';
                    }
                }
            } else if (count > 0 && count % 4 == 0)
                std::cout << ' ';

            if (i < (int) item.second->sec_hdr.sh_size) {
                if (binary[sec_offset + i] < 16) { 
                    std::cout << '0' << std::setbase(16);
                    std::cout << (int) binary[sec_offset + i];
                } else {
                    std::cout << std::setbase(16);
                    std::cout << (int) binary[sec_offset + i];
                }
            }

            count++;
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
            break;
        default:
            ERROR("Invalid options!");
    }

    return 0;
}

