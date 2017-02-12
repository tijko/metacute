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
    elf_osabi = elf_hdr.e_ident[EI_OSABI];
}

int Elf::check_magic_number(std::vector<uint8_t> binary)
{
    char *file_magic_mark[SELFMAG];
    memcpy(file_magic_mark, binary.data(), SELFMAG);
    return memcmp(ELFMAG, file_magic_mark, SELFMAG);
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
    int sec_offset = sec_hdr.sh_offset;
    int sec_size = sec_hdr.sh_size;
    std::cout << std::endl;
    std::cout << SEP;
    std::cout << std::endl << " Name: " << name;
    std::cout << " Size: " << std::setbase(10) << sec_size;
    std::cout << " Offset: " << sec_offset;
    std::cout << " Type: " << sec_hdr.sh_type << std::endl;
    std::cout << " Type-Name: " << section_types[sec_hdr.sh_type];
    std::cout << " Flags: " << sec_hdr.sh_flags;
    std::cout << " Link: " << sec_hdr.sh_link;
    std::cout << " Info: " << sec_hdr.sh_info;
    std::cout << std::endl;
    std::cout << SEP;
}

Meta::Meta(const char *file)
{
    this->file = file;
    // Return errno on failure
    // (e.g. doesn't exist, privileged cap, invalid file attrs)
    file_handle.open(file, std::ios::binary | std::ios::in);
    // if file_handle.is_open() or just not
    
    struct stat st;
    stat(file, &st);
    binary.resize(st.st_size);
    file_handle.read((char *) &binary[0], st.st_size);
    // check for bytes actually read...
    file_handle.close();

    elf = Elf(binary);
}

void Meta::print_elf(void)
{
    // Have macro formatted....
    std::cout << elf.elf_endian << std::endl;
    std::cout << elf.elf_osabi << std::endl;
    std::cout << elf.elf_hdr.e_type << std::endl;
    std::cout << elf.elf_hdr.e_machine << std::endl;
    std::cout << elf.elf_hdr.e_entry << std::endl;
    std::cout << elf.elf_hdr.e_ehsize << std::endl;
    std::cout << elf.elf_hdr.e_phoff << std::endl;
    std::cout << elf.elf_hdr.e_shoff << std::endl;
    std::cout << elf.elf_hdr.e_phnum << std::endl;
    std::cout << elf.elf_hdr.e_shnum << std::endl;
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

        std::cout << std::endl;
        std::cout << std::setw(0);
    }

}

Elf64_Ehdr Meta::get_elf(void)
{
    return elf.elf_hdr;
}

int main(int argc, char *argv[])
{
    if (argc > 3)
        ERROR("Invalid options!");

    const char *options = "esp";
    char opt = getopt(argc, argv, options);
    
    switch (opt) {

        case ('e'):
            break;
        default:
            ERROR("Invalid options!");
    }

    const char *file = argv[2];
    Meta metacute(file);
    //metacute.print_elf();
    metacute.load_sections();
    // print out strings and size/offsets of sections
    metacute.print_sections();

    return 0;
}

