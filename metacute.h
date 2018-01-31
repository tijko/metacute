#include <map>
#include <vector>
#include <cstdlib>
#include <fstream>

#define ERROR(msg)                      \
    do {                                \
        std::cout << msg << std::endl;  \
        print_usage();                  \
        exit(1);                        \
    } while (1)                         \

#define ALIGN_SECTION_WIDTH 36

#define SEC_SIZE sizeof(Elf64_Shdr)

#define NUM_SEC_VALS 34
#define NUM_SEG_VALS 20
#define ALIGN_OUTPUT 15

#define ELF_PRINT_FORMAT "------------------------------------------------------------\n" \
                         "File: %s\tArch: %s\tType: %s\nElf-Size: %d\t"                   \
                         "Endian: %s\nEntry: %11x\nABI: %13d\nSegments: %8u\t"            \
                         "Sections: %8u\nSegment-Offset: %lu\tSection-Offset: %lu\n"      \
                         "------------------------------------------------------------\n" \

#define SEC_PRINT_FORMAT "------------------------------------------------------------\n" \
                         " Name: %s\tSize: %lu\tOffset: %lu\n Type: %s\n"                 \
                         " Link: %s\n Info: %s\n Flags: %lu\n"                            \
                         "------------------------------------------------------------"   \

#define SEG_PRINT_FORMAT "------------------------------------------------------------\n" \
                         " Type: %s\t Offset: %ld\t Vaddr: %ld\t Paddr: %ld\n"            \
                         " Filesz: %ld\t Memsz: %ld\t Flags: %d\t Align: %ld\n"           \
                         "------------------------------------------------------------\n" \

const unsigned int section_values[] = {
    SHT_NULL,
    SHT_PROGBITS,
    SHT_SYMTAB,
    SHT_STRTAB,
    SHT_RELA,
    SHT_HASH,
    SHT_DYNAMIC,
    SHT_NOTE,
    SHT_NOBITS,
    SHT_REL,
    SHT_SHLIB,
    SHT_DYNSYM,
    SHT_INIT_ARRAY,
    SHT_FINI_ARRAY,
    SHT_PREINIT_ARRAY,
    SHT_GROUP,
    SHT_SYMTAB_SHNDX,
    SHT_NUM,
    SHT_LOOS,
    SHT_GNU_ATTRIBUTES,
    SHT_GNU_HASH,
    SHT_GNU_LIBLIST,
    SHT_CHECKSUM,
    SHT_LOSUNW,
    SHT_SUNW_move,
    SHT_SUNW_COMDAT,
    SHT_SUNW_syminfo,
    SHT_GNU_verdef,
    SHT_GNU_verneed,
    SHT_GNU_versym,
    SHT_HISUNW,
    SHT_HIOS,
    SHT_LOPROC,
    SHT_HIPROC,
    SHT_LOUSER,
    SHT_HIUSER
};

const std::string section_value_names[] = {
    "SHT_NULL",
    "SHT_PROGBITS",
    "SHT_SYMTAB",
    "SHT_STRTAB",
    "SHT_RELA",
    "SHT_HASH",
    "SHT_DYNAMIC",
    "SHT_NOTE",
    "SHT_NOBITS",
    "SHT_REL",
    "SHT_SHLIB",
    "SHT_DYNSYM",
    "SHT_INIT_ARRAY",
    "SHT_FINI_ARRAY",
    "SHT_PREINIT_ARRAY",
    "SHT_GROUP",
    "SHT_SYMTAB_SHNDX",
    "SHT_NUM",
    "SHT_LOOS",
    "SHT_GNU_ATTRIBUTES",
    "SHT_GNU_HASH",
    "SHT_GNU_LIBLIST",
    "SHT_CHECKSUM",
    "SHT_LOSUNW",
    "SHT_SUNW_move",
    "SHT_SUNW_COMDAT",
    "SHT_SUNW_syminfo",
    "SHT_GNU_verdef",
    "SHT_GNU_verneed",
    "SHT_HISUNW",       // These next 3 types share the same value.
    "SHT_HIOS",         // Since I don't need HIOS or HISUNW, I put
    "SHT_GNU_versym",   // them first so they don't intefere with the GNU_versym
    "SHT_LOPROC",       // when building the hash table
    "SHT_HIPROC",
    "SHT_LOUSER",
    "SHT_HIUSER"
};

const std::string segment_type_names[] {
    "PT_NULL",
    "PT_LOAD",
    "PT_DYNAMIC",
    "PT_INTERP",
    "PT_NOTE",
    "PT_SHLIB",
    "PT_PHDR",
    "PT_TLS",
    "PT_NUM",
    "PT_LOOS",
    "PT_GNU_EH_FRAME",
    "PT_GNU_STACK",
    "PT_GNU_RELRO",
    "PT_LOSUNW",
    "PT_SUNWBSS",
    "PT_SUNWSTACK",
    "PT_HISUNW",
    "PT_HIOS",
    "PT_LOPROC",
    "PT_HIPROC"
};

const unsigned int segment_type_values[] {
    PT_NULL,
    PT_LOAD,
    PT_DYNAMIC,
    PT_INTERP,
    PT_NOTE,
    PT_SHLIB,
    PT_PHDR,
    PT_TLS,
    PT_NUM,
    PT_LOOS,
    PT_GNU_EH_FRAME,
    PT_GNU_STACK,
    PT_GNU_RELRO,
    PT_LOSUNW,
    PT_SUNWBSS,
    PT_SUNWSTACK,
    PT_HISUNW,
    PT_HIOS,
    PT_LOPROC,
    PT_HIPROC,
};

void print_usage(void);

class Elf {

    public:
        Elf(std::vector<uint8_t> binary);
        Elf(void) { }
        Elf64_Ehdr elf_hdr;
        int elf_class;
        int elf_endian;
        int elf_osabi;
        std::string arch;
        std::string type;
        std::string endian;

    private:
        int check_magic_number(std::vector<uint8_t> binary);
};

class Section {

    public:
        Section(Elf64_Shdr *section); 
        Elf64_Shdr sec_hdr;
        std::string link;
        std::string info; // Depends section-type
        std::map<const unsigned int, std::string> section_types;
        void print_section_hdr(std::string name);

    private:
        void load_section_types(void);
};

class Segment {

    public:
        Segment(Elf64_Phdr *seg_hdr);
        Elf64_Phdr *seg_hdr;
        std::map<const unsigned int, std::string> segment_types;

    private:
        void load_segment_types(void);
};

class Meta {

    public:
        Meta(const char *file, size_t file_size);
        std::string file;
        std::vector<uint8_t> binary;
        std::map<std::string, Section *> sections;
        std::vector<Segment *> segments; 
        void print_sections(void);
        void print_segments(void);
        void print_elf(void);
        Elf64_Ehdr get_elf(void);

    private:
        Elf elf;
        void load_elf(void);
        void load_sections(void);
        void load_segments(void);
        void display_section_chars(int idx, size_t sec_offset);
        std::string get_section_str(size_t sh_idx, size_t str_tbl_offset);
        std::ifstream file_handle;
};

