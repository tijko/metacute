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
#define ALIGN_OUTPUT 15

#define ALIGN_DYNAMIC 15

// create on construction, if to be made compatible with 32-bit elfs
#define SH_SIZE sizeof(Elf64_Shdr)
#define PH_SIZE sizeof(Elf64_Phdr)
#define DH_SIZE sizeof(Elf64_Dyn)
#define SY_SIZE sizeof(Elf64_Sym)

#define SH_TYPES 33
#define PH_TYPES 20
#define DT_TYPES 72 
#define SY_TYPES 7

#define SY_BINDS 3
#define SY_VISIS 4

#define SH_FLAGS 14
#define PH_FLAGS 3
#define DF_FLAGS 5
#define DF_FLAGS_1 26
#define DF_FLAGS_POS_1 2


#define ELF_PRINT_FORMAT "------------------------------------------------------------\n" \
                         "File: %s\tArch: %s\tType: %s\nElf-Size: %d\t"                   \
                         "Endian: %s\nEntry: %11x\nABI: %13d\nSegments: %8u\t"            \
                         "Sections: %8u\nSegment-Offset: %lu\tSection-Offset: %lu\n"      \
                         "------------------------------------------------------------\n" \

#define SH_PRINT_FORMAT "------------------------------------------------------------\n"  \
                         " Name: %s\tSize: %lu\tOffset: %lu\n Type:  %s\n"                \
                         " Link:  %s\n Info:  %s\n Flags: "                               \

#define PH_PRINT_FORMAT "------------------------------------------------------------\n"  \
                         " Type: %s\t Offset: %ld\t Filesz: %ld\n"                        \
                         " Paddr: %#lx\n Vaddr: %#lx\n Memsz: %ld\t Align: %ld\n Flags: " \

#define DT_PRINT_FORMAT "------------------------------------------------------------\n"  \
                        "     Dynamic Tag                         Name/Value           "  \
                        
#define SY_PRINT_FORMAT "------------------------------------------------------------\n"  \
                        " Address  Type\t\t Bind\t Visibility   Name                   "  \

#define PRINT_TERM       "\n------------------------------------------------------------" \


const char *sh_names[] = {
    "NULL",
    "PROGBITS",
    "SYMTAB",
    "STRTAB",
    "RELA",
    "HASH",
    "DYNAMIC",
    "NOTE",
    "NOBITS",
    "REL",
    "SHLIB",
    "DYNSYM",
    "INIT_ARRAY",
    "FINI_ARRAY",
    "PREINIT_ARRAY",
    "GROUP",
    "SYMTAB_SHNDX",
    "NUM",
    "LOOS",
    "GNU_ATTRIBUTES",
    "GNU_HASH",
    "GNU_LIBLIST",
    "CHECKSUM",
    "LOSUNW",
    "SUNW_move",
    "SUNW_COMDAT",
    "SUNW_syminfo",
    "GNU_verdef",
    "GNU_verneed",
    "HISUNW",       // These next 3 types share the same value.
    "HIOS",         // Since I don't need HIOS or HISUNW, I put
    "GNU_versym",   // them first so they don't intefere with the GNU_versym
    "LOPROC",       // when building the hash table
    "HIPROC",
    "LOUSER",
};

unsigned long sh_types[] = {
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
};

const char *sh_flag_names[] {
    "WRITE",
    "ALLOC",
    "EXECINSTR",
    "MERGE",
    "STRINGS",
    "INFO_LINK",
    "LINK_ORDER"
    "OS_NONCONFORMING",
    "GROUP",
    "TLS",
    "COMPRESSED",
    "MASKOS",
    "MASKPROC",
    "ORDERED",
    "EXCLUDE"
};

unsigned long sh_flags[] {
    SHF_WRITE,
    SHF_ALLOC,
    SHF_EXECINSTR,
    SHF_MERGE,
    SHF_STRINGS,
    SHF_INFO_LINK,
    SHF_LINK_ORDER,
    SHF_OS_NONCONFORMING,
    SHF_GROUP,
    SHF_COMPRESSED,
    SHF_MASKOS,
    SHF_MASKPROC,
    SHF_ORDERED,
};

const char *ph_names[] {
    "NULL",
    "LOAD",
    "DYNAMIC",
    "INTERP",
    "NOTE",
    "SHLIB",
    "PHDR",
    "TLS",
    "NUM",
    "LOOS",
    "GNU_EH_FRAME",
    "GNU_STACK",
    "GNU_RELRO",
    "LOSUNW",
    "SUNWBSS",
    "SUNWSTACK",
    "HISUNW",
    "HIOS",
    "LOPROC",
    "HIPROC"
};

unsigned long ph_types[] {
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

const char *ph_flag_names[] {
    "EXEC",
    "WRITE",
    "READ"
};

unsigned long ph_flags[] {
    PF_X,
    PF_W,
    PF_R
};

const char *dt_names[] {
    "NULL",
    "NEEDED",
    "PLTRELSZ",
    "PLTGOT",
    "HASH",
    "STRTAB",
    "SYMTAB",
    "RELA",
    "RELASZ",
    "RELAENT",
    "STRSZ",
    "SYMENT",
    "INIT",
    "FINI",
    "SONAME",
    "RPATH",
    "SYMBOLIC",
    "REL",
    "RELSZ",
    "RELENT",
    "PLTREL",
    "DEBUG",
    "TEXTREL",
    "JMPREL",
    "BIND_NOW",
    "INIT_ARRAY",
    "FINI_ARRAY",
    "INIT_ARRAYSZ",
    "FINI_ARRAYSZ",
    "RUNPATH",
    "FLAGS",
    "ENCODING",
    "PREINIT_ARRAY",
    "PREINIT_ARRAYSZ",
    "NUM",
    "LOOS",
    "HIOS",
    "LOPROC",
    "HIPROC",
    "VALRNGLO",
    "GNU_PRELINKED",
    "GNU_CONFLICTSZ",
    "GNU_LIBLISTSZ",
    "CHECKSUM",
    "PLTPADSZ",
    "MOVEENT",
    "MOVESZ",
    "FEATURE_1",
    "POSFLAG_1",
    "SYMINSZ",
    "SYMINENT",
    "ADDRRNGLO",
    "GNU_HASH",
    "TLSDESC_PLT",
    "TLSDESC_GOT",
    "GNU_CONFLICT",
    "GNU_LIBLIST",
    "CONFIG",
    "DEPAUDIT",
    "AUDIT",
    "PLTPAD",
    "MOVETAB",
    "SYMINFO",
    "VERSYM",
    "RELACOUNT",
    "RELCOUNT",
    "FLAGS_1",
    "VERDEF",
    "VERDEFNUM",
    "VERNEED",
    "VERNEEDNUM",
    "AUXILLARY",
    "FILTER",
};

unsigned long dt_tags[] {
    DT_NULL,
    DT_NEEDED,
    DT_PLTRELSZ,
    DT_PLTGOT,
    DT_HASH,
    DT_STRTAB,
    DT_SYMTAB,
    DT_RELA,
    DT_RELASZ,
    DT_RELAENT,
    DT_STRSZ,
    DT_SYMENT,
    DT_INIT,
    DT_FINI,
    DT_SONAME,
    DT_RPATH,
    DT_SYMBOLIC,
    DT_REL,
    DT_RELSZ,
    DT_RELENT,
    DT_PLTREL,
    DT_DEBUG,
    DT_TEXTREL,
    DT_JMPREL,
    DT_BIND_NOW,
    DT_INIT_ARRAY,
    DT_FINI_ARRAY,
    DT_INIT_ARRAYSZ,
    DT_FINI_ARRAYSZ,
    DT_RUNPATH,
    DT_FLAGS,
    DT_ENCODING,
    DT_PREINIT_ARRAY,
    DT_PREINIT_ARRAYSZ,
    DT_NUM,
    DT_LOOS,
    DT_HIOS,
    DT_LOPROC,
    DT_HIPROC,
    DT_VALRNGLO,
    DT_GNU_PRELINKED,
    DT_GNU_CONFLICTSZ,
    DT_GNU_LIBLISTSZ,
    DT_CHECKSUM,
    DT_PLTPADSZ,
    DT_MOVEENT,
    DT_MOVESZ,
    DT_FEATURE_1,
    DT_POSFLAG_1,
    DT_SYMINSZ,
    DT_SYMINENT,
    DT_ADDRRNGLO,
    DT_GNU_HASH,
    DT_TLSDESC_PLT,
    DT_TLSDESC_GOT,
    DT_GNU_CONFLICT,
    DT_GNU_LIBLIST,
    DT_CONFIG,
    DT_DEPAUDIT,
    DT_AUDIT,
    DT_PLTPAD,
    DT_MOVETAB,
    DT_SYMINFO,
    DT_VERSYM,
    DT_RELACOUNT,
    DT_RELCOUNT,
    DT_FLAGS_1,
    DT_VERDEF,
    DT_VERDEFNUM,
    DT_VERNEED,
    DT_VERNEEDNUM,
    DT_AUXILIARY,
    DT_FILTER
};

const char *df_flag_names[] = {
    "ORIGIN",
    "SYMBOLIC",
    "TEXTREL",
    "BIND-NOW",
    "STATIC-TLS"
};

unsigned long df_flags[] = {
    DF_ORIGIN,
    DF_SYMBOLIC,
    DF_TEXTREL,
    DF_BIND_NOW,
    DF_STATIC_TLS
};

const char *df_flags_1_names[] = {
    "NOW",
    "GLOBAL",
    "GROUP",
    "NODELETE",
    "LOADFLTR",
    "INITFIRST",
    "NOOPEN",
    "ORIGIN",
    "DIRECT",
    "TRANS",
    "INTERPOSE",
    "NODEFLIB",
    "NODUMP",
    "CONFALT",
    "ENDFILTEE",
    "DISPRELDNE",
    "DISPRELPND",
    "NODIRECT",
    "IGNMULDEF",
    "NOKSYSMS",
    "NOHDR",
    "EDITED",
    "NORELOC",
    "SYMINTERPOSE",
    "GLOBAUDIT",
    "SINGLETON",
};

unsigned long df_flags_1[] = {
    DF_1_NOW,
    DF_1_GLOBAL,
    DF_1_GROUP,
    DF_1_NODELETE,
    DF_1_LOADFLTR,
    DF_1_INITFIRST,
    DF_1_NOOPEN,
    DF_1_ORIGIN,
    DF_1_DIRECT,
    DF_1_TRANS,
    DF_1_INTERPOSE,
    DF_1_NODEFLIB,
    DF_1_NODUMP,
    DF_1_CONFALT,
    DF_1_ENDFILTEE,
    DF_1_DISPRELDNE,
    DF_1_DISPRELPND,
    DF_1_NODIRECT,
    DF_1_IGNMULDEF,
    DF_1_NOKSYMS,
    DF_1_NOHDR,
    DF_1_EDITED,
    DF_1_NORELOC,
    DF_1_SYMINTPOSE,
    DF_1_GLOBAUDIT,
    DF_1_SINGLETON,
};

const char *df_posflag_1_names[] = {
    "LAZYLOAD",
    "GROUPPERM"
};

unsigned long df_posflag_1[] = {
    DF_P1_LAZYLOAD,
    DF_P1_GROUPPERM
};

const char *sym_names[] = {
    "NOTYPE",
    "OBJECT",
    "FUNC",
    "SECTION",
    "FILE",
    "COMMON",
    "TLS",
};

unsigned long sym_types[] = {
    STT_NOTYPE,
    STT_OBJECT,
    STT_FUNC,
    STT_SECTION,
    STT_FILE,
    STT_COMMON,
    STT_TLS,
};

const char *sym_bind_names[] = {
    "LOCAL",
    "GLOBAL",
    "WEAK"
};

unsigned long sym_binds[] = {
    STB_LOCAL,
    STB_GLOBAL,
    STB_WEAK
};

const char *sym_visi_names[] = {
    "DEFAULT",
    "INTERNAL",
    "HIDDEN",
    "PROTECTED"
};

unsigned long sym_visi[] = {
    STV_DEFAULT,
    STV_INTERNAL,
    STV_HIDDEN,
    STV_PROTECTED
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

class Meta {

    public:
        // public v. private (review)
        Meta(const char *file, size_t file_size);
        std::string file;
        std::vector<uint8_t> binary;

        // XXX create an opaque type and hold just single vector
        std::map<std::string, Elf64_Shdr *> sections;
        std::vector<Elf64_Dyn *> dynamics;
        std::vector<Elf64_Phdr *> segments; 
        std::vector<Elf64_Sym *> symbols;

        void print_elf(void);
        void print_sections(void);
        void print_segments(void);
        void print_dynamics(void);
        void print_symbols(void);

        Elf64_Ehdr get_elf(void);

    private:
        Elf elf;
        void load_elf(void);
        void load_sections(void); 
        void load_segments(void); 
        void load_dynamics(void);
        void load_symbols(void);

        void print_section_hdr(Elf64_Shdr *section, std::string section_name);
        void display_section_chars(int idx, size_t sec_offset);
        std::string get_section_str(size_t sh_idx, size_t str_tbl_offset);

        /*
         * separate find-section and find-segment?
         *
         *   size_t find_segment(unsigned long pt_type);
         *
         * resolve string-name to type in separate
         * the above will be relavent when the other flags
         * for specific sections/segments are passed on cmd-line
         */

        // XXX as noted above cut down on structures by using generics
        // and passing along function ptrs
        std::map<unsigned long, std::string> segment_types; 
        
        std::map<unsigned long, std::string> section_types;
        
        std::map<unsigned long, std::string> dynamic_tags;

        std::map<unsigned long, std::string> symbol_types;
        std::map<unsigned long, std::string> symbol_binds;
        std::map<unsigned long, std::string> symbol_visi;

        std::map<std::string, std::string> section_links;
        std::map<std::string, std::string> section_infos;

        std::map<unsigned long, std::string> 
        map_types(const char **type_names, unsigned long *type_values, 
                                                        long type_num);

        std::vector<std::string>
        get_hdr_flags(const char **flag_names, unsigned long *flag_values,
                      long hdr_flags, int flag_num);

        void add_white_space(size_t length);

        std::ifstream file_handle;
};

