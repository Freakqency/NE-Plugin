typedef struct {
        ut16 e_magic;      /* 00: MZ Header signature */
        ut16 e_cblp;       /* 02: Bytes on last page of file */
        ut16 e_cp;         /* 04: Pages in file */
        ut16 e_crlc;       /* 06: Relocations */
        ut16 e_cparhdr;    /* 08: Size of header in paragraphs */
        ut16 e_minalloc;   /* 0a: Minimum extra paragraphs needed */
        ut16 e_maxalloc;   /* 0c: Maximum extra paragraphs needed */
        ut16 e_ss;         /* 0e: Initial (relative) SS value */
        ut16 e_sp;         /* 10: Initial SP value */
        ut16 e_csum;       /* 12: Checksum */
        ut16 e_ip;         /* 14: Initial IP value */
        ut16 e_cs;         /* 16: Initial (relative) CS value */
        ut16 e_lfarlc;     /* 18: File address of relocation table */
        ut16 e_ovno;       /* 1a: Overlay number */
        ut16 e_res[4];     /* 1c: Reserved words */
        ut16 e_oemid;      /* 24: OEM identifier (for e_oeminfo) */
        ut16 e_oeminfo;    /* 26: OEM information; e_oemid specific */
        ut16 e_res2[10];   /* 28: Reserved words */
        ut32 e_lfanew;     /* 3c: Offset to extended header */
}Dos_header;


typedef struct{
    uint16_t  magic;             /* 00  signature '' */
    uint8_t  ver;               /* 02 Linker version number */
    uint8_t  rev;               /* 03 Linker revision number */
    uint16_t  enttab;            /* 04 Offset to entry table */
    uint16_t  cbenttab;          /* 06 Length of entry table in uint8_ts */
    uint32_t crc;               /* 08 Checksum */
    uint16_t  flags;             /* 0c Flags about segments in this file */
    uint8_t  autodata;          /* 0e Automatic data segment number */
    uint8_t  unused;            /* 0f */
    uint16_t heap;              /* 10 Initial size of local heap */
    uint16_t  stack;             /* 12 Initial size of stack */
    uint16_t  ip;                /* 14 Initial IP */
    uint16_t  cs;                /* 16 Initial CS */
    uint16_t  sp;                /* 18 Initial SP */
    uint16_t  ss;                /* 1a Initial SS */
    uint16_t  cseg;              /* 1c # of entries in segment table */
    uint16_t  cmod;              /* 1e # of entries in import module table */
    uint16_t  cbnrestab;         /* 20 Length of nonresident-name table */
    uint16_t  segtab;            /* 22 Offset to segment table */
    uint16_t  rsrctab;           /* 24 Offset to resource table */
    uint16_t  restab;            /* 26 Offset to resident-name table */
    uint16_t  modtab;            /* 28 Offset to import module table */
    uint16_t  imptab;            /* 2a Offset to name table */
    uint32_t nrestab;           /* 2c ABSOLUTE Offset to nonresident-name table */
    uint16_t cmovent;           /* 30 # of movable entry points */
    uint16_t  align;             /* 32 Logical sector alignment shift count */
    uint16_t  cres;              /* 34 # of resource segments */
    uint8_t  exetyp;            /* 36 Flags indicating target OS */
    uint8_t  flagsothers;       /* 37 Additional information flags */
    uint16_t  pretthunks;        /* 38 Offset to return thunks */
    uint16_t  psegrefuint8_ts;      /* 3a Offset to segment ref. uint8_ts */
    uint16_t  swaparea;          /* 3c Reserved by Microsoft */
    uint8_t  expver_min;        /* 3e Expected Windows version number (minor) */
    uint8_t  expver_maj;        /* 3f Expected Windows version number (major) */
}NEHEADER;
