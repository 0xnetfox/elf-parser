use crate::{Address, convert, Elf64Hdr, ParseError};

/// Indicates the lower bound of the range of reserved indices
pub const SHN_LORESERVE: u16 = 0xff00;

/// Indicates sections that store string tables
pub const SHT_STRTAB: u32    = 0x3;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum StringTableType {
    /// String Table
    StrTab,
    /// Section Header String Table
    ShStrTab,
    /// Dynamic Symbols String Table
    /// TODO: doesn't parse DynStr sections yet
    _DynSym,
}

#[derive(Debug, Clone)]
pub struct StringTable {
    /// Offset to the first byte of the table
    pub offset:     u64,
    /// Size of the table
    pub size:       u64,
    /// Vector of bytes that conform the table
    pub table:      Vec<u8>,
    /// Type of string table
    pub sh_type:    StringTableType
}

#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
pub struct Elf64SHdr {
    /// Name of the header section
    pub name: u32,
    /// Type of the header section
    pub s_type: u32,
    /// 1-bit flags that describe misc attributes
    pub flags: u64,
    /// if the section is loaded into the process memory, indicates at which
    /// address its first bit should reside, otherwise it contains 0
    pub addr: Address,
    /// The offset from the start of the file to the first byte in this section
    pub offset: u64,
    /// Section size
    pub size: u64,
    /// Index link to the section header table, whose interpretation is dependant on `s_type`
    pub link: u32,
    /// Extra information, whose interpretation is dependant on `s_type`
    pub info: u32,
    /// Alignment constraints as required by some sections, otherwise contains 0 or 1 indicating
    /// no constraints
    pub addr_align: u64,
    /// Holds the size in bytes of the section's table, or 0 if there is no table
    pub ent_size: u64,
}

impl Elf64SHdr {
    #[allow(dead_code)]
    pub fn has_table(&self) -> bool {
        self.ent_size != 0
    }

    #[allow(dead_code)]
    pub fn has_align_constraints(&self) -> bool {
        self.addr_align != 0 && self.addr_align != 1
    }

    pub fn parse_str_table(data: &[u8], section_header: &Elf64SHdr, is_header_table: bool) -> Result<StringTable, ParseError> {
        let off = section_header.offset as usize;
        let siz = section_header.size as usize;

        assert_eq!(section_header.s_type, SHT_STRTAB);

        let table: Vec<u8> = data[off..off + siz].try_into().unwrap();

        assert_eq!(table.len(), siz);
        assert_eq!(*table.first().unwrap(), 0u8);
        assert_eq!(*table.last().unwrap(), 0u8);

        let sh_type = if is_header_table { StringTableType::ShStrTab } else { StringTableType::StrTab };

        Ok(StringTable {
            offset: section_header.offset,
            size: section_header.size,
            table,
            sh_type,
        })
    }

    pub fn parse(data: &[u8], headers: &Elf64Hdr) -> Result<Vec<Self>, ParseError> {
        let nth = headers.sh_num as usize;
        let off = headers.sh_off as usize;
        let siz = headers.sh_ent_size as usize;

        if nth >= SHN_LORESERVE as usize {
            unimplemented!("If the number of entries in the section header table is
              larger than or equal to SHN_LORESERVE (0xff00), e_shnum
              holds the value zero and the real number of entries in the
              section header table is held in the sh_size member of the
              initial entry in section header table.  Otherwise, the
              sh_size member of the initial entry in the section header
              table holds the value zero.");
        }

        let headers: Vec<Elf64SHdr> = data[off..]
            .chunks(siz)
            .take(nth)
            .map(|sh| Elf64SHdr {
                name: convert(sh[0..=3].try_into().unwrap(), headers.ident.data),
                s_type: convert(sh[4..=7].try_into().unwrap(), headers.ident.data),
                flags: convert(sh[8..=15].try_into().unwrap(), headers.ident.data),
                addr: convert(sh[16..=23].try_into().unwrap(), headers.ident.data),
                offset: convert(sh[24..=31].try_into().unwrap(), headers.ident.data),
                size: convert(sh[32..=39].try_into().unwrap(), headers.ident.data),
                link: convert(sh[40..=43].try_into().unwrap(), headers.ident.data),
                info: convert(sh[44..=47].try_into().unwrap(), headers.ident.data),
                addr_align: convert(sh[48..=55].try_into().unwrap(), headers.ident.data),
                ent_size: convert(sh[56..=63].try_into().unwrap(), headers.ident.data)
            }).collect();

        Ok(headers)
    }
}