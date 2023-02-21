mod bytes;

extern crate core;

use crate::bytes::{Address, GenericBytes};
use crate::ElfHData::ElfData2Msb;

/// Based of:
/// [System V Application Binary Interface - DRAFT - 10 June 2013](http://www.sco.com/developers/gabi/latest/contents.html)

/// Implementation Constraints List:
/// + This implementation only handles RISC-V machines
/// + This implementation only handles 64-bit class

/// Size of the first batch of information on the file, which contains
/// the data needed to parse the rest of the file
const IDENT_SZ: usize = 16;

/// Indicates the lower bound of the range of reserved indices
const SHN_LORESERVE: u16 = 0xff00;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Default, Copy, Clone)]
enum ElfHClass {
    /// Identifies the ELF class as invalid
    #[default]
    ElfClassIn = 0,
    /// Identifies the ELF class as 32-bit
    _ElfClass32 = 1,
    /// Identifies the ELF class as 64-bit
    ElfClass64 = 2,
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Default, Copy, Clone)]
enum ElfHData {
    /// Identifies the ELF data as 2's complement, with the least significant byte
    /// occupying the lowest address.
    #[default]
    ElfData2Lsb = 1,
    /// Identifies the ELF data as 2's complement, with the most significant byte
    /// occupying the lowest address.
    ElfData2Msb = 2,
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Default, Copy, Clone)]
enum ElfHVersion {
    /// Identifies the ELF version as invalid
    #[default]
    ElfEvNone = 0,
    /// Identifies the ELF version as current
    ElfEvCurr = 1,
}

impl TryFrom<u8> for ElfHVersion {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ElfHVersion::ElfEvNone),
            1 => Ok(ElfHVersion::ElfEvCurr),
            _ => Err(())
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone)]
struct Elf64Ident {
    /// Holds a magic number that identifies the file as an ELF file.
    /// The magic number is: 0x7f E L F
    mag: [u8; 4],
    /// Defines which machine architecture the file supports.
    /// The `class` helps identify which data types need to be used to parse
    /// the ELF headers.
    class: ElfHClass,
    /// Defines which way the data structures have been encoded both in the
    /// file header and in the file sections.
    data: ElfHData,
    /// Defines the ELF header version for this file.
    version: ElfHVersion,
    /// Identifies ELF extensions specific for an Operating System (OS) or
    /// Application Binary Interface (ABI). If 0, it means no dependant extensions
    /// have been used, otherwise each value maps to an OS/ABI.
    os_abi: u8,
    /// Identifies the version of the ABI this file's `os_abi` is targeting.
    /// If `os_abi` is 0, indicating no OS/ABI dependencies, this field should also
    /// hold a 0.
    abi_version: u8,
    /// Padding to keep the struct size as required by the specification
    _pad: [u8; IDENT_SZ - 9]
}

#[repr(u16)]
#[derive(Debug, Default)]
enum ElfHType {
    /// No file type
    #[default]
    None = 0,
    /// An executable file
    Executable = 2,
}

impl TryFrom<u16> for ElfHType {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            2 => Ok(ElfHType::Executable),
            _ => Err(())
        }
    }
}

/// ELF headers specification
#[repr(C)]
#[derive(Debug, Default)]
struct Elf64Hdr {
    /// Identifies how to interpret the file
    ident: Elf64Ident,
    /// Indicates the type of the file
    e_type: ElfHType,
    /// Indicates the architecture needed for the file
    machine: u16,
    /// Indicates the ELF header version for this file.
    version: u32,
    /// Specifies the virtual address to which the system will handle control.
    /// If there's no entry point for this file, this field holds 0.
    entry: Address,
    /// Indicates the offset in bytes of the program header table.
    /// If there's no program header table for this file, this field holds 0.
    ph_off: u64,
    /// Indicates the offset in bytes of the section header table.
    /// If there's no section header table for this file, this field holds 0.
    sh_off: u64,
    /// Indicates processor-specific flags associated with this file.
    flags: u32,
    /// Indicates the size in bytes of the headers.
    eh_size: u16,
    /// Indicates the size in bytes of one of the entries of the program header table.
    /// All of the entries in the table are of the same size.
    ph_ent_size: u16,
    /// Indicates the number of entries in the program header table.
    /// If there's no program header table for this file, this field holds 0.
    ph_num: u16,
    /// Indicates the size in bytes of one section header.
    /// A section header is one entry in the section header table, all entries are of
    /// the same size.
    sh_ent_size: u16,
    /// Indicates the number of entries in the section header table.
    /// If there's no section header table for this file, this field holds 0.
    sh_num: u16,
    /// Indicates the section header table index of the entry associated with the
    /// section name string table.
    /// If there's no section name string table for this file, this field holds SHN_UNDEF.
    sh_str_ndx: u16,
}

#[allow(dead_code)]
#[derive(Debug, Copy, Clone)]
struct Elf64SHdr {
    /// Name of the header section
    name: u32,
    /// Type of the header section
    s_type: u32,
    /// 1-bit flags that describe misc attributes
    flags: u64,
    /// if the section is loaded into the process memory, indicates at which
    /// address its first bit should reside, otherwise it contains 0
    addr: Address,
    /// The offset from the start of the file to the first byte in this section
    offset: u64,
    /// Header section size
    size: u64,
    /// Index link to the section header table, whose interpretation is dependant on `s_type`
    link: u32,
    /// Extra information, whose interpretation is dependant on `s_type`
    info: u32,
    /// Alignment constraints as required by some sections, otherwise contains 0 or 1 indicating
    /// no constraints
    addr_align: u64,
    /// Holds the size in bytes of the section's table, or 0 if there is no table
    ent_size: u64,
}

impl Elf64SHdr {
    #[allow(dead_code)]
    fn has_table(&self) -> bool {
        self.ent_size == 0
    }

    #[allow(dead_code)]
    fn has_align_constraints(&self) -> bool {
        self.addr_align == 0 || self.addr_align == 1
    }
}

#[derive(Debug, Default)]
struct ElfParser {
    endianness: ElfHData,
    headers: Elf64Hdr,
    section_headers: Vec<Elf64SHdr>
}

#[derive(Debug)]
pub enum ParseError {
    InvalidLength,
}


impl ElfParser {
    pub fn new() -> Self {
        ElfParser::default()
    }

    pub fn convert<T: GenericBytes<N>, const N: usize>(&self, bytes: [u8; N]) -> T {
        if self.endianness == ElfData2Msb {
            T::from_be_bytes(bytes)
        } else {
            T::from_le_bytes(bytes)
        }
    }

    pub fn parse_ident(data: &[u8]) -> Result<Elf64Ident, ParseError> {
        let mut ident = [0u8; IDENT_SZ];
        ident.copy_from_slice(&(data
            .get(..IDENT_SZ)
            .ok_or(ParseError::InvalidLength)?)[..IDENT_SZ]
        );
        let ident = unsafe { std::mem::transmute::<[u8; IDENT_SZ], Elf64Ident>(ident) };

        assert_eq!(ident.mag, [0x7f, b'E', b'L', b'F']);
        assert_eq!(ident.class, ElfHClass::ElfClass64);
        assert_eq!(ident.data, ElfHData::ElfData2Lsb);
        assert_eq!(ident.version, ElfHVersion::ElfEvCurr);

        Ok(ident)
    }

    pub fn parse_headers(&mut self, data: &Vec<u8>) -> Result<Elf64Hdr, ParseError> {
        let ident = Self::parse_ident(&data).unwrap();
        self.endianness = ident.data;

        Ok(Elf64Hdr {
            ident,
            e_type: self.convert::<u16, 2>(data[16..=17].try_into().unwrap())
                .try_into()
                .unwrap(),
            machine: self.convert(data[18..=19].try_into().unwrap()),
            version: self.convert(data[20..=23].try_into().unwrap()),
            entry: self.convert(data[24..=31].try_into().unwrap()),
            ph_off: self.convert(data[32..=39].try_into().unwrap()),
            sh_off: self.convert(data[40..=47].try_into().unwrap()),
            flags: self.convert(data[48..=51].try_into().unwrap()),
            eh_size: self.convert(data[52..=53].try_into().unwrap()),
            ph_ent_size: self.convert(data[54..=55].try_into().unwrap()),
            ph_num: self.convert(data[56..=57].try_into().unwrap()),
            sh_ent_size: self.convert(data[58..=59].try_into().unwrap()),
            sh_num: self.convert(data[60..=61].try_into().unwrap()),
            sh_str_ndx: self.convert(data[62..=63].try_into().unwrap())
        })
    }

    pub fn parse_header_sections(&mut self, data: &Vec<u8>) -> Result<Vec<Elf64SHdr>, ParseError> {
        let nth = self.headers.sh_num as usize;
        let off = self.headers.sh_off as usize;
        let siz = self.headers.sh_ent_size as usize;

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
                name: self.convert(sh[0..=3].try_into().unwrap()),
                s_type: self.convert(sh[4..=7].try_into().unwrap()),
                flags: self.convert(sh[8..=15].try_into().unwrap()),
                addr: self.convert(sh[16..=23].try_into().unwrap()),
                offset: self.convert(sh[24..=31].try_into().unwrap()),
                size: self.convert(sh[32..=39].try_into().unwrap()),
                link: self.convert(sh[40..=43].try_into().unwrap()),
                info: self.convert(sh[44..=47].try_into().unwrap()),
                addr_align: self.convert(sh[48..=55].try_into().unwrap()),
                ent_size: self.convert(sh[56..=63].try_into().unwrap())
            }).collect();

        Ok(headers)
    }

    pub fn parse(&mut self, data: Vec<u8>) -> Result<&Self, ParseError> {
        self.headers = self.parse_headers(&data)?;
        self.section_headers = self.parse_header_sections(&data)?;

        Ok(self)
    }
}

fn main() {
    let contents = std::fs::read("./out/rv64i-test").unwrap();
    let mut elf = ElfParser::new();
    elf.parse(contents).unwrap();

    println!("{:#?}", elf);
}
