mod bytes;

extern crate core;

use crate::bytes::{Address, GenericBytes};
use crate::ElfHData::ElfData2Msb;

/// Based of:
/// [System V Application Binary Interface - DRAFT - 10 June 2013](http://www.sco.com/developers/gabi/latest/contents.html)

/// Implementation Constraints List:
/// + This implementation only handles RISC-V machines
/// + This implementation only handles 64-bit class

const IDENT_SZ: usize = 16;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Default)]
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
#[derive(Debug, PartialEq, Eq, Default)]
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
#[derive(Debug, PartialEq, Eq, Default)]
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
#[derive(Debug, Default)]
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
    version: ElfHVersion,
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

struct Elf64SHdr {
    name: u32,
    s_type: u32,
    flags: u64,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addr_align: u64,
    ent_size: u64,
}

#[derive(Debug, Default)]
struct ElfParser {
    endianness: ElfHData,
    headers: Elf64Hdr,
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
            T::from_le_bytes(bytes)
        } else {
            T::from_be_bytes(bytes)
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

    pub fn parse_headers(&mut self, data: Vec<u8>) -> Result<Elf64Hdr, ParseError> {
        let ident = Self::parse_ident(&data).unwrap();

        Ok(Elf64Hdr {
            ident,
            e_type: self.convert::<u16, 2>(data[16..=17].try_into().unwrap())
                .try_into()
                .unwrap(),
            machine: self.convert(data[18..=19].try_into().unwrap()),
            version: data[20].try_into().unwrap(),
            entry: self.convert(data[21..=28].try_into().unwrap()),
            ph_off: self.convert(data[29..=36].try_into().unwrap()),
            sh_off: self.convert(data[37..=44].try_into().unwrap()),
            flags: self.convert(data[45..=48].try_into().unwrap()),
            eh_size: self.convert(data[49..=50].try_into().unwrap()),
            ph_ent_size: self.convert(data[51..=52].try_into().unwrap()),
            ph_num: self.convert(data[53..=54].try_into().unwrap()),
            sh_ent_size: self.convert(data[55..=56].try_into().unwrap()),
            sh_num: self.convert(data[57..=58].try_into().unwrap()),
            sh_str_ndx: self.convert(data[59..=60].try_into().unwrap())
        })
    }

    pub fn parse(&mut self, data: Vec<u8>) -> Result<&Self, ParseError> {
        self.headers = self.parse_headers(data)?;
        Ok(self)
    }
}

fn main() {
    let contents = std::fs::read("./out/rv64i-test").unwrap();
    let mut elf = ElfParser::new();
    elf.parse(contents).unwrap();

    println!("{:#?}", elf);
}
