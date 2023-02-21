use crate::bytes::{Address, convert};
use crate::parser::ParseError;

/// Size of the first batch of information on the file, which contains
/// the data needed to parse the rest of the file
pub const IDENT_SZ: usize = 16;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ElfHClass {
    /// Identifies the ELF class as invalid
    _ElfClassIn = 0,
    /// Identifies the ELF class as 32-bit
    _ElfClass32 = 1,
    /// Identifies the ELF class as 64-bit
    ElfClass64 = 2,
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ElfHData {
    /// Identifies the ELF data as 2's complement, with the least significant byte
    /// occupying the lowest address.
    ElfData2Lsb = 1,
    /// Identifies the ELF data as 2's complement, with the most significant byte
    /// occupying the lowest address.
    ElfData2Msb = 2,
}

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum ElfHVersion {
    /// Identifies the ELF version as invalid
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
#[derive(Debug, Copy, Clone)]
pub struct Elf64Ident {
    /// Holds a magic number that identifies the file as an ELF file.
    /// The magic number is: 0x7f E L F
    pub mag: [u8; 4],
    /// Defines which machine architecture the file supports.
    /// The `class` helps identify which data types need to be used to parse
    /// the ELF headers.
    pub class: ElfHClass,
    /// Defines which way the data structures have been encoded both in the
    /// file header and in the file sections.
    pub data: ElfHData,
    /// Defines the ELF header version for this file.
    pub version: ElfHVersion,
    /// Identifies ELF extensions specific for an Operating System (OS) or
    /// Application Binary Interface (ABI). If 0, it means no dependant extensions
    /// have been used, otherwise each value maps to an OS/ABI.
    pub os_abi: u8,
    /// Identifies the version of the ABI this file's `os_abi` is targeting.
    /// If `os_abi` is 0, indicating no OS/ABI dependencies, this field should also
    /// hold a 0.
    pub abi_version: u8,
    /// Padding to keep the struct size as required by the specification
    _pad: [u8; IDENT_SZ - 9]
}

#[repr(u16)]
#[derive(Debug, Copy, Clone)]
pub enum ElfHType {
    /// No file type
    _None = 0,
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
#[derive(Debug, Copy, Clone)]
pub struct Elf64Hdr {
    /// Identifies how to interpret the file
    pub ident: Elf64Ident,
    /// Indicates the type of the file
    pub e_type: ElfHType,
    /// Indicates the architecture needed for the file
    pub machine: u16,
    /// Indicates the ELF header version for this file.
    pub version: u32,
    /// Specifies the virtual address to which the system will handle control.
    /// If there's no entry point for this file, this field holds 0.
    pub entry: Address,
    /// Indicates the offset in bytes of the program header table.
    /// If there's no program header table for this file, this field holds 0.
    pub ph_off: u64,
    /// Indicates the offset in bytes of the section header table.
    /// If there's no section header table for this file, this field holds 0.
    pub sh_off: u64,
    /// Indicates processor-specific flags associated with this file.
    pub flags: u32,
    /// Indicates the size in bytes of the headers.
    pub eh_size: u16,
    /// Indicates the size in bytes of one of the entries of the program header table.
    /// All of the entries in the table are of the same size.
    pub ph_ent_size: u16,
    /// Indicates the number of entries in the program header table.
    /// If there's no program header table for this file, this field holds 0.
    pub ph_num: u16,
    /// Indicates the size in bytes of one section header.
    /// A section header is one entry in the section header table, all entries are of
    /// the same size.
    pub sh_ent_size: u16,
    /// Indicates the number of entries in the section header table.
    /// If there's no section header table for this file, this field holds 0.
    pub sh_num: u16,
    /// Indicates the section header table index of the entry associated with the
    /// section name string table.
    /// If there's no section name string table for this file, this field holds SHN_UNDEF.
    pub sh_str_ndx: u16,
}

impl Elf64Hdr {
    pub fn validate(&self) -> &Self {
        assert_eq!(self.ident.mag, [0x7f, b'E', b'L', b'F']);
        assert_eq!(self.ident.class, ElfHClass::ElfClass64);
        assert_eq!(self.ident.data, ElfHData::ElfData2Lsb);
        assert_eq!(self.ident.version, ElfHVersion::ElfEvCurr);

        self
    }

    pub fn parse_ident(data: &[u8]) -> Result<Elf64Ident, ParseError> {
        let mut ident = [0u8; IDENT_SZ];
        ident.copy_from_slice(&(data
            .get(..IDENT_SZ)
            .ok_or(ParseError::InvalidLength)?)[..IDENT_SZ]
        );

        Ok(unsafe { std::mem::transmute::<[u8; IDENT_SZ], Elf64Ident>(ident) })
    }

    pub fn parse(data: &[u8]) -> Result<Self, ParseError> {
        let ident = Self::parse_ident(&data).unwrap();

        Ok(Elf64Hdr {
            ident,
            e_type: convert::<u16, 2>(data[16..=17].try_into().unwrap(), ident.data)
                .try_into()
                .unwrap(),
            machine: convert(data[18..=19].try_into().unwrap(), ident.data),
            version: convert(data[20..=23].try_into().unwrap(), ident.data),
            entry: convert(data[24..=31].try_into().unwrap(), ident.data),
            ph_off: convert(data[32..=39].try_into().unwrap(), ident.data),
            sh_off: convert(data[40..=47].try_into().unwrap(), ident.data),
            flags: convert(data[48..=51].try_into().unwrap(), ident.data),
            eh_size: convert(data[52..=53].try_into().unwrap(), ident.data),
            ph_ent_size: convert(data[54..=55].try_into().unwrap(), ident.data),
            ph_num: convert(data[56..=57].try_into().unwrap(), ident.data),
            sh_ent_size: convert(data[58..=59].try_into().unwrap(), ident.data),
            sh_num: convert(data[60..=61].try_into().unwrap(), ident.data),
            sh_str_ndx: convert(data[62..=63].try_into().unwrap(), ident.data)
        })
    }
}