use crate::bytes::{convert, Address};
use crate::elf::ehdr::Elf64Hdr;
use crate::elf::phdr::PTypeData::Ignorable;
use crate::parser::ParseError;

pub const PF_EXEC: u32 = 0x1;
pub const PF_WRITE: u32 = 0x2;
pub const PF_READ: u32 = 0x4;

pub const DT_ENCODING: i64 = 32;
pub const DT_HIOS: i64 = 0x6ffff000;
pub const DT_LOPROC: i64 = 0x70000000;

#[repr(u32)]
#[derive(Debug, PartialEq)]
pub enum PType {
    PtNull = 0,
    PtLoad = 1,
    PtDynamic = 2,
    PtInterp = 3,
    PtNote = 4,
    PtShlib = 5,
    PtPhdr = 6,
    PtTls = 7,
    PtLoos = 8,
    PtHios = 9,
    PtLoProc = 10,
    PtHiProc = 11,
}

#[derive(Debug, PartialEq)]
pub enum PTypeData {
    PtLoadData(Vec<u8>),
    PtDynamicData(Vec<ELF64Dyn>),
    Ignorable,
}

impl PTypeData {
    pub fn parse_section(
        p_type: &PType,
        headers: &Elf64Hdr,
        filesz: u64,
        memsz: u64,
        offset: u64,
        data: &[u8],
    ) -> Result<Self, ParseError> {
        match p_type {
            PType::PtLoad => {
                if filesz > memsz {
                    panic!();
                }

                // initialize the data vector with len `memsz`, as that's the total length that
                // it should occupy on the process memory
                let mut bytes = vec![0u8; memsz as usize];

                let section = &data[offset as usize..(offset + filesz) as usize];
                bytes[0..filesz as usize].copy_from_slice(section);

                Ok(PTypeData::PtLoadData(bytes))
            }
            PType::PtDynamic => {
                let section = &data[offset as usize..(offset + filesz) as usize];

                Ok(PTypeData::PtDynamicData(
                    section
                        .chunks(16)
                        .map(|s| {
                            let d_tag: i64 =
                                convert(s[0..=7].try_into().unwrap(), headers.ident.data);
                            let d_un = convert(s[8..=15].try_into().unwrap(), headers.ident.data);

                            ELF64Dyn {
                                d_tag,
                                d_un: ELF64Dyn::d_un(d_tag, d_un),
                            }
                        })
                        .collect(),
                ))
            }
            _ => Ok(Ignorable),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum DynValue {
    DVal(u64),
    DPtr(Address),
}

#[derive(Debug, PartialEq)]
pub struct ELF64Dyn {
    pub d_tag: i64,
    pub d_un: DynValue,
}

impl ELF64Dyn {
    pub fn d_un(d_tag: i64, d_un: u64) -> DynValue {
        let is_ptr = d_tag % 2 == 0;

        match is_ptr {
            true => DynValue::DPtr(Address(d_un)),
            false => {
                if d_tag < DT_ENCODING || (d_tag > DT_HIOS && d_tag < DT_LOPROC) {
                    // TODO for now we don't care about this special case, but as the spec
                    // says `d_tags` that fall into these values are not ruled by the same
                    // rules as the other ones.
                    return DynValue::DVal(d_un);
                }

                DynValue::DVal(d_un)
            }
        }
    }
}

impl TryFrom<u32> for PType {
    type Error = ();

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        if v < 8 {
            return Ok(unsafe { std::mem::transmute::<u32, PType>(v) });
        }

        Ok(match v {
            0x60000000..0x6fffffff => PType::PtLoos,
            0x6fffffff..0x70000000 => PType::PtHios,
            0x70000000..0x7fffffff => PType::PtLoProc,
            0x7fffffff..=0xffffffff => PType::PtHiProc,
            _ => unreachable!(),
        })
    }
}

#[derive(Debug)]
pub struct Elf64PHdr {
    /// Segment type
    pub p_type: PType,
    /// Flags relevant to the segment
    pub flags: u32,
    /// Offset from the beginning of the file to the first byte of the segment
    pub offset: u64,
    /// The Virtual Address at which the first byte of this segment needs to reside
    pub vaddr: Address,
    /// On systems for which physical addressing is relevant, this member is reserved
    /// for the segment's physical address. Because System V ignores physical addressing
    /// for application programs, this member has unspecified contents for executable
    /// files and shared objects.
    pub paddr: Address,
    /// The number of bytes in the file image of the segment
    pub filesz: u64,
    /// The number of bytes in the memory image of the segment
    pub memsz: u64,
    /// This member gives the value to which the segments are aligned in memory and in
    /// the file. Values 0 and 1 mean no alignment is required. Otherwise, p_align should
    /// be a positive, integral power of 2, and p_vaddr should equal p_offset modulo p_align.
    pub align: u64,
    /// The section data that should be loaded into the process
    pub section: PTypeData,
}

impl Elf64PHdr {
    pub fn parse(data: &[u8], headers: &Elf64Hdr) -> Result<Vec<Self>, ParseError> {
        let nth = headers.ph_num as usize;
        let off = headers.ph_off as usize;
        let siz = headers.ph_ent_size as usize;

        let headers: Vec<Elf64PHdr> = data[off..]
            .chunks(siz)
            .take(nth)
            .map(|sh| {
                let p_type = convert::<u32, 4>(sh[0..=3].try_into().unwrap(), headers.ident.data)
                    .try_into()
                    .unwrap();
                let filesz = convert::<u64, 8>(sh[32..=39].try_into().unwrap(), headers.ident.data);
                let memsz = convert::<u64, 8>(sh[40..=47].try_into().unwrap(), headers.ident.data);
                let offset = convert::<u64, 8>(sh[8..=15].try_into().unwrap(), headers.ident.data);
                let section =
                    PTypeData::parse_section(&p_type, headers, filesz, memsz, offset, data)
                        .unwrap();

                Elf64PHdr {
                    p_type,
                    flags: convert(sh[4..=7].try_into().unwrap(), headers.ident.data),
                    offset,
                    vaddr: convert(sh[16..=23].try_into().unwrap(), headers.ident.data),
                    paddr: convert(sh[24..=31].try_into().unwrap(), headers.ident.data),
                    filesz,
                    memsz,
                    align: convert(sh[48..=55].try_into().unwrap(), headers.ident.data),
                    section,
                }
            })
            .collect();

        Ok(headers)
    }
}
