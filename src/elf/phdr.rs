use crate::bytes::{convert, Address};
use crate::elf::ehdr::Elf64Hdr;
use crate::parser::ParseError;

pub const PF_EXEC: u8 = 0x1;
pub const PF_WRITE: u8 = 0x2;
pub const PF_READ: u8 = 0x4;

#[repr(u32)]
#[derive(Debug)]
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
}

impl Elf64PHdr {
    pub fn parse(data: &[u8], headers: &Elf64Hdr) -> Result<Vec<Self>, ParseError> {
        let nth = headers.ph_num as usize;
        let off = headers.ph_off as usize;
        let siz = headers.ph_ent_size as usize;

        let headers: Vec<Elf64PHdr> = data[off..]
            .chunks(siz)
            .take(nth)
            .map(|sh| Elf64PHdr {
                p_type: convert::<u32, 4>(sh[0..=3].try_into().unwrap(), headers.ident.data)
                    .try_into()
                    .unwrap(),
                flags: convert(sh[4..=7].try_into().unwrap(), headers.ident.data),
                offset: convert(sh[8..=15].try_into().unwrap(), headers.ident.data),
                vaddr: convert(sh[16..=23].try_into().unwrap(), headers.ident.data),
                paddr: convert(sh[24..=31].try_into().unwrap(), headers.ident.data),
                filesz: convert(sh[32..=39].try_into().unwrap(), headers.ident.data),
                memsz: convert(sh[40..=47].try_into().unwrap(), headers.ident.data),
                align: convert(sh[48..=55].try_into().unwrap(), headers.ident.data),
            })
            .collect();

        Ok(headers)
    }
}
