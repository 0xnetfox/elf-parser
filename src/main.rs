mod bytes;
mod elf;

use crate::elf::shdr::{Elf64SHdr};
use crate::bytes::{Address, convert};
use crate::elf::ehdr::{Elf64Hdr, ElfHData, IDENT_SZ};

/// Based of:
/// [System V Application Binary Interface - DRAFT - 10 June 2013](http://www.sco.com/developers/gabi/latest/contents.html)

/// Implementation Constraints List:
/// + This implementation only handles RISC-V machines
/// + This implementation only handles 64-bit class

#[derive(Debug, Default)]
struct ElfParser {
    headers: Elf64Hdr,
    section_headers: Vec<Elf64SHdr>,
    section_header_string_table: Vec<u8>,
}

#[derive(Debug)]
pub enum ParseError {
    InvalidLength,
}

impl ElfParser {
    pub fn new() -> Self {
        ElfParser::default()
    }

    pub fn parse_sh_str_tab(data: Vec<u8>, sh_str_tab_hdr: Elf64SHdr) -> Result<Vec<u8>, ParseError> {
        let off = sh_str_tab_hdr.offset as usize;
        let siz = sh_str_tab_hdr.size as usize;
        let table: Vec<u8> = data[off..off + siz]
            .try_into()
            .unwrap();

        assert_eq!(table.len(), siz);
        assert_eq!(*table.first().unwrap(), 0u8);
        assert_eq!(*table.last().unwrap(), 0u8);

        Ok(table)
    }

    pub fn parse(&mut self, data: Vec<u8>) -> Result<&Self, ParseError> {
        self.headers = *Elf64Hdr::parse(&data)?.validate();
        self.section_headers = Elf64SHdr::parse(&data, &self.headers)?;

        self.section_header_string_table = ElfParser::parse_sh_str_tab(
            data,
            self.section_headers[self.headers.sh_str_ndx as usize]
        )?;

        Ok(self)
    }
}

fn main() {
    let contents = std::fs::read("./out/rv64i-test").unwrap();
    let mut elf = ElfParser::new();
    elf.parse(contents).unwrap();

    println!("{:#?}", elf);
}
