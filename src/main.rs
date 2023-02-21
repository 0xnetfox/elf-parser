mod bytes;
mod elf;

use crate::elf::shdr::{Elf64SHdr};
use crate::bytes::{Address, convert, str_from_u8};
use crate::elf::ehdr::{Elf64Hdr, ElfHData};

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

    pub fn parse_str_tab(data: Vec<u8>, off: usize, size: usize) -> Result<Vec<u8>, ParseError> {
        let table: Vec<u8> = data[off..off + size]
            .try_into()
            .unwrap();

        assert_eq!(table.len(), size);
        assert_eq!(*table.first().unwrap(), 0u8);
        assert_eq!(*table.last().unwrap(), 0u8);

        Ok(table)
    }

    pub fn get_sh_name(&self, sh_idx: usize) -> Result<String, ()> {
        str_from_u8(&self.section_header_string_table[sh_idx..])
    }

    pub fn parse(&mut self, data: Vec<u8>) -> Result<&Self, ParseError> {
        self.headers = *Elf64Hdr::parse(&data)?.validate();
        self.section_headers = Elf64SHdr::parse(&data, &self.headers)?;

        let sh_str_tab = self.section_headers[self.headers.sh_str_ndx as usize];
        self.section_header_string_table = ElfParser::parse_str_tab(
            data,
            sh_str_tab.offset as usize,
            sh_str_tab.size as usize
        )?;

        self.section_headers.iter()
            .for_each(|sh| println!("{:?}", self.get_sh_name(sh.name as usize).unwrap()));

        Ok(self)
    }
}

fn main() {
    let contents = std::fs::read("./out/rv64i-test").unwrap();
    let mut elf = ElfParser::new();
    elf.parse(contents).unwrap();
}
