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

    pub fn parse(&mut self, data: Vec<u8>) -> Result<&Self, ParseError> {
        self.headers = *Elf64Hdr::parse(&data)?.validate();
        self.section_headers = Elf64SHdr::parse(&data, &self.headers)?;

        Ok(self)
    }
}

fn main() {
    let contents = std::fs::read("./out/rv64i-test").unwrap();
    let mut elf = ElfParser::new();
    elf.parse(contents).unwrap();

    println!("{:#?}", elf);
}
