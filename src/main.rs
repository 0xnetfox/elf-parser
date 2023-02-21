mod bytes;
mod elf;

use crate::elf::shdr::{Elf64SHdr, SHT_STRTAB, StringTable, StringTableType};
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
    header_string_table_idx: usize,
    string_tables: Vec<StringTable>
}

#[derive(Debug)]
pub enum ParseError {
    InvalidLength,
}

impl ElfParser {
    pub fn new() -> Self {
        ElfParser::default()
    }

    pub fn parse_string_tables(&self, data: &[u8]) -> Result<Vec<StringTable>, ParseError> {
        Ok(self.section_headers
            .iter()
            .enumerate()
            .filter(|(_, sh)| sh.s_type == SHT_STRTAB)
            .map(|(idx, str_sh)| Elf64SHdr::parse_str_table(&data, str_sh, idx == self.headers.sh_str_ndx as usize).unwrap())
            .collect())
    }

    pub fn get_sh_name(str_table: &StringTable, idx: u32) -> Result<String, ()> {
        str_from_u8(&str_table.table[idx as usize..])
    }

    pub fn parse(&mut self, data: Vec<u8>) -> Result<&Self, ParseError> {
        self.headers = *Elf64Hdr::parse(&data)?.validate();
        self.section_headers = Elf64SHdr::parse(&data, &self.headers)?;
        self.string_tables = self.parse_string_tables(&data).unwrap();
        self.header_string_table_idx =
            self.string_tables.iter()
                .enumerate()
                .filter(|(_, sh)| sh.sh_type == StringTableType::ShStrTab)
                .map(|(idx, _)| idx)
                .nth(0)
                .unwrap();

        self.section_headers.iter()
            .for_each(|sh| {
                println!("{:?}", ElfParser::get_sh_name(&self.string_tables[self.header_string_table_idx], sh.name).unwrap());
            });

        Ok(self)
    }
}

fn main() {
    let contents = std::fs::read("./out/rv64i-test").unwrap();
    let mut elf = ElfParser::new();
    elf.parse(contents).unwrap();
}
