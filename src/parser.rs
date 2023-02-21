use crate::bytes::str_from_u8;
use crate::elf::ehdr::Elf64Hdr;
use crate::elf::shdr::{Elf64SHdr, StringTable, StringTableType, SHT_STRTAB};

/// Based of:
/// [System V Application Binary Interface - DRAFT - 10 June 2013](http://www.sco.com/developers/gabi/latest/contents.html)

/// Implementation Constraints List:
/// + This implementation only handles RISC-V machines
/// + This implementation only handles 64-bit class
#[allow(dead_code)]
#[derive(Debug)]
pub struct ElfParser {
    pub headers: Elf64Hdr,
    pub section_headers: Vec<Elf64SHdr>,
    pub header_string_table_idx: usize,
    pub string_tables: Vec<StringTable>,
}

#[derive(Debug)]
pub enum ParseError {
    InvalidLength,
}

impl ElfParser {
    pub fn parse_string_tables(
        data: &[u8],
        headers: &Elf64Hdr,
        section_headers: &Vec<Elf64SHdr>,
    ) -> Result<Vec<StringTable>, ParseError> {
        Ok(section_headers
            .iter()
            .enumerate()
            .filter(|(_, sh)| sh.s_type == SHT_STRTAB)
            .map(|(idx, str_sh)| {
                Elf64SHdr::parse_str_table(&data, str_sh, idx == headers.sh_str_ndx as usize)
                    .unwrap()
            })
            .collect())
    }

    pub fn get_sh_name(str_table: &StringTable, idx: u32) -> Result<String, ()> {
        str_from_u8(&str_table.table[idx as usize..])
    }

    pub fn parse(data: Vec<u8>) -> Result<Self, ParseError> {
        let headers = *Elf64Hdr::parse(&data)?.validate();
        let section_headers = Elf64SHdr::parse(&data, &headers)?;

        let string_tables =
            ElfParser::parse_string_tables(&data, &headers, &section_headers).unwrap();
        let header_string_table_idx = string_tables
            .iter()
            .enumerate()
            .filter(|(_, sh)| sh.sh_type == StringTableType::ShStrTab)
            .map(|(idx, _)| idx)
            .nth(0)
            .unwrap();

        section_headers.iter().for_each(|sh| {
            println!(
                "{:?}",
                ElfParser::get_sh_name(&string_tables[header_string_table_idx], sh.name).unwrap()
            );
        });

        Ok(ElfParser {
            headers,
            section_headers,
            string_tables,
            header_string_table_idx,
        })
    }
}
