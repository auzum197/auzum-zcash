//! Utility traits for encoding and decoding using corez.io primitives.

use corez::io::{self, Read, Write};

pub(crate) trait ReadBytesExt {
    fn read_u8(self) -> io::Result<u8>;
    fn read_u16_le(self) -> io::Result<u16>;
    fn read_u32_le(self) -> io::Result<u32>;
    fn read_u64_le(self) -> io::Result<u64>;
}

impl<R: Read> ReadBytesExt for &mut R {
    fn read_u8(self) -> io::Result<u8> {
        let mut repr = [0u8; 1];
        self.read_exact(&mut repr)?;
        Ok(repr[0])
    }

    fn read_u16_le(self) -> io::Result<u16> {
        let mut repr = [0u8; 2];
        self.read_exact(&mut repr)?;
        Ok(u16::from_le_bytes(repr))
    }

    fn read_u32_le(self) -> io::Result<u32> {
        let mut repr = [0u8; 4];
        self.read_exact(&mut repr)?;
        Ok(u32::from_le_bytes(repr))
    }

    fn read_u64_le(self) -> io::Result<u64> {
        let mut repr = [0u8; 8];
        self.read_exact(&mut repr)?;
        Ok(u64::from_le_bytes(repr))
    }
}

pub(crate) trait WriteBytesExt {
    fn write_u8(self, value: u8) -> io::Result<()>;
    fn write_u16_le(self, value: u16) -> io::Result<()>;
    fn write_u32_le(self, value: u32) -> io::Result<()>;
    fn write_u64_le(self, value: u64) -> io::Result<()>;
}

impl<W: Write> WriteBytesExt for &mut W {
    fn write_u8(self, value: u8) -> io::Result<()> {
        self.write_all(&[value])
    }

    fn write_u16_le(self, value: u16) -> io::Result<()> {
        self.write_all(&value.to_le_bytes())
    }

    fn write_u32_le(self, value: u32) -> io::Result<()> {
        self.write_all(&value.to_le_bytes())
    }

    fn write_u64_le(self, value: u64) -> io::Result<()> {
        self.write_all(&value.to_le_bytes())
    }
}
