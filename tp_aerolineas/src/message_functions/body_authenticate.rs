use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Read;

#[derive(Debug, Clone)]
pub struct BodyAuthenticate {
    pub mechanism: Vec<u8>,
}

impl BodyAuthenticate {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];
        let mechanism_len: u32 = self.mechanism.len() as u32;
        if let Err(e) = bytes.write_u32::<BigEndian>(mechanism_len) {
            eprintln!(
                "Error al serializar longitud del mechanism en BodyAuthenticate: {:?}",
                e
            );
        }
        bytes.extend_from_slice(&self.mechanism);
        bytes
    }

    pub fn deserialize(bytes: &[u8]) -> std::io::Result<Self> {
        let mut reader: &[u8] = bytes;
        let mechanism_len: usize = reader.read_u32::<BigEndian>()? as usize;
        let mut mechanism: Vec<u8> = vec![0; mechanism_len];
        reader.read_exact(&mut mechanism)?;

        Ok(BodyAuthenticate { mechanism })
    }
}
