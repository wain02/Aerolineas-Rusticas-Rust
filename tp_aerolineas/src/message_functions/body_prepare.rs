use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Cursor;
use std::io::Read;

#[derive(Debug, Clone)]
pub struct BodyPrepare {
    pub query_string: String,
}

impl BodyPrepare {
    // Deserialización: Convierte un vector de bytes en una instancia de BodyPrepare
    pub fn deserialize(bytes: &[u8]) -> std::io::Result<Self> {
        let mut reader = Cursor::new(bytes);
        let query_len = reader.read_u32::<BigEndian>()? as usize;
        let mut query_bytes = vec![0; query_len];
        reader.read_exact(&mut query_bytes)?;

        let query_string = String::from_utf8(query_bytes)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "UTF-8 inválido"))?;

        Ok(BodyPrepare { query_string })
    }

    // Serialización: Convierte BodyPrepare en un vector de bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![];
        if let Err(e) = bytes.write_u32::<BigEndian>(self.query_string.len() as u32) {
            eprintln!(
                "Error al serializar longitud de consulta en BodyPrepare: {:?}",
                e
            );
        }
        bytes.extend_from_slice(self.query_string.as_bytes());
        bytes
    }
}
