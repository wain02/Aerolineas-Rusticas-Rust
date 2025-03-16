use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read};
#[derive(Debug, Clone)]
pub struct QueryValue {
    pub name: Option<String>, // Nombre del valor si el flag 0x40 está presente
    pub value: Vec<u8>,       // Valor serializado
}

impl QueryValue {
    // Deserializar `QueryValue`
    pub fn deserialize(reader: &mut Cursor<&[u8]>) -> std::io::Result<Self> {
        let value_len = reader.read_u32::<BigEndian>()? as usize;
        let mut value_bytes = vec![0; value_len];
        reader.read_exact(&mut value_bytes)?;

        Ok(QueryValue {
            name: None,
            value: value_bytes,
        })
    }

    // Serializar `QueryValue`
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        if let Err(e) = bytes.write_u32::<BigEndian>(self.value.len() as u32) {
            eprintln!("Error serializando valor de QueryValue: {:?}", e);
        }

        bytes.extend_from_slice(&self.value);
        bytes
    }
}
