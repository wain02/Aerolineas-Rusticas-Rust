use crate::message_functions::string_map::StringMap;
use byteorder::ReadBytesExt;
use std::io::Read;

#[derive(Debug, Clone)]
pub struct BodyStartup {
    pub options: StringMap, // Mapa de opciones, clave-valor
}

// Implementación de serialización y deserialización para cada uno de estos cuerpos
impl BodyStartup {
    /// Serializa los pares clave-valor de `self.options.entries` en un vector de bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.push(self.options.entries.len() as u8);
        for (key, value) in &self.options.entries {
            bytes.push(key.len() as u8);
            bytes.extend_from_slice(key.as_bytes());
            bytes.push(value.len() as u8);
            bytes.extend_from_slice(value.as_bytes());
        }
        bytes
    }
    /// Deserializa un slice de bytes en un objeto `BodyStartup`.
    pub fn deserialize(bytes: &[u8]) -> std::io::Result<Self> {
        let mut reader = bytes;
        let mut entries = vec![];

        let count = reader.read_u8()? as usize;
        for _ in 0..count {
            let key_len = reader.read_u8()? as usize;
            let mut key_bytes = vec![0; key_len];
            reader.read_exact(&mut key_bytes)?;
            let key = String::from_utf8(key_bytes).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-8")
            })?;

            let value_len = reader.read_u8()? as usize;
            let mut value_bytes = vec![0; value_len];
            reader.read_exact(&mut value_bytes)?;
            let value = String::from_utf8(value_bytes).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-8")
            })?;

            entries.push((key, value));
        }

        Ok(BodyStartup {
            options: StringMap { entries },
        })
    }
}
