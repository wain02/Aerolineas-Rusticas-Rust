use crate::message_functions::metadata::Metadata;
use byteorder::{BigEndian, ReadBytesExt};

#[derive(Debug, Clone)]
pub struct BodyPreparedResult {
    pub id: u64,                   // ID de la consulta preparada (short bytes)
    pub metadata: Metadata,        // Metadata de la consulta preparada
    pub result_metadata: Metadata, // Metadata del resultado de la consulta
}

impl BodyPreparedResult {
    // Serializa el BodyPreparedResult en un vector de bytes
    // Serializa el BodyPreparedResult en un vector de bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Primero agregamos el kind 0x0004 (Prepared)
        bytes.extend_from_slice(&0x0004_u32.to_be_bytes()); // kind = 0x0004 para "Prepared"

        // Serializar el ID (u64)
        bytes.extend_from_slice(&self.id.to_be_bytes());

        // Serializar los metadatos de la consulta
        bytes.extend(self.metadata.serialize());

        // Serializar los metadatos del resultado
        bytes.extend(self.result_metadata.serialize());

        bytes
    }

    // Deserializa un slice de bytes en un BodyPreparedResult
    pub fn deserialize(bytes: &[u8]) -> std::io::Result<Self> {
        let mut reader = std::io::Cursor::new(&bytes[4..]); // Saltamos el kind (los primeros 4 bytes)

        // Leer el ID (u64)
        let id = reader.read_u64::<BigEndian>()?;

        // Deserializar los metadatos de la consulta preparada
        let metadata = Metadata::deserialize(&mut reader)?;

        // Deserializar los metadatos del resultado esperado
        let result_metadata = Metadata::deserialize(&mut reader)?;

        Ok(Self {
            id,
            metadata,
            result_metadata,
        })
    }
}
