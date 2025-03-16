use byteorder::{BigEndian, ReadBytesExt};
use std::io::Read;

#[derive(Debug, Clone)]
pub struct BodySetKeyspace {
    pub keyspace: String, // Nombre del keyspace que fue cambiado.
}

// Serialización y deserialización de `BodySetKeyspace`
impl BodySetKeyspace {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0003_u32.to_be_bytes()); // `kind = 0x0003` para "Set_keyspace".

        let keyspace_len = self.keyspace.len() as u16;
        bytes.extend_from_slice(&keyspace_len.to_be_bytes());
        bytes.extend_from_slice(self.keyspace.as_bytes());

        bytes
    }

    pub fn deserialize(bytes: &[u8]) -> std::io::Result<Self> {
        let mut reader = &bytes[4..]; // Saltamos los primeros 4 bytes (kind = 0x0003).

        let keyspace_len = reader.read_u16::<BigEndian>()? as usize;
        let mut keyspace_bytes = vec![0; keyspace_len];
        reader.read_exact(&mut keyspace_bytes)?;
        let keyspace = String::from_utf8(keyspace_bytes).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid keyspace")
        })?;

        Ok(Self { keyspace })
    }
}
