use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Read;

#[derive(Debug, Clone)]
pub struct BodyAuthResponse {
    pub token: Vec<u8>, // Token de autenticación (SASL)
}

impl BodyAuthResponse {
    /// Serializa el token de `self` en un vector de bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![];
        let token_len = self.token.len() as u32;
        if let Err(e) = bytes.write_u32::<BigEndian>(token_len) {
            eprintln!(
                "Error al serializar longitud del token en BodyAuthResponse: {:?}",
                e
            );
        }
        bytes.extend_from_slice(&self.token);
        bytes
    }
    /// Deserializa un slice de bytes en un objeto `BodyAuthResponse`.
    pub fn deserialize(bytes: &[u8]) -> std::io::Result<Self> {
        let mut reader = bytes;
        let token_len = reader.read_u32::<BigEndian>()? as usize;
        let mut token = vec![0; token_len];
        reader.read_exact(&mut token)?;

        Ok(BodyAuthResponse { token })
    }
}
