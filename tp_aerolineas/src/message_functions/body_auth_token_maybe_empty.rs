use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Read;

#[derive(Debug, Clone)]
pub struct BodyAuthTokenMaybeEmpty {
    pub token: Vec<u8>,
}

impl BodyAuthTokenMaybeEmpty {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];

        // Verificamos si el token es vacío o no, y ajustamos la serialización en consecuencia
        let token_len: u32 = self.token.len() as u32;
        if let Err(e) = bytes.write_u32::<BigEndian>(token_len) {
            eprintln!(
                "Error al serializar longitud del token en BodyAuthTokenMaybeEmpty: {:?}",
                e
            );
        }
        if token_len > 0 {
            // Si el token no está vacío, lo agregamos
            bytes.extend_from_slice(&self.token);
        }

        bytes
    }

    pub fn deserialize(bytes: &[u8]) -> std::io::Result<Self> {
        let mut reader: &[u8] = bytes;

        // Leer la longitud del token primero
        let token_len: usize = reader.read_u32::<BigEndian>()? as usize;
        let mut token: Vec<u8> = vec![0; token_len];

        // Si el token no está vacío, leemos los datos del token
        if token_len > 0 {
            reader.read_exact(&mut token)?;
        }

        Ok(BodyAuthTokenMaybeEmpty { token })
    }
}
