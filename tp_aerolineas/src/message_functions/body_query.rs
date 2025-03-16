use crate::message_functions::query_parameters::QueryParameters;
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::Read;

#[derive(Debug, Clone)]
pub struct BodyQuery {
    pub query_string: String,        // La consulta CQL (long string)
    pub parameters: QueryParameters, // Parámetros de la consulta
}

impl BodyQuery {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![];
        // Serializar la cadena de consulta
        let query_len = self.query_string.len() as u32;
        if let Err(e) = bytes.write_u32::<BigEndian>(query_len) {
            eprintln!(
                "Error al serializar longitud de la consulta en BodyQuery: {:?}",
                e
            );
        }
        bytes.extend_from_slice(self.query_string.as_bytes());

        // Serializar los parámetros
        bytes.extend(self.parameters.serialize());
        bytes
    }

    pub fn deserialize(bytes: &[u8]) -> std::io::Result<Self> {
        let mut reader = bytes; // Crear una referencia mutable a los bytes
        let query_len = reader.read_u32::<BigEndian>()? as usize;
        let mut query_bytes = vec![0; query_len];
        reader.read_exact(&mut query_bytes)?;

        let query_string = String::from_utf8(query_bytes)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-8"))?;
        let parameters = QueryParameters::deserialize(&mut reader)?;

        Ok(BodyQuery {
            query_string,
            parameters,
        })
    }
}
