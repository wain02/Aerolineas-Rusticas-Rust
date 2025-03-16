use crate::message_functions::query_parameters::QueryParameters;
use byteorder::{BigEndian, ReadBytesExt};
use std::io::Cursor;

#[derive(Debug, Clone)]
pub struct BodyExecute {
    pub query_id: u64,               // El ID de la consulta preparada
    pub parameters: QueryParameters, // Los parámetros para ejecutar la consulta
}

impl BodyExecute {
    //Cosntructor de BodyExecute
    pub fn new(query_id: u64, parameters: QueryParameters) -> Self {
        BodyExecute {
            query_id,
            parameters,
        }
    }

    // Método para deserializar un BodyExecute desde un array de bytes
    pub fn deserialize(bytes: &[u8]) -> std::io::Result<Self> {
        let mut reader = Cursor::new(bytes);

        // Leer el query_id (u64 = 8 bytes)
        let query_id = reader.read_u64::<BigEndian>()?;

        // Obtener los bytes restantes después de leer el query_id
        let remaining_bytes = &bytes[8..];

        // Convertir los bytes restantes a un slice para deserializar los parámetros
        let mut params_reader: &[u8] = remaining_bytes;

        // Deserializar los parámetros de consulta
        let parameters = QueryParameters::deserialize(&mut params_reader)?;

        Ok(BodyExecute {
            query_id,
            parameters,
        })
    }

    // Método para serializar un BodyExecute a un array de bytes
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Serializar el query_id (u64 = 8 bytes)
        bytes.extend_from_slice(&self.query_id.to_be_bytes());

        // Serializar los parámetros de la consulta
        bytes.extend_from_slice(&self.parameters.serialize());

        bytes
    }
}
