use crate::message_functions::{consistency::Consistency, query_value::QueryValue};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

#[derive(Debug, Clone)]
pub struct QueryParameters {
    pub consistency: Consistency,                // Nivel de consistencia
    pub flags: u8,                               // Flags que definen las opciones de la consulta
    pub values: Option<Vec<QueryValue>>,         // Valores si el flag 0x01 está presente
    pub result_page_size: Option<i32>,           // Tamaño de la página
    pub paging_state: Option<Vec<u8>>,           // Estado de paginación
    pub serial_consistency: Option<Consistency>, // Consistencia serial
    pub timestamp: Option<i64>,                  // Timestamp opcional
}

impl QueryParameters {
    /// Serializa los parámetros de consulta en un vector de bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = vec![];
        if let Err(e) = bytes.write_u16::<BigEndian>(self.consistency.clone() as u16) {
            eprintln!(
                "Error al serializar la consistencia en QueryParameters: {:?}",
                e
            );
        }
        bytes.push(self.flags);
        bytes
    }

    /// Deserializa un slice de bytes en una estructura `QueryParameters`.
    pub fn deserialize(reader: &mut &[u8]) -> std::io::Result<Self> {
        if reader.len() < 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Not enough bytes for consistency",
            ));
        }
        let consistency = Consistency::from_u16(reader.read_u16::<BigEndian>()?)?;
        let flags = reader.read_u8()?;

        Ok(QueryParameters {
            consistency,
            flags,
            values: None,
            result_page_size: None,
            paging_state: None,
            serial_consistency: None,
            timestamp: None,
        })
    }
}
