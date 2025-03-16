use std::io::Read;

use byteorder::{BigEndian, ReadBytesExt};

use crate::message_functions::column_spec::ColumnSpec;

#[derive(Debug, Clone)]
pub struct Metadata {
    pub flags: u32,                                  // Flags de la respuesta.
    pub columns_count: u32,                          // Número de columnas.
    pub global_table_spec: Option<(String, String)>, // Especificación de keyspace y tabla global.
    pub column_specs: Vec<ColumnSpec>,               // Especificaciones de las columnas.
}

// Para serializar los metadatos de columnas (esto ya lo tienes en BodyRows)
impl Metadata {
    /// Serializa la estructura en un vector de bytes.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.columns_count.to_be_bytes());

        if let Some((ks, table)) = &self.global_table_spec {
            bytes.extend_from_slice(&(ks.len() as u16).to_be_bytes());
            bytes.extend_from_slice(ks.as_bytes());
            bytes.extend_from_slice(&(table.len() as u16).to_be_bytes());
            bytes.extend_from_slice(table.as_bytes());
        }

        for col in &self.column_specs {
            bytes.extend_from_slice(&(col.name.len() as u16).to_be_bytes());
            bytes.extend_from_slice(col.name.as_bytes());
            bytes.extend_from_slice(&col.col_type.to_be_bytes());
        }

        bytes
    }
    /// Deserializa los datos de un lector de bytes en una estructura.
    pub fn deserialize(reader: &mut std::io::Cursor<&[u8]>) -> std::io::Result<Self> {
        let flags = reader.read_u32::<BigEndian>()?;
        let columns_count = reader.read_u32::<BigEndian>()?;

        let global_table_spec = if flags & 0x0001 != 0 {
            let ks_len = reader.read_u16::<BigEndian>()? as usize;
            let mut ks_bytes = vec![0; ks_len];
            reader.read_exact(&mut ks_bytes)?;
            let keyspace = String::from_utf8(ks_bytes).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid keyspace name")
            })?;
            let table_len = reader.read_u16::<BigEndian>()? as usize;
            let mut table_bytes = vec![0; table_len];
            reader.read_exact(&mut table_bytes)?;
            let table = String::from_utf8(table_bytes).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid table name")
            })?;
            Some((keyspace, table))
        } else {
            None
        };
        let mut column_specs = vec![];
        for _ in 0..columns_count {
            let name_len = reader.read_u16::<BigEndian>()? as usize;
            let mut name_bytes = vec![0; name_len];
            reader.read_exact(&mut name_bytes)?;
            let name = String::from_utf8(name_bytes).map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid column name")
            })?;

            let col_type = reader.read_u16::<BigEndian>()?;
            column_specs.push(ColumnSpec { name, col_type });
        }
        Ok(Self {
            flags,
            columns_count,
            global_table_spec,
            column_specs,
        })
    }
}
