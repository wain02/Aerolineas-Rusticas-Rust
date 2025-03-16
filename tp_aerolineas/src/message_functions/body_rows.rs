use crate::message_functions::{
    column_spec::ColumnSpec, metadata::Metadata, row_content::RowContent, value::Value,
};
use byteorder::{BigEndian, ReadBytesExt};
use std::io::{self, Read};

#[derive(Debug, Clone)]
pub struct BodyRows {
    pub metadata: Metadata,            // Metadata sobre las columnas.
    pub rows_count: u32,               // Número de filas.
    pub rows_content: Vec<RowContent>, // Contenido de las filas.
}

// Serialización y deserialización de `BodyRows`
impl BodyRows {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0002_u32.to_be_bytes()); // `kind = 0x0002` para "Rows".

        bytes.extend_from_slice(&self.metadata.flags.to_be_bytes());
        bytes.extend_from_slice(&self.metadata.columns_count.to_be_bytes());

        if let Some((ks, table)) = &self.metadata.global_table_spec {
            bytes.extend_from_slice(&(ks.len() as u16).to_be_bytes());
            bytes.extend_from_slice(ks.as_bytes());
            bytes.extend_from_slice(&(table.len() as u16).to_be_bytes());
            bytes.extend_from_slice(table.as_bytes());
        }

        for col in &self.metadata.column_specs {
            bytes.extend_from_slice(&(col.name.len() as u16).to_be_bytes());
            bytes.extend_from_slice(col.name.as_bytes());
            bytes.extend_from_slice(&col.col_type.to_be_bytes());
        }

        bytes.extend_from_slice(&self.rows_count.to_be_bytes());

        for row in &self.rows_content {
            for value in &row.values {
                bytes.extend_from_slice(&(value.data.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&value.data);
            }
        }

        bytes
    }

    pub fn deserialize(bytes: &[u8]) -> std::io::Result<Self> {
        let mut reader = &bytes[4..]; // Saltamos los primeros 4 bytes (kind = 0x0002).

        let flags = reader.read_u32::<BigEndian>()?;
        let columns_count = reader.read_u32::<BigEndian>()?;

        let global_table_spec = Self::deserialize_table_spec(flags, &mut reader)?;
        let column_specs = Self::deserialize_columns_spec(&mut reader, columns_count)?;

        let rows_count = reader.read_u32::<BigEndian>()?;
        let rows_content = match Self::deserialize_rows(&column_specs, rows_count, &mut reader) {
            Ok(rows) => rows,
            Err(e) => return Err(e),
        };

        Ok(Self {
            metadata: Metadata {
                flags,
                columns_count,
                global_table_spec,
                column_specs,
            },
            rows_count,
            rows_content,
        })
    }

    fn deserialize_table_spec(
        flags: u32,
        reader: &mut &[u8],
    ) -> io::Result<Option<(String, String)>> {
        if flags & 0x0001 != 0 {
            let ks_len = reader.read_u16::<BigEndian>()? as usize;
            let mut ks_bytes = vec![0; ks_len];
            reader.read_exact(&mut ks_bytes)?;
            let keyspace = String::from_utf8(ks_bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid keyspace name"))?;

            let table_len = reader.read_u16::<BigEndian>()? as usize;
            let mut table_bytes = vec![0; table_len];
            reader.read_exact(&mut table_bytes)?;
            let table = String::from_utf8(table_bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid table name"))?;

            Ok(Some((keyspace, table)))
        } else {
            Ok(None)
        }
    }

    fn deserialize_columns_spec(
        reader: &mut &[u8],
        columns_count: u32,
    ) -> io::Result<Vec<ColumnSpec>> {
        let mut column_specs = vec![];
        for _ in 0..columns_count {
            let name_len = reader.read_u16::<BigEndian>()? as usize;
            let mut name_bytes = vec![0; name_len];
            reader.read_exact(&mut name_bytes)?;
            let name = String::from_utf8(name_bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid column name"))?;

            let col_type = reader.read_u16::<BigEndian>()?;
            column_specs.push(ColumnSpec { name, col_type });
        }
        Ok(column_specs)
    }

    fn match_col_type(col_spec: &ColumnSpec, value_bytes: Vec<u8>) -> io::Result<Value> {
        let value = match col_spec.col_type {
            0x000D => {
                // varchar (cadena de texto)
                let string_value = String::from_utf8(value_bytes.clone()).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid UTF-8 data")
                })?;
                println!(
                    "Columna '{}' valor (String): {}",
                    col_spec.name, string_value
                );
                Value {
                    data: string_value.into_bytes(),
                }
            }
            0x000A => {
                // int (ejemplo)
                let int_value =
                    String::from_utf8(value_bytes.clone()).unwrap_or_else(|_| "0".to_string());
                println!("Columna '{}' valor (Int): {}", col_spec.name, int_value);
                Value {
                    data: int_value.into_bytes(),
                }
            }
            _ => {
                println!(
                    "Columna '{}' valor (Raw bytes): {:?}",
                    col_spec.name, value_bytes
                );
                Value { data: value_bytes }
            }
        };
        Ok(value)
    }

    fn deserialize_rows(
        column_specs: &[ColumnSpec],
        rows_count: u32,
        reader: &mut &[u8],
    ) -> io::Result<Vec<RowContent>> {
        let mut rows_content = vec![];
        for _ in 0..rows_count {
            let mut values = vec![];
            for col_spec in column_specs {
                let value_len = reader.read_u32::<BigEndian>()? as usize;
                let mut value_bytes = vec![0; value_len];
                reader.read_exact(&mut value_bytes)?;
                let value = Self::match_col_type(col_spec, value_bytes)?;
                values.push(value);
            }
            rows_content.push(RowContent { values });
        }
        Ok(rows_content)
    }
}
