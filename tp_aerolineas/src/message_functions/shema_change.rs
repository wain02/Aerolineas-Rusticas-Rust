use crate::message_functions::{change_type::ChangeType, target::Target};
use std::io;

#[derive(Debug)]
pub struct SchemaChange {
    pub change_type: ChangeType,
    pub target: Target,
    pub keyspace: String,
    pub table_or_type: Option<String>, // Opcional, solo para TABLE o TYPE
}

// Serialización y deserialización de `SchemaChange`
impl SchemaChange {
    // Serializa el mensaje SchemaChange a bytes
    pub fn serialize(&self) -> Vec<u8> {
        //to_bytes
        let mut result = Vec::new();
        result.extend_from_slice(&0x0005_u32.to_be_bytes()); // `kind = 0x0005` para "SchemaChange".
        result.extend(self.change_type.serialize());
        result.push(0); // Separador de campos
        result.extend(self.target.serialize());
        result.push(0);
        result.extend(self.keyspace.as_bytes());
        if let Some(ref name) = self.table_or_type {
            result.push(0);
            result.extend(name.as_bytes());
        }
        result
    }

    // Deserializa un mensaje SchemaChange desde bytes
    pub fn deserialize(bytes: &[u8]) -> std::io::Result<Self> {
        //from_bytes
        let reader = &bytes[4..];

        let mut parts = reader.split(|&b| b == 0);
        println!("los bytes de parts: {:?} ", parts);
        let change_type = parts
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Tipo de cambio faltante en SchemaChange",
                )
            })
            .and_then(ChangeType::deserialize)?;

        let target = parts
            .next()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Objetivo faltante en SchemaChange",
                )
            })
            .and_then(Target::deserialize)?;

        let keyspace_bytes = parts.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Keyspace faltante en SchemaChange",
            )
        })?;
        let keyspace = String::from_utf8(keyspace_bytes.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Keyspace inválido"))?;

        let table_or_type = if target == Target::Table || target == Target::Type {
            Some(
                String::from_utf8(parts.next().unwrap_or(&[]).to_vec()).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Nombre de tabla/tipo inválido",
                    )
                })?,
            )
        } else {
            None
        };

        println!("los bytes de table_or_type: {:?} ", keyspace);
        Ok(SchemaChange {
            change_type,
            target,
            keyspace,
            table_or_type,
        })
    }
}
