#[derive(Debug)]
pub enum ChangeType {
    Create,
}

impl ChangeType {
    // Serializa el tipo de cambio a su representación en bytes
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            ChangeType::Create => b"CREATE".to_vec(),
        }
    }

    // Deserializa el tipo de cambio desde bytes
    pub fn deserialize(bytes: &[u8]) -> std::io::Result<Self> {
        match bytes {
            b"CREATE" => Ok(ChangeType::Create),
            //b"UPDATED" => Ok(ChangeType::Updated),
            //b"DROPPED" => Ok(ChangeType::Dropped),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Tipo de cambio no válido",
            )),
        }
    }
}
