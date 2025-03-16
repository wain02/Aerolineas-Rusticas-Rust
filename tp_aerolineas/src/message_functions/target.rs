#[derive(Debug, PartialEq)]
pub enum Target {
    Keyspace,
    Table,
    Type,
}

impl Target {
    /// Serializa el objetivo (`Target`) a un vector de bytes.
    /// Devuelve un vector que representa el tipo de objetivo.
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Target::Keyspace => b"KEYSPACE".to_vec(),
            Target::Table => b"TABLE".to_vec(),
            Target::Type => b"TYPE".to_vec(),
        }
    }
    /// Deserializa un slice de bytes a un objetivo (`Target`).
    /// Intenta convertir los bytes en el tipo de objetivo correspondiente.
    pub fn deserialize(bytes: &[u8]) -> std::io::Result<Self> {
        match bytes {
            b"KEYSPACE" => Ok(Target::Keyspace),
            b"TABLE" => Ok(Target::Table),
            b"TYPE" => Ok(Target::Type),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Objetivo no válido",
            )),
        }
    }
}
