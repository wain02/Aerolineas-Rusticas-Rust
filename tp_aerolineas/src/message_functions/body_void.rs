#[derive(Debug, Clone)]
pub struct BodyVoid;

// Serialización y deserialización de `BodyVoid`
impl BodyVoid {
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0001_u32.to_be_bytes()); // `kind = 0x0001` para "Void".
        bytes
    }
}
