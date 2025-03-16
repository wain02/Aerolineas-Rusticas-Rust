// Estructura de clave primaria
#[derive(Debug, Clone)]
pub struct PrimaryKey {
    pub partition_key: Vec<String>,  // Clave de partición
    pub clustering_key: Vec<String>, // Clave de agrupamiento
}
