#[derive(Debug, Clone)]
pub struct ColumnSpec {
    pub name: String,  // Nombre de la columna.
    pub col_type: u16, // Tipo de la columna (ejemplo: 0x000D para `varchar`).
}
