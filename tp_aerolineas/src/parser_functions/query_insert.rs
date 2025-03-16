use crate::parser_functions::consistency::Consistency;

#[derive(Debug)]
pub struct InsertQuery {
    pub tabla: String,
    pub keyspace: String,
    pub columnas: Vec<String>,
    pub valores: Vec<Vec<String>>, // Cada Vec<String> es una fila de valores
    pub consistency: Consistency,
}
