use crate::parser_functions::{condicion_compuesta::CondicionCompuesta, consistency::Consistency};

#[derive(Debug)]
pub struct SelectQuery {
    pub tabla: String,
    pub keyspace: String,
    pub columnas: Vec<String>,
    pub condiciones: CondicionCompuesta,
    pub order_by: Vec<(String, bool)>,
    pub consistency: Consistency,
}
