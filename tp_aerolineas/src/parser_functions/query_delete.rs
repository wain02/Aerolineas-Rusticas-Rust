use crate::parser_functions::{condicion_compuesta::CondicionCompuesta, consistency::Consistency};

#[derive(Debug)]
pub struct DeleteQuery {
    pub tabla: String,
    pub keyspace: String,
    pub condiciones: CondicionCompuesta,
    pub consistency: Consistency,
}
