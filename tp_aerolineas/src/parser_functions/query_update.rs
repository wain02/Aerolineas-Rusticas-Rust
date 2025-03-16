use crate::parser_functions::{condicion_compuesta::CondicionCompuesta, consistency::Consistency};

#[derive(Debug)]
pub struct UpdateQuery {
    pub tabla: String,
    pub keyspace: String,
    pub set: Vec<(String, String)>,
    pub condiciones: CondicionCompuesta,
    pub consistency: Consistency,
}
