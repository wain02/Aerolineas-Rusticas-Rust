use crate::parser_functions::operator::Operator;

// Representación de una condición
#[derive(Debug)]
pub struct SimpleCondition {
    pub columna1: String,
    pub operador: Operator,
    pub columna2: Option<String>, // Solo se utiliza si es una comparación entre columnas
    pub valor: Option<String>,    // Solo se utiliza si es una comparación con un valor constante
    pub es_comparacion_columnas: bool,
}
