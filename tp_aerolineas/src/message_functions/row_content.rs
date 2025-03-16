use crate::message_functions::value::Value;

#[derive(Debug, Clone)]
pub struct RowContent {
    pub values: Vec<Value>, // Cada fila tiene una lista de valores para las columnas.
}
