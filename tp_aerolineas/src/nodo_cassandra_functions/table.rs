use crate::nodo_cassandra_functions::primary_key::PrimaryKey;
use std::collections::HashMap;

// Estructura que representa una tabla
#[derive(Debug, Clone)]
pub struct Table {
    pub name: String,                      // Nombre de la tabla
    pub primary_key: PrimaryKey,           // PrimaryKey de la tabla
    pub columnas: HashMap<String, String>, // Columnas de la tabla con tipo de datos
}
