use crate::nodo_cassandra_functions::primary_key::PrimaryKey;

//CREATE
#[derive(Debug)]
pub struct CreateTableQuery {
    pub tabla: String,
    pub keyspace: String,
    pub columnas: Vec<(String, String)>, // (nombre, tipo)
    pub primary_key: PrimaryKey,
}
