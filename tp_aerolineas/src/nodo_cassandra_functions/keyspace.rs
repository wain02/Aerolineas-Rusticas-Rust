use crate::nodo_cassandra_functions::replication_config::ReplicationConfig;
use crate::nodo_cassandra_functions::table::Table;
use std::collections::HashMap;
// Estructura que representa un keyspace
#[derive(Debug, Clone)]
pub struct Keyspace {
    pub name: String,                            // Nombre del keyspace
    pub replication_strategy: ReplicationConfig, // Configuración de replicación
    pub tables: HashMap<String, Table>,          // Tablas dentro del keyspace
}
