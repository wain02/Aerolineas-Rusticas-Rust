use crate::nodo_cassandra_functions::replication_config::ReplicationConfig;
// Estructura que representa un keyspace
#[derive(Debug)]
pub struct CreateKeyspaceQuery {
    pub name: String,                            // Nombre del keyspace
    pub replication_strategy: ReplicationConfig, // Configuración de replicación
}
