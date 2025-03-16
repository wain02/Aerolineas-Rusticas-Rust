use crate::nodo_cassandra_functions::replication_class::ReplicationClass;
// Configuración de replicación
#[derive(Debug, Clone)]
pub struct ReplicationConfig {
    pub class: ReplicationClass, // Estrategia de replicación
    pub replication_factor: u32, // Factor de replicación
}
