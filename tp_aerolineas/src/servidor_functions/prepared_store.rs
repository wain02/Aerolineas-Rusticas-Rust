use crate::servidor_functions::{
    prepared_metadata::PreparedMetadata, prepared_query::PreparedQuery,
};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

#[derive(Debug)]
pub struct PreparedStore {
    pub prepared_queries: HashMap<u64, PreparedQuery>,
}

impl PreparedStore {
    /// Crea una nueva instancia de `QueryManager`  .
    pub fn new() -> Self {
        Self {
            prepared_queries: HashMap::new(),
        }
    }
    /// Agrega una consulta preparada al administrador de consultas.
    pub fn add_prepared_query(&mut self, query_string: String, metadata: PreparedMetadata) -> u64 {
        let mut hasher = DefaultHasher::new();
        query_string.hash(&mut hasher);
        let query_id = hasher.finish();
        self.prepared_queries.insert(
            query_id,
            PreparedQuery {
                query_string,
                metadata,
            },
        );
        query_id
    }
    /// Recupera una consulta preparada usando su identificador.
    pub fn get_prepared_query(&self, id: u64) -> Option<&PreparedQuery> {
        self.prepared_queries.get(&id)
    }
}

impl Default for PreparedStore {
    fn default() -> Self {
        Self::new()
    }
}
