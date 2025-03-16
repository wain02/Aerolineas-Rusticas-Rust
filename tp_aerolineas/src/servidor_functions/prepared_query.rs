use crate::servidor_functions::prepared_metadata::PreparedMetadata;
#[derive(Debug)]
pub struct PreparedQuery {
    pub query_string: String,
    pub metadata: PreparedMetadata,
}
