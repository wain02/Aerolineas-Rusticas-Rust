use crate::message_functions::{
    body_auth_response::BodyAuthResponse, body_auth_token_maybe_empty::BodyAuthTokenMaybeEmpty,
    body_authenticate::BodyAuthenticate, body_execute::BodyExecute, body_prepare::BodyPrepare,
    body_prepared_result::BodyPreparedResult, body_query::BodyQuery, body_rows::BodyRows,
    body_set_keyspace::BodySetKeyspace, body_startup::BodyStartup, body_void::BodyVoid,
    shema_change::SchemaChange,
};

// Definición del enum Body para manejar diferentes tipos de respuestas.
#[derive(Debug)]
pub enum Body {
    Void(BodyVoid),
    Rows(BodyRows),
    SetKeyspace(BodySetKeyspace),
    Query(BodyQuery),               // Consulta CQL
    Startup(BodyStartup),           // Mensaje STARTUP
    AuthResponse(BodyAuthResponse), // Respuesta de autenticación
    Authenticate(BodyAuthenticate),
    AuthChallenge(BodyAuthTokenMaybeEmpty),
    AuthSuccess(BodyAuthTokenMaybeEmpty),
    Options,              // Mensaje OPTIONS (sin cuerpo)
    Execute(BodyExecute), // Nuevo cuerpo para ejecutar consultas preparadas
    Prepare(BodyPrepare), // Nuevo cuerpo para consultas preparadas
    Raw(Vec<u8>),         // Variante para manejar datos no procesados
    PreparedResult(BodyPreparedResult),
    SchemaChange(SchemaChange),
    QueryNodoANodo(String), //solo para uso interno
}

// Opciones no necesitan un cuerpo, pero igual pueden tener un serializador que devuelva un array vacío
impl Body {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Body::Void(void_body) => void_body.serialize(),
            Body::Rows(rows_body) => rows_body.serialize(),
            Body::SetKeyspace(set_keyspace_body) => set_keyspace_body.serialize(),
            Body::Query(query_body) => query_body.serialize(),
            Body::Startup(startup_body) => startup_body.serialize(),
            Body::AuthResponse(auth_response) => auth_response.serialize(),

            Body::AuthChallenge(auth_body) => auth_body.serialize(),
            Body::AuthSuccess(auth_body) => auth_body.serialize(),
            Body::Authenticate(auth_body) => auth_body.serialize(),
            Body::Options => vec![], // No tiene cuerpo
            Body::Raw(bytes) => bytes.clone(),
            Body::Prepare(body_prepare) => body_prepare.serialize(),
            Body::PreparedResult(body_prepared_result) => body_prepared_result.serialize(),
            Body::Execute(body_execute) => body_execute.serialize(),
            Body::SchemaChange(schema_change) => schema_change.serialize(),
            Body::QueryNodoANodo(_) => vec![],
        }
    }
}
