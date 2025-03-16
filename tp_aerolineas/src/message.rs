// message.rs
use crate::message_functions::{
    body::Body, body_auth_response::BodyAuthResponse,
    body_auth_token_maybe_empty::BodyAuthTokenMaybeEmpty, body_authenticate::BodyAuthenticate,
    body_execute::BodyExecute, body_prepare::BodyPrepare, body_prepared_result::BodyPreparedResult,
    body_query::BodyQuery, body_rows::BodyRows, body_set_keyspace::BodySetKeyspace,
    body_startup::BodyStartup, body_void::BodyVoid, change_type::ChangeType,
    column_spec::ColumnSpec, consistency::Consistency, metadata::Metadata,
    query_parameters::QueryParameters, row_content::RowContent, shema_change::SchemaChange,
    target::Target, value::Value,
};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Read};

pub const VERSION_REQUEST: u8 = 0x03; //03 -> 00000011, el primer 0 nos define una solicitud
pub const VERSION_RESPONSE: u8 = 0x83; //83 -> 10000011, el primer 1 nos define un responde

pub const OPCODE_ERROR: u8 = 0x00;
pub const OPCODE_STARTUP: u8 = 0x01;
pub const OPCODE_READY: u8 = 0x02;
pub const OPCODE_AUTHENTICATE: u8 = 0x03;
pub const OPCODE_OPTIONS: u8 = 0x05;
pub const OPCODE_SUPPORTED: u8 = 0x06;
pub const OPCODE_QUERY: u8 = 0x07;
pub const OPCODE_RESULT: u8 = 0x08;
pub const OPCODE_PREPARE: u8 = 0x09;
pub const OPCODE_EXECUTE: u8 = 0x0A;
pub const OPCODE_REGISTER: u8 = 0x0B;
pub const OPCODE_EVENT: u8 = 0x0C;
pub const OPCODE_BATCH: u8 = 0x0D;
pub const OPCODE_AUTH_CHALLENGE: u8 = 0x0E;
pub const OPCODE_AUTH_RESPONSE: u8 = 0x0F;
pub const OPCODE_AUTH_SUCCESS: u8 = 0x10;

pub const OPCODES_VEC: [u8; 16] = [
    OPCODE_ERROR,
    OPCODE_STARTUP,
    OPCODE_READY,
    OPCODE_AUTHENTICATE,
    OPCODE_OPTIONS,
    OPCODE_SUPPORTED,
    OPCODE_QUERY,
    OPCODE_RESULT,
    OPCODE_PREPARE,
    OPCODE_EXECUTE,
    OPCODE_REGISTER,
    OPCODE_EVENT,
    OPCODE_BATCH,
    OPCODE_AUTH_CHALLENGE,
    OPCODE_AUTH_RESPONSE,
    OPCODE_AUTH_SUCCESS,
];

pub const TEXT_STARTUP: &str = "STARTUP";
pub const TEXT_OPTIONS: &str = "OPTIONS";
pub const TEXT_AUTHENTICATION: &str = "AUTHENTICATE";
pub const TEXT_QUERY: &str = "QUERY";
pub const TEXT_PREPARE: &str = "PREPARE";
pub const TEXT_EXECUTE: &str = "EXECUTE";
pub const TEXT_EXIT: &str = "EXIT";

#[derive(Debug)]
pub struct Message {
    pub version: u8, // Versión del protocolo
    pub flags: u8,   // Flags de la conexión
    pub stream: u16, // ID del stream
    pub opcode: u8,  // Código de operación (ej: QUERY)
    pub length: u32, // Longitud del cuerpo
    pub body: Body,  // Cuerpo del mensaje como enum Body
}

impl Message {
    pub fn new(version: u8, opcode: u8, body: Body) -> Self {
        let length = 0;

        Self {
            version,
            flags: 0x00,
            stream: 0x0001,
            opcode,
            length,
            body,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut message = vec![];
        message.push(self.version);
        message.push(self.flags);
        if let Err(e) = message.write_u16::<BigEndian>(self.stream) {
            eprintln!("Error al serializar stream ID en Message: {:?}", e);
        }
        message.push(self.opcode);

        // Serializamos el body en función de la variante del enum Body
        let body_bytes = match &self.body {
            Body::Query(query_body) => query_body.serialize(), // Serializa el body de la consulta
            Body::Startup(startup_body) => startup_body.serialize(), // Serializa el body de STARTUP
            Body::AuthResponse(auth_body) => auth_body.serialize(), // Serializa la respuesta de autenticación
            Body::AuthChallenge(auth_challenge_body) => auth_challenge_body.serialize(),
            Body::AuthSuccess(auth_body) => auth_body.serialize(),
            Body::Authenticate(auth_body) => auth_body.serialize(),
            Body::Void(void_body) => void_body.serialize(), // Serializa el body de tipo VOID
            Body::Rows(rows_body) => rows_body.serialize(), // Serializa el body de tipo ROWS
            Body::SetKeyspace(set_keyspace_body) => set_keyspace_body.serialize(), // Serializa el body de tipo SetKeyspace
            Body::Options => vec![], // `Options` no tiene cuerpo
            Body::Prepare(body_prepare) => body_prepare.serialize(), // Serializa el body de consulta preparada
            Body::PreparedResult(body_prepared_result) => body_prepared_result.serialize(),
            Body::Execute(execute_body) => execute_body.serialize(), // Serializa el body de consulta preparada
            Body::Raw(raw_bytes) => raw_bytes.clone(), // Copia el contenido raw directamente
            Body::SchemaChange(schema_change) => schema_change.serialize(),
            Body::QueryNodoANodo(_) => vec![],
        };

        // Actualizamos la longitud del body y lo escribimos en el frame
        let length = body_bytes.len() as u32;
        if let Err(e) = message.write_u32::<BigEndian>(length) {
            eprintln!(
                "Error al escribir la longitud del cuerpo en Message: {:?}",
                e
            );
        }
        message.extend(body_bytes);
        message
    }

    fn deserialize_result_kind(body_bytes: &[u8]) -> io::Result<Body> {
        let kind = (&body_bytes[..4]).read_u32::<BigEndian>()?;
        match kind {
            0x0001 => Ok(Body::Void(BodyVoid {})),
            0x0002 => BodyRows::deserialize(body_bytes).map(Body::Rows),
            0x0003 => BodySetKeyspace::deserialize(body_bytes).map(Body::SetKeyspace),
            0x0004 => BodyPreparedResult::deserialize(body_bytes).map(Body::PreparedResult),
            0x0005 => SchemaChange::deserialize(body_bytes).map(Body::SchemaChange),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unknown result kind: {}", kind),
            )),
        }
    }

    fn deserialize_opcode(opcode: u8, body_bytes: &[u8]) -> io::Result<Body> {
        match opcode {
            OPCODE_QUERY => {
                let query_body = BodyQuery::deserialize(body_bytes)?;
                Ok(Body::Query(query_body))
            }
            OPCODE_PREPARE => {
                let prepare_body = BodyPrepare::deserialize(body_bytes)?;
                Ok(Body::Prepare(prepare_body))
            }
            OPCODE_EXECUTE => {
                let execute_body = BodyExecute::deserialize(body_bytes)?;
                Ok(Body::Execute(execute_body))
            }
            OPCODE_STARTUP => {
                let startup_body = BodyStartup::deserialize(body_bytes)?;
                Ok(Body::Startup(startup_body))
            }
            OPCODE_AUTH_RESPONSE => {
                let auth_body = BodyAuthResponse::deserialize(body_bytes)?;
                Ok(Body::AuthResponse(auth_body))
            }
            OPCODE_AUTHENTICATE => {
                let auth_body = BodyAuthenticate::deserialize(body_bytes)?;
                Ok(Body::Authenticate(auth_body))
            }
            OPCODE_AUTH_CHALLENGE => {
                let auth_body = BodyAuthTokenMaybeEmpty::deserialize(body_bytes)?;
                Ok(Body::AuthChallenge(auth_body))
            }
            OPCODE_AUTH_SUCCESS => {
                let auth_body = BodyAuthTokenMaybeEmpty::deserialize(body_bytes)?;
                Ok(Body::AuthSuccess(auth_body))
            }
            OPCODE_OPTIONS => Ok(Body::Options),
            OPCODE_READY | OPCODE_ERROR => Ok(Body::Raw(body_bytes.to_vec())),
            OPCODE_RESULT => Self::deserialize_result_kind(body_bytes),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Opcode desconocido: {}", opcode),
            )),
        }
    }

    // Método para deserializar el mensaje desde bytes
    pub fn deserialize(reader: &mut dyn Read) -> std::io::Result<Self> {
        let mut header = [0; 9];
        //entra
        reader.read_exact(&mut header)?;
        //no llega

        let version = header[0];
        let flags = header[1];
        let stream = (&header[2..4]).read_u16::<BigEndian>()?;
        let opcode = header[4];
        let length = (&header[5..9]).read_u32::<BigEndian>()?;
        println!("{:?}", header);

        let mut body_bytes = vec![0; length as usize];
        reader.read_exact(&mut body_bytes)?;

        if header[0..5].iter().all(|&byte| byte == 0xFF) {
            println!("En deserialize, me llegó un mensaje de nodo a nodo xd");
            return Ok(Self {
                version: 0xFF,
                flags: 0xFF,
                stream: 0xFFFF,
                opcode: 0xFF,
                length,
                body: Body::QueryNodoANodo(String::from_utf8(body_bytes).unwrap_or_default()),
            });
        }

        let body = Self::deserialize_opcode(opcode, &body_bytes)?;
        Ok(Self {
            version,
            flags,
            stream,
            opcode,
            length,
            body,
        })
    }

    pub fn handle_error_message(&self) {
        if let Body::Raw(body_bytes) = &self.body {
            let body_str = String::from_utf8(body_bytes.clone()).unwrap_or_else(|_| {
                "Error al convertir el cuerpo del mensaje a String".to_string()
            });
            let body_parts: Vec<&str> = body_str.splitn(2, ' ').collect();

            if body_parts.len() == 2 {
                let error_code = body_parts[0];
                let error_message = body_parts[1];
                println!(
                    "Error recibido: Código: {}, Mensaje: {}",
                    error_code, error_message
                );
            } else {
                println!("Error recibido con formato incorrecto");
            }
        } else {
            println!("Error: el cuerpo no está en formato Raw.");
        }
    }
    pub fn create_query_success_message() -> Self {
        // Aquí puedes personalizar la respuesta en función de lo que necesites
        let body = Body::Raw("QUERY ACEPTADA".as_bytes().to_vec()); // Simple respuesta de texto
        Message::new(VERSION_RESPONSE, OPCODE_RESULT, body)
    }
}
/// Crea un mensaje de inicio para establecer una conexión inicial con CQL.
/// El mensaje incluye la versión de CQL usada.
pub fn create_startup_message() -> Message {
    let mut body: Vec<u8> = vec![];
    body.push(0x00);

    let cql_version_key = "CQL_VERSION";
    body.push(cql_version_key.len() as u8);
    body.extend_from_slice(cql_version_key.as_bytes());

    let cql_version_value = "3.0.0";
    body.push(cql_version_value.len() as u8);
    body.extend_from_slice(cql_version_value.as_bytes());

    Message::new(VERSION_REQUEST, OPCODE_STARTUP, Body::Raw(body))
}

/// Crea un mensaje de consulta para ejecutar una instrucción CQL `SELECT`.
/// El mensaje contiene la consulta, la consistencia y las opciones de flags.
pub fn create_query_message() -> Message {
    let mut body: Vec<u8> = vec![];

    // <query>
    let query = "SELECT * FROM keyspace.user WHERE id = 1";
    let query_len = query.len() as u32;
    body.extend_from_slice(&query_len.to_be_bytes());
    body.extend_from_slice(query.as_bytes());

    // <consistency>
    let consistency = 0x0001;
    body.extend_from_slice(&(consistency as u16).to_be_bytes());

    // <flags>
    let flags = 0x00;
    body.push(flags);

    Message::new(VERSION_REQUEST, OPCODE_QUERY, Body::Raw(body))
}

/// Crea un mensaje de consulta preparado con un `token` específico.
/// Incluye parámetros como consistencia y flags, sin valores adicionales.
pub fn create_query_ready_message(token: &[u8]) -> Message {
    let query_body = BodyQuery {
        query_string: String::from_utf8_lossy(token).to_string(),
        parameters: QueryParameters {
            consistency: Consistency::One,
            flags: 0x00,
            values: None,
            result_page_size: None,
            paging_state: None,
            serial_consistency: None,
            timestamp: None,
        },
    };
    Message::new(VERSION_REQUEST, OPCODE_QUERY, Body::Query(query_body))
}

/// Crea un mensaje de respuesta indicando que la consulta fue aceptada.
pub fn create_query_succes_message() -> Message {
    Message::new(
        VERSION_RESPONSE,
        OPCODE_QUERY,
        Body::Raw("QUERY ACEPTADA".as_bytes().to_vec()),
    )
}

/// Crea un mensaje de tipo `READY` para indicar que el sistema está listo.
pub fn create_ready_message() -> Message {
    Message::new(VERSION_RESPONSE, OPCODE_READY, Body::Raw(vec![]))
}

/// Crea un mensaje de resultado `Void`, utilizado para operaciones no `SELECT`.
pub fn create_void_result_message() -> Message {
    Message::new(VERSION_RESPONSE, OPCODE_RESULT, Body::Raw(vec![]))
}

/// Crea un mensaje para cambiar el esquema, como la creación de una tabla.
pub fn create_schema_change_message() -> Message {
    let schema_change = SchemaChange {
        change_type: ChangeType::Create,
        target: Target::Table,
        keyspace: "my_keyspace".to_string(),
        table_or_type: Some("my_table".to_string()),
    };
    Message::new(
        VERSION_RESPONSE,
        OPCODE_RESULT,
        Body::SchemaChange(schema_change),
    )
}

/// Genera un mensaje de tipo `Rows` para consultas `SELECT`.
/// Convierte los datos de CSV en un formato de filas adecuado para su transmisión.
pub fn create_rows_message(csv_data: &str) -> Message {
    println!("---------------");
    println!("CSV DATA: {}", csv_data);
    println!("---------------");

    let mut lines = csv_data.split("//////");

    let header = lines.next().unwrap_or_default();
    let columns: Vec<&str> = header.split(',').collect();

    let column_specs: Vec<ColumnSpec> = columns
        .iter()
        .map(|col| ColumnSpec {
            name: col.to_string(),
            col_type: 0x000D,
        })
        .collect();

    let mut rows_content: Vec<RowContent> = Vec::new();

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }

        let row_values: Vec<Value> = line
            .split(',')
            .map(|value| Value {
                data: value.as_bytes().to_vec(),
            })
            .collect();

        rows_content.push(RowContent { values: row_values });
    }

    Message::new(
        VERSION_RESPONSE,
        OPCODE_RESULT,
        Body::Rows(BodyRows {
            metadata: Metadata {
                flags: 0x00,                         // Sin flags especiales
                columns_count: columns.len() as u32, // Número de columnas
                global_table_spec: None,             // Sin keyspace o tabla global
                column_specs,                        // Especificaciones de las columnas
            },
            rows_count: rows_content.len() as u32, // Número de filas
            rows_content,                          // Contenido de las filas
        }),
    )
}

// Genera un mensaje de tipo Void (para consultas que no sean SELECT)
pub fn create_void_message() -> Message {
    Message::new(VERSION_RESPONSE, OPCODE_RESULT, Body::Void(BodyVoid {}))
}

// pub fn schema_change_message() -> Message {
//     Message::new(VERSION_RESPONSE, OPCODE_RESULT, Body::Raw("SCHEMA CHANGE".as_bytes().to_vec()))
// }
pub fn create_prepared_result_message(query_id: u64) -> Message {
    // Crear el body para el resultado del PREPARE con los metadatos correspondientes
    let metadata = Metadata {
        flags: 0,
        columns_count: 0,
        global_table_spec: None,
        column_specs: vec![], // Vacío en este caso
    };

    let prepared_result = BodyPreparedResult {
        id: query_id,               // Convertimos el query_id a bytes
        metadata: metadata.clone(), // Metadata vacío en este caso
        result_metadata: metadata,  // Metadata del resultado también vacío
    };

    // Creamos el mensaje con el opcode de resultado y el body correspondiente
    Message {
        version: VERSION_RESPONSE,                        // Versión de la respuesta
        flags: 0,                                         // Flags
        stream: 1,             // Stream ID, debería ajustarse según corresponda
        opcode: OPCODE_RESULT, // El opcode es de tipo RESULT
        length: prepared_result.serialize().len() as u32, // Longitud del body serializado
        body: Body::PreparedResult(prepared_result), // Cuerpo del mensaje de respuesta
    }
}

pub fn create_response_auth_response(token: &[u8]) -> Message {
    let mut body: Vec<u8> = vec![];

    let token_len = token.len() as u32;
    body.extend_from_slice(&token_len.to_be_bytes());
    body.extend_from_slice(token);
    let auth_body = BodyAuthResponse { token: body }; //

    // Creamos el mensaje
    Message::new(
        VERSION_REQUEST,
        OPCODE_AUTH_RESPONSE,
        Body::AuthResponse(auth_body),
    )
}

pub fn create_request_authenticate_message() -> Message {
    let mut body: Vec<u8> = vec![];

    let authenticator = "SCRAM-SHA-256"; //cambiar el nombre del autenticador en caso de ser otro
    let authenticator_len = authenticator.len() as u32;
    body.extend_from_slice(&authenticator_len.to_be_bytes());
    body.extend_from_slice(authenticator.as_bytes());
    let auth_body = BodyAuthenticate { mechanism: body };

    // Creamos el mensaje
    Message::new(
        VERSION_RESPONSE,
        OPCODE_AUTHENTICATE,
        Body::Authenticate(auth_body),
    )
}

pub fn create_request_auth_challenge(token: &[u8]) -> Message {
    let mut body: Vec<u8> = vec![];

    let token_len = token.len() as u32;
    body.extend_from_slice(&token_len.to_be_bytes());
    body.extend_from_slice(token);
    let auth_body = BodyAuthTokenMaybeEmpty { token: body };
    Message::new(
        VERSION_RESPONSE,
        OPCODE_AUTH_CHALLENGE,
        Body::AuthChallenge(auth_body),
    )
}
/// Crea un mensaje de respuesta para la autenticación exitosa, incluyendo
/// el token de autenticación en el cuerpo del mensaje. El token se
/// precede por su longitud en bytes (32 bits) en formato big-endian.
pub fn create_response_auth_success(token: &[u8]) -> Message {
    let mut body: Vec<u8> = vec![];

    let token_len = token.len() as u32;
    body.extend_from_slice(&token_len.to_be_bytes());
    body.extend_from_slice(token);
    let auth_body = BodyAuthTokenMaybeEmpty { token: body };

    Message::new(
        VERSION_RESPONSE,
        OPCODE_AUTH_SUCCESS,
        Body::AuthSuccess(auth_body),
    )
}
