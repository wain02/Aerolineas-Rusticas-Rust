use crate::message;
use crate::message::Message;
use crate::message_functions::{
    self, body::Body, body_execute::BodyExecute, body_prepare::BodyPrepare, body_query::BodyQuery,
    body_rows::BodyRows, consistency::Consistency, query_parameters::QueryParameters,
};
use rustls::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::fs::File;
use std::io::{self, BufReader, Error, ErrorKind, Write};
use std::net::TcpStream;
use std::sync::Arc;

// Cargar certificados raíz (de los servidores) para verificar la autenticidad del servidor
pub fn load_root_certificates() -> Result<RootCertStore, std::io::Error> {
    let mut root_cert_store = RootCertStore::empty();

    // Cambiar al archivo correcto del certificado del servidor
    let cert_file = File::open("server.crt")?; // Cambiado a "server.crt"
    let mut reader = BufReader::new(cert_file);

    // Cargar certificados
    let certs = rustls_pemfile::certs(&mut reader)?;

    // Añadir los certificados al almacén de certificados raíz
    for cert in certs {
        root_cert_store
            .add(&rustls::Certificate(cert))
            .map_err(|_| Error::new(ErrorKind::InvalidData, "Certificado no válido"))?;
    }

    Ok(root_cert_store)
}

fn create_tls_connection(addr: &str) -> Result<StreamOwned<ClientConnection, TcpStream>, Error> {
    let root_cert_store = load_root_certificates()?;
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    let config = Arc::new(config);
    let server_name = ServerName::try_from("localhost")
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "Nombre del servidor no válido"))?;

    let stream = TcpStream::connect(addr)?;
    let client = ClientConnection::new(config, server_name).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("Error al crear conexión TLS: {:?}", e),
        )
    })?;
    Ok(StreamOwned::new(client, stream))
}

pub fn run_cliente() -> std::io::Result<()> {
    let addr = "localhost:8081";
    let mut tls_stream = match create_tls_connection(addr) {
        Ok(stream) => stream,
        Err(e) => {
            println!("Error al conectar al servidor: {:?}", e);
            return Err(e);
        }
    };

    println!("Escribe tu mensaje...");
    loop {
        let mut buffer = String::new();
        io::stdout().flush()?;
        io::stdin().read_line(&mut buffer)?;
        let mensaje = buffer.trim();

        match mensaje.to_uppercase().as_str() {
            message::TEXT_STARTUP => handle_startup_authenticate(&mut tls_stream)?,
            message::TEXT_QUERY => handle_client_query(&mut tls_stream)?,
            message::TEXT_PREPARE => {
                println!("Ingrese la query a preparar:");
                io::stdout().flush()?;
                let mut nueva_linea = String::new();
                io::stdin().read_line(&mut nueva_linea)?;
            }
            _ => println!("Comando no reconocido"),
        }
        println!("\n");
    }
}

fn handle_client_query(
    stream: &mut StreamOwned<rustls::ClientConnection, TcpStream>,
) -> std::io::Result<()> {
    println!("Ingrese la query:");
    io::stdout().flush()?;
    let mut nueva_linea = String::new();
    io::stdin().read_line(&mut nueva_linea)?;
    let query = nueva_linea.trim().replace("\"", "");
    println!("Nueva query ingresada: {}", query);

    if query.is_empty() {
        return Err(Error::new(
            std::io::ErrorKind::InvalidData,
            "Query Inválida",
        ));
    }
    println!("Procesando...");
    handle_query(stream, query)?;
    Ok(())
}

// Esta función maneja el proceso de autenticación del cliente enviando un mensaje de inicio al servidor y manejando la respuesta.
pub fn handle_startup(
    stream: &mut StreamOwned<rustls::ClientConnection, TcpStream>,
) -> Result<(), Error> {
    let startup_message = message::create_startup_message();

    println!("Mensaje STARTUP enviado");

    stream.write_all(&startup_message.serialize())?;
    stream.flush()?;

    let response = message::Message::deserialize(stream)?;
    handle_response(&response)?;

    if response.opcode == message::OPCODE_AUTHENTICATE {
        println!("El servidor solicita que se autentique\n");
        Ok(())
    } else {
        println!("Error: Se esperaba un mensaje de autenticación.");
        Err(Error::new(
            std::io::ErrorKind::InvalidData,
            "Error al recibir mensaje de autenticación",
        ))
    }
}

// Esta función maneja el proceso de autenticación del cliente después de enviar un mensaje de inicio al servidor,
// solicitando al usuario sus credenciales y realizando la autenticación.
pub fn handle_startup_authenticate(
    stream: &mut StreamOwned<rustls::ClientConnection, TcpStream>,
) -> Result<(), Error> {
    handle_startup(stream)?;
    let (usuario, password) = match request_user_credentials() {
        Ok((usuario, password)) => (usuario, password),
        Err(e) => {
            println!("Error al obtener usuario y contraseña: {}", e);
            return Err(e);
        }
    };
    match handle_authentication_request(stream, usuario, password) {
        Ok(()) => {
            println!("Autenticación exitosa");
            Ok(())
        }
        Err(e) => {
            println!("Error al autenticar: {:?}", e);
            Ok(())
        }
    }
}

// Esta función maneja la respuesta recibida del servidor, procesando diferentes códigos de operación
// para determinar la acción correspondiente y proporcionar retroalimentación al usuario.
pub fn handle_response(response: &message::Message) -> std::io::Result<()> {
    if response.version == message::VERSION_RESPONSE {
        match response.opcode {
            message::OPCODE_READY => {
                println!("Servidor listo (READY), conexión segura!\nYa puede autenticarse.")
            }
            message::OPCODE_QUERY => {
                handle_response_opcode_query(response);
            }
            message::OPCODE_AUTHENTICATE => println!("Autenticación requerida (AUTHENTICATE)"),
            message::OPCODE_ERROR => response.handle_error_message(),
            message::OPCODE_AUTH_SUCCESS => {
                println!("Autenticación exitosa (AUTH_SUCCESS)");
                println!("El servidor ha aceptado la autenticación.");
            }
            message::OPCODE_RESULT => {
                handle_response_opcode_result(response);
            }
            _ => println!("Opcode de respuesta desconocido: {}", response.opcode),
        }
    } else {
        println!("Se recibió una solicitud en lugar de una respuesta o no pertenece a la versión.");
    }
    Ok(())
}

fn handle_response_opcode_query(response: &message::Message) {
    println!("Respuesta a una query (QUERY)");
    // Verificamos si el body es de tipo Rows
    if let Body::Rows(body_rows) = &response.body {
        println!("Número de filas: {}", body_rows.rows_count);
        // Imprimir las columnas (ColumnSpecs)
        for (i, col_spec) in body_rows.metadata.column_specs.iter().enumerate() {
            println!("Columna {}: {}", i + 1, col_spec.name);
        }
        // Imprimir el contenido de cada fila
        for (i, row) in body_rows.rows_content.iter().enumerate() {
            println!("Fila {}:", i + 1);
            for (j, value) in row.values.iter().enumerate() {
                // Detectamos el tipo de la columna usando `column_specs`
                let col_spec = &body_rows.metadata.column_specs[j];
                let value_str = match col_spec.col_type {
                    0x0009 => {
                        // Int
                        if value.data.len() == 4 {
                            // Convertimos los 4 bytes a un `i32`
                            let int_value = i32::from_be_bytes(
                                value.data.clone().try_into().unwrap_or_else(|_| {
                                    eprintln!("Error: La longitud de data no es 4 bytes para convertir a i32.");
                                    [0; 4]
                                })
                            );
                            int_value.to_string()
                        } else {
                            "<valor no válido para Int>".to_string()
                        }
                    }
                    0x000D => {
                        // Varchar
                        String::from_utf8(value.data.clone())
                            .unwrap_or_else(|_| "<valor no imprimible>".to_string())
                    }
                    _ => "<tipo no soportado>".to_string(),
                };
                println!("  Columna {}: {}", j + 1, value_str);
            }
        }
    } else {
        println!("El cuerpo de la respuesta no es de tipo Rows.");
    }
}

fn handle_response_opcode_result(response: &message::Message) {
    match &response.body {
        message_functions::body::Body::Void(_) => {
            println!("Consulta exitosa, tipo de resultado: VOID");
        }
        Body::Rows(body_rows) => {
            println!("Consulta exitosa, tipo de resultado: ROWS");
            println!("Número de filas: {}", body_rows.rows_count);
            for (i, col_spec) in body_rows.metadata.column_specs.iter().enumerate() {
                println!("Columna {}: {}", i + 1, col_spec.name);
            }
            for (i, row) in body_rows.rows_content.iter().enumerate() {
                println!("Fila {}:", i + 1);
                for (j, value) in row.values.iter().enumerate() {
                    let value_str = String::from_utf8(value.data.clone())
                        .unwrap_or_else(|_| "<valor no imprimible>".to_string());
                    println!("  Columna {}: {}", j + 1, value_str);
                }
            }
        }
        Body::SetKeyspace(body_set_keyspace) => {
            println!("Consulta exitosa, tipo de resultado: KEYSPACE");
            println!("Keyspace seteado: {}", body_set_keyspace.keyspace);
        }
        Body::SchemaChange(body_schema_change) => {
            println!("Consulta exitosa, tipo de resultado: SchemaChange");
            println!("Tipo de cambio: {:?}", body_schema_change.change_type);
            println!("Objetivo: {:?}", body_schema_change.target);
            println!("Keyspace: {}", body_schema_change.keyspace);
        }
        Body::PreparedResult(body_prepared) => {
            println!("Consulta exitosa, tipo de resultado: PREPARED");
            println!("ID de la consulta preparada: {:?}", body_prepared.id);
        }
        _ => println!("Tipo de resultado desconocido o no manejado"),
    }
}

// Función para construir un mensaje de tipo Query
pub fn build_query_message(query: String) -> Message {
    let version = 0x03; // Versión del protocolo
    let flags = 0x00; // Sin flags
    let stream = 0x01; // Stream ID
    let opcode_query = 0x07; // Opcode para Query (0x07)

    // Convertir el query a bytes
    let query_bytes = query.as_bytes();
    let query_length = query_bytes.len() as u32;
    // Los parámetros solo incluirán el nivel de consistencia
    let query_parameters = QueryParameters {
        consistency: Consistency::One, // Consistencia pasada como parámetro
        flags: 0x00,                   // Sin opciones adicionales
        values: None,                  // Sin valores
        result_page_size: None,        // Sin tamaño de página
        paging_state: None,            // Sin paginación
        serial_consistency: None,      // Sin consistencia serial
        timestamp: None,               // Sin timestamp
    };
    let body_query = BodyQuery {
        query_string: query,
        parameters: query_parameters,
    };
    // El body tiene la longitud de la query string más los parámetros (en este caso, solo consistencia y flags)
    let body_length = query_length + 2; // 2 bytes adicionales para consistencia y flags
    Message {
        version,
        flags,
        stream,
        opcode: opcode_query,
        length: body_length,
        body: Body::Query(body_query),
    }
}

// Esta función maneja el envío de una consulta al servidor, serializando el mensaje de consulta
// y esperando la respuesta del servidor para procesarla.
pub fn handle_query(
    stream: &mut StreamOwned<rustls::ClientConnection, TcpStream>,
    query: String,
) -> std::io::Result<()> {
    let message = build_query_message(query);
    let serialized_message = message.serialize();

    // Verificar si la conexión sigue activa antes de escribir
    if stream.get_mut().peer_addr().is_err() {
        return Err(Error::new(
            ErrorKind::NotConnected,
            "Conexión perdida con el nodo",
        ));
    }

    // Forzar el stream a modo bloqueante (si no lo estaba)
    if let Err(e) = stream.get_mut().set_nonblocking(false) {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Error al cambiar a modo bloqueante: {}", e),
        ));
    }

    // Intentar escribir con reintentos en caso de EAGAIN
    let mut retries = 5;
    while retries > 0 {
        match stream.write_all(&serialized_message) {
            Ok(_) => break,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                eprintln!(
                    "Buffer lleno al escribir en el stream, reintentando... Intentos restantes: {}",
                    retries
                );
                std::thread::sleep(std::time::Duration::from_millis(100));
                retries -= 1;
            }
            Err(e) => {
                return Err(Error::new(
                    e.kind(),
                    format!("Error al escribir en el stream: {}", e),
                ));
            }
        }
    }
    if retries == 0 {
        return Err(Error::new(
            ErrorKind::TimedOut,
            "No se pudo escribir en el stream tras múltiples intentos",
        ));
    }

    // Intentar vaciar el buffer de escritura
    if let Err(e) = stream.flush() {
        return Err(Error::new(
            ErrorKind::Other,
            format!("Error al hacer flush del stream: {}", e),
        ));
    }

    // Intentar leer la respuesta del servidor
    let response = message::Message::deserialize(stream).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("Error al deserializar la respuesta del servidor: {}", e),
        )
    })?;

    // Manejar la respuesta
    handle_response(&response).map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("Error al manejar la respuesta: {}", e),
        )
    })?;

    Ok(())
}

// Esta función realiza la autenticación del usuario enviando las credenciales al servidor
// y manejando la respuesta del servidor para verificar el éxito de la autenticación.
pub fn handle_authentication_request(
    stream: &mut StreamOwned<rustls::ClientConnection, TcpStream>,
    user: String,
    password: String,
) -> Result<(), Error> {
    let token = format!("{}:{}", user, password).into_bytes();
    let auth_message: Message = message::create_response_auth_response(&token);
    println!("Mensaje AUTH_RESPONSE enviado");
    stream.write_all(&auth_message.serialize())?;
    stream.flush()?;
    let response = message::Message::deserialize(stream)?;
    handle_response(&response)?;

    if response.opcode == message::OPCODE_AUTH_CHALLENGE {
        let auth_string = format!("\0{}\0{}", user, password);
        let mechanism_response = auth_string.into_bytes();
        let auth_response = message::create_response_auth_response(&mechanism_response);
        println!("Enviando respuesta de autenticación");
        stream.write_all(&auth_response.serialize())?;
        stream.flush()?;
        let response = message::Message::deserialize(stream)?;
        match handle_response(&response) {
            Ok(()) => Ok(()),
            Err(e) => Err(e),
        }
    } else if response.opcode == message::OPCODE_AUTH_SUCCESS {
        return Ok(());
    } else if response.opcode == message::OPCODE_ERROR {
        Err(Error::new(
            std::io::ErrorKind::InvalidData,
            "Error al autenticar",
        ))
    } else {
        Ok(())
    }
}

pub fn request_user_credentials() -> std::io::Result<(String, String)> {
    println!("Inicializando el proceso de autenticación...");

    println!("Introduce tu usuario:");
    io::stdout().flush()?;
    let mut user = String::new();
    io::stdin().read_line(&mut user)?;
    let user = user.trim();

    println!("Introduce tu contraseña:");
    io::stdout().flush()?;
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    let password = password.trim(); // Elimina espacios en blanco y saltos de línea y convierte a String

    println!("Usuario y contraseña recibidos correctamente.");

    Ok((user.to_string(), password.to_string()))
}

// Esta función arma un mensaje para ejecutar una consulta preparada en el protocolo,
// utilizando el ID de la consulta como parámetro.
pub fn build_execute_message(query_id: u64) -> Message {
    let version = 0x03; // Versión del protocolo
    let flags = 0x00; // Sin flags adicionales
    let stream = 0x01; // Stream ID
    let opcode_execute = 0x0A; // Opcode para EXECUTE (0x0A)

    // Parámetros de la consulta
    let query_parameters = QueryParameters {
        consistency: Consistency::One, // Consistencia pasada como parámetro
        flags: 0x00,                   // Sin opciones adicionales
        values: None,                  // Sin valores
        result_page_size: None,        // Sin tamaño de página
        paging_state: None,            // Sin paginación
        serial_consistency: None,      // Sin consistencia serial
        timestamp: None,               // Sin timestamp
    };

    // Cuerpo del mensaje EXECUTE
    let body_execute = BodyExecute {
        query_id,                     // ID de la consulta preparada
        parameters: query_parameters, // Parámetros
    };

    // Calcular la longitud del body
    let body_length = 8 + 2 + 4 + 8; // Longitud del query_id (8 bytes), consistencia (2), flags, y valores

    // Retornar el mensaje completo
    Message {
        version,
        flags,
        stream,
        opcode: opcode_execute,
        length: body_length,
        body: Body::Execute(body_execute),
    }
}

// Función para construir un mensaje de tipo Prepare
pub fn build_prepare_message(query: String) -> Message {
    let version = 0x03; // Versión del protocolo
    let flags = 0x00; // Sin flags
    let stream = 0x01; // Stream ID
    let opcode_query = 0x09; // Opcode para Prepare (0x09)

    // Convertir la query a bytes
    let query_bytes = query.as_bytes();
    let query_length = query_bytes.len() as u32;

    // El body consiste en la longitud de la query más el string en sí mismo
    let body_length = query_length; // Longitud solo de la query string

    // Crear el body del mensaje
    let body_prepare = BodyPrepare {
        query_string: query,
    };

    // Crear el mensaje con la longitud del body
    Message {
        version,
        flags,
        stream,
        opcode: opcode_query,
        length: body_length,
        body: Body::Prepare(body_prepare),
    }
}

// Esta función se encarga de conectar al servidor utilizando una dirección IP,
// un usuario y una contraseña. Devuelve un TcpStream si la conexión y
// autenticación son exitosas.
pub fn ui_cliente(
    ip: &str,
    user: &String,
    password: &String,
) -> Result<StreamOwned<ClientConnection, TcpStream>, Error> {
    match create_tls_connection(ip) {
        Ok(mut socket) => {
            match handle_startup(&mut socket) {
                Ok(()) => {
                    println!("Startup exitoso");
                }
                Err(e) => {
                    println!("Error al autenticar: {:?}", e);
                    return Err(e);
                }
            }

            match handle_authentication_request(&mut socket, user.to_string(), password.to_string())
            {
                Ok(()) => {
                    println!("Autenticación exitosa");
                    Ok(socket)
                }
                Err(e) => {
                    println!("Error al autenticar: {:?}", e);
                    Err(e)
                }
            }
        }
        Err(e) => {
            println!("Error conectando con el servidor: {}", e);
            Err(e)
        }
    }
}

// Esta función maneja la ejecución de una consulta SQL a través de un socket TCP,
// enviando el mensaje correspondiente y recibiendo la respuesta.
pub fn handle_query_ui(
    socket: &mut StreamOwned<ClientConnection, TcpStream>,
    query: String,
) -> Result<Vec<Vec<String>>, Error> {
    let message = build_query_message(query);
    let serialized_message = message.serialize();
    socket.write_all(&serialized_message)?;
    socket.flush()?;
    let response = message::Message::deserialize(socket)?;
    match response.opcode {
        message::OPCODE_RESULT => match &response.body {
            Body::Rows(body_rows) => {
                println!("Consulta exitosa, tipo de resultado: ROWS");
                println!("Número de filas: {}", body_rows.rows_count);
                for (i, col_spec) in body_rows.metadata.column_specs.iter().enumerate() {
                    println!("Columna {}: {}", i + 1, col_spec.name);
                }
                let mut rows_vec = Vec::new();
                for (i, row) in body_rows.rows_content.iter().enumerate() {
                    let mut new_row = Vec::new();
                    println!("Fila {}:", i + 1);
                    for (j, value) in row.values.iter().enumerate() {
                        let value_str = String::from_utf8(value.data.clone())
                            .unwrap_or_else(|_| "<valor no imprimible>".to_string());
                        println!("  Columna {}: {}", j + 1, value_str);
                        new_row.push(value_str);
                    }
                    rows_vec.push(new_row);
                }
                Ok(rows_vec)
            }
            _ => Err(Error::new(
                std::io::ErrorKind::InvalidData,
                "Error: recibi una respuesta de no el tipo ROWS",
            )),
        },
        _ => Err(Error::new(
            std::io::ErrorKind::InvalidData,
            "Error al recibir la respuesta",
        )),
    }
}

/// Esta función imprime el contenido de las filas de un cuerpo de respuesta.
// Recibe un &BodyRows que contiene información sobre las filas y las columnas.
pub fn print_body_rows(body_rows: &BodyRows) -> Result<(), Error> {
    println!("Número de filas: {}", body_rows.rows_count);
    print!("| ");
    for col_spec in &body_rows.metadata.column_specs {
        print!("{:<15} | ", col_spec.name);
    }
    println!(
        "\n{}",
        "-".repeat(body_rows.metadata.columns_count as usize * 18)
    );
    for row in body_rows.rows_content.iter() {
        print!("| ");
        for (j, value) in row.values.iter().enumerate() {
            let col_spec = &body_rows.metadata.column_specs[j];
            let value_str = match col_spec.col_type {
                0x0009 => {
                    // Int
                    if value.data.len() == 4 {
                        let int_value = match value.data.clone().try_into() {
                            Ok(bytes) => i32::from_be_bytes(bytes),
                            Err(_) => {
                                eprintln!("Error: no se pudo convertir el array de bytes a un array de 4 elementos para i32.");
                                return Err(Error::new(
                                    ErrorKind::InvalidData,
                                    "Conversión fallida de bytes a i32",
                                ));
                            }
                        };
                        int_value.to_string()
                    } else {
                        "<valor inválido>".to_string()
                    }
                }
                0x000D => String::from_utf8(value.data.clone())
                    .unwrap_or_else(|_| "<valor no imprimible>".to_string()),
                _ => "<tipo no soportado>".to_string(),
            };

            print!("{:<15} | ", value_str);
        }
        println!();
    }
    Ok(())
}
