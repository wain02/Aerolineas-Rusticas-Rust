use crate::message::{
    create_prepared_result_message, create_request_auth_challenge,
    create_request_authenticate_message, create_response_auth_success, create_rows_message,
    create_schema_change_message, create_void_message, Message, OPCODES_VEC, OPCODE_RESULT,
    VERSION_RESPONSE,
};
use crate::message_functions::{body::Body, body_set_keyspace::BodySetKeyspace};
use crate::servidor_functions::{
    prepared_metadata::PreparedMetadata, prepared_store::PreparedStore,
};
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
//use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
//use bcrypt::{hash, DEFAULT_COST};
//use tp_aerolineas::archivo_hashear_contrasenas;
use crate::auth_challenge;
use crate::error_codes;
use crate::error_codes::ErrorCode;
use crate::message::{self};
//imposrts cassandra
use crate::nodo_cassandra::{
    self, enviar_mensaje_a_replicado, handle_nodo, handle_query_consistencia,
    handle_query_consistencia_restantes, handle_read_repair, Nodo,
};
use crate::threadpool_functions::threadpool;

//use env_logger;
use log::{debug, error, info, warn};
use rustls::{Certificate, PrivateKey, ServerConfig, ServerConnection, StreamOwned};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::net::{TcpListener, TcpStream};
//use flexi_logger::{Logger, WriteMode};
use chrono;
use flexi_logger::{FileSpec, Logger, WriteMode};

/// Estructura para encapsular los parámetros necesarios para `handle_client`.
pub struct HandleClientParameters<'a> {
    pub stream: &'a mut StreamOwned<ServerConnection, TcpStream>,
    pub login_authenticated: &'a mut bool,
    pub users: &'a HashMap<String, String>,
    pub user: &'a mut String,
    pub password: &'a mut String,
    pub prepared_store: &'a Arc<Mutex<PreparedStore>>,
    pub auth_success: &'a mut bool,
    pub nodo_actual: &'a mut Nodo,
    pub message: Message,
}

pub fn init_logger() -> Result<(), Box<dyn Error>> {
    // Definimos un FileSpec que almacene los logs en la carpeta "logs"
    let file_spec = FileSpec::default().directory("logs");

    Logger::try_with_str("info")? // Configura el nivel de logs (puede ser "debug", "trace", etc.)
        .log_to_file(file_spec)
        .write_mode(WriteMode::BufferAndFlush) // Escribe los logs con buffer para mayor eficiencia
        .duplicate_to_stdout(flexi_logger::Duplicate::Info)
        .format(|write, _now, record| {
            write!(
                write,
                "{} [{}] - {}",
                chrono::Local::now().format("%Y-%m-%d: %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .start()?;
    Ok(())
}

pub fn adapt_cluster(nodo: &Arc<Mutex<Nodo>>, cantidad_nodos: u8) -> io::Result<()> {
    let max_reintentos = 5;
    let mut intentos = 0;

    while intentos < max_reintentos {
        match nodo.lock() {
            Ok(nodo_lock) => {
                let mensaje = format!("ADAPT NODE TO: {} ;", cantidad_nodos);
                for nodo_address in &nodo_lock.shared_peers {
                    println!("\n\nAdaptando nodo: {}\n\n", nodo_address.address);
                    if nodo_lock.address != nodo_address.address {
                        if let Err(e) =
                            enviar_mensaje_a_replicado(mensaje.clone(), &nodo_address.address)
                        {
                            eprintln!("Error al enviar mensaje a nodo replicado: {:?}", e);
                        }
                    }
                }
                break;
            }
            Err(e) => {
                eprintln!("Error al bloquear el nodo: {:?}. Reintentando...", e);
                intentos += 1;
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
    match nodo.lock() {
        Ok(mut lock) => {
            info!("Reenviando todos los registros a los nodos replicados...");
            nodo_cassandra::reenviar_todos_registros_adapt(&mut lock)?;
        }
        Err(e) => {
            println!("Error al bloquear el nodo: {:?}", e);
            return Ok(());
        }
    };

    info!("Fin de adapt cluster");
    Ok(())
}

// Implementación principal del servidor
pub fn server_run(nodo: &mut Arc<Mutex<Nodo>>, cantidad_nodos: u8) -> io::Result<()> {
    init_logger().unwrap_or_else(|e| error!("Error al inicializar el logger: {:?}", e));
    info!(
        "Iniciando server_run con cantidad_nodos: {}",
        cantidad_nodos
    );
    debug!("checking credenctials");
    print!("Creando archivo de info de keyspaces");
    let archivo_info = "keyspaces_info/info.txt";
    let mut archivo = match File::create(archivo_info) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Error al crear el archivo {}: {:?}", archivo_info, e);
            return Ok(()); // Retorna Ok para que el programa continúe
        }
    };

    match write!(archivo, "{}", cantidad_nodos) {
        Ok(_) => {
            println!(
                "Archivo actualizado correctamente con cantidad_nodos: {}",
                cantidad_nodos
            );
        }
        Err(e) => {
            eprintln!("Error al escribir en el archivo {}: {:?}", archivo_info, e);
        }
    }

    print!("FIN archivo de info de keyspaces");

    // Cargar certificado y clave privada
    info!("Cargando certificado y clave privada...");
    let cert_file = File::open("server.crt")?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<Certificate> = certs(&mut cert_reader)?
        .into_iter()
        .map(Certificate)
        .collect();

    info!("Cargando clave privada...");
    let key_file = File::open("server.key")?;
    let mut key_reader = BufReader::new(key_file);
    let private_keys: Vec<PrivateKey> = pkcs8_private_keys(&mut key_reader)?
        .into_iter()
        .map(PrivateKey)
        .collect();

    if private_keys.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "No se encontró una clave privada en key.pem",
        ));
    }

    // Crear configuración TLS
    let server_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_keys[0].clone())
        .map_err(|e| {
            error!("Error al configurar TLS: {:?}", e);
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Error al configurar TLS")
        })?;
    let tls_config = Arc::new(server_config);

    // Hacer una copia de la dirección y el puerto del nodo
    let address = match nodo.lock() {
        Ok(n) => n.address.clone(),
        Err(e) => {
            error!("Error al bloquear el nodo: {:?}", e);
            return Ok(()); // Permite que el programa continúe sin interrumpirse
        }
    };
    let port = match nodo.lock() {
        Ok(n) => n.puerto.clone(),
        Err(e) => {
            error!("Error al bloquear el nodo: {:?}", e);
            return Ok(());
        }
    };
    let listener = TcpListener::bind(&address)?;
    info!("Servidor escuchando en: {:?}", &address);

    //  le aviso a los nodos el tamaño que tendra el cluster
    //adapt_cluster(nodo, cantidad_nodos)?; // esto tomi lo va a remplazar

    // Cargar usuarios
    let users = load_users("usuarios_database/usuarios.csv")?;
    //let prepared_store = Arc::new(Mutex::new(PreparedStore::new()));

    // Crear el ThreadPool con tamaño configurado
    let pool = threadpool::initialize_thread_pool()?;

    // Escuchar conexiones entrantes
    for stream in listener.incoming() {
        let mut stream = stream?;
        let tls_config = tls_config.clone();
        let usuarios = users.clone();
        let prepared_store = Arc::new(Mutex::new(PreparedStore::new()));
        let address_cloned = address.clone();
        let port_cloned = port.clone();

        let _ = pool.execute(move || {
            let nodo_actual = Arc::new(Mutex::new(Nodo::new(
                &address_cloned,
                &port_cloned,
                cantidad_nodos,
            )));

            let mut tls_connection = match rustls::ServerConnection::new(tls_config) {
                Ok(conn) => conn,
                Err(e) => {
                    error!("Error al crear conexión TLS: {:?}", e);
                    return;
                }
            };

            let mut stream = match tls_connection.complete_io(&mut stream) {
                Ok(_) => StreamOwned::new(tls_connection, stream),
                Err(e) => {
                    error!("Error al completar IO de la conexión TLS: {:?}", e);
                    return;
                }
            };

            let mut autentificado_ingreso = false;
            let mut auth_success = false;
            let mut user = String::new();
            let mut password = String::new();

            loop {
                let nodo_actual = Arc::clone(&nodo_actual);
                let mut nodo_lock = match nodo_actual.lock() {
                    Ok(lock) => lock,
                    Err(e) => {
                        error!("Error al bloquear nodo_actual: {:?}", e);
                        return;
                    }
                };

                nodo_lock.actualizar_keyspaces();

                let mut reader = BufReader::new(&mut stream);
                let mensaje = match Message::deserialize(&mut reader) {
                    Ok(msg) => msg,
                    Err(e) => {
                        if e.kind() == io::ErrorKind::UnexpectedEof {
                            break;
                        } else {
                            error!("Error al leer del cliente: {:?}", e);
                            break;
                        }
                    }
                };

                if mensaje.version == 0xFF
                    && mensaje.flags == 0xFF
                    && mensaje.stream == 0xFFFF
                    && mensaje.opcode == 0xFF
                {
                    let body = match mensaje.body {
                        Body::QueryNodoANodo(body) => body,
                        _ => {
                            error!("Error: el cuerpo no está en el formato correcto");
                            break;
                        }
                    };
                    if let Err(e) = handle_nodo(&mut stream, &mut nodo_lock, body) {
                        error!("Error al procesar mensaje de nodo: {:?}", e);
                        break;
                    }
                } else if let Err(e) = {
                    let params = HandleClientParameters {
                        stream: &mut stream,
                        login_authenticated: &mut autentificado_ingreso,
                        users: &usuarios,
                        user: &mut user,
                        password: &mut password,
                        prepared_store: &prepared_store,
                        auth_success: &mut auth_success,
                        nodo_actual: &mut nodo_lock,
                        message: mensaje,
                    };
                    handle_client(params)
                } {
                    if e.kind() != io::ErrorKind::UnexpectedEof {
                        error!("Error handling client: {:?}", e);
                    }
                    break;
                }
                //drop(nodo_lock);
            }
        });
    }

    Ok(())
}

fn handle_client(params: HandleClientParameters) -> std::io::Result<()> {
    let HandleClientParameters {
        stream,
        login_authenticated: autentificado_ingreso,
        users: usuarios,
        user: usuario,
        password: contrasena,
        prepared_store,
        auth_success,
        nodo_actual,
        message: mensaje,
    } = params;

    let mut header: [u8; 9] = [0; 9];
    header.copy_from_slice(&mensaje.serialize()[..9]);

    // Debug: Imprimir el mensaje completo
    //println!("Mensaje recibido: {:?}", mensaje);

    if has_error(header) {
        let error_code = return_error(header);
        send_error(stream, error_code)?;
        warn!("No es un mensaje de solicitud o no tiene bien la versión");
    } else {
        match mensaje.opcode {
            message::OPCODE_STARTUP => {
                hacer_startup(stream, autentificado_ingreso)?;
            }
            message::OPCODE_AUTH_RESPONSE => {
                auth_response_recibido(
                    stream,
                    autentificado_ingreso,
                    usuario,
                    contrasena,
                    mensaje,
                    usuarios,
                    auth_success,
                )?;
                info!("{:?}", auth_success);
            }
            message::OPCODE_EVENT => {
                info!("Mensaje OPCODE_EVENT recibido");
            }
            message::OPCODE_QUERY => {
                println!("mensaje query: {:?}", mensaje);
                hacer_query(
                    stream,
                    auth_success,
                    mensaje.body,
                    nodo_actual,
                    prepared_store.clone(),
                )?;
            }
            message::OPCODE_PREPARE => {
                info!("El mensaje es un prepare");
                println!("mensaje prepare: {:?}", mensaje);
                handle_prepare_request(stream, auth_success, mensaje.body, prepared_store.clone())?;
            }
            message::OPCODE_EXECUTE => {
                info!("El mensaje es un execute");
                println!("mensaje query: {:?}", mensaje);
                hacer_query(
                    stream,
                    auth_success,
                    mensaje.body,
                    nodo_actual,
                    prepared_store.clone(),
                )?;
            }
            _ => {
                warn!("Mensaje desconocido: opcode = {}", mensaje.version);
                send_error(stream, ErrorCode::ProtocolError)?;
            }
        }
    }
    Ok(())
}

fn hacer_authenticate(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    autentificado_ingreso: &mut bool,
    valido: bool,
) -> std::io::Result<()> {
    info!("Mensaje OPCODE_AUTH_RESPONSE recibido");
    if *autentificado_ingreso {
        warn!("Ya se encuentra autenticado el usuario");
        send_error(stream, error_codes::ErrorCode::ProtocolError)?;
    } else {
        verificar_auth_response_token(stream, autentificado_ingreso, valido)?;
    }
    Ok(())
}

fn auth_response_recibido(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    autentificado_ingreso: &mut bool,
    usuario: &mut String,
    contrasena: &mut String,
    mensaje: Message,
    usuarios: &HashMap<String, String>,
    auth_success: &mut bool,
) -> Result<(), std::io::Error> {
    if !*autentificado_ingreso {
        let body = match mensaje.body {
            Body::AuthResponse(body) => body,
            _ => {
                error!("Error: el cuerpo no está en el formato correcto");
                return Ok(());
            }
        };

        match validate_tokens(body.token.clone(), usuarios) {
            Ok((valido, nuevo_usuario, nueva_contrasena)) => {
                if valido {
                    *usuario = nuevo_usuario;
                    *contrasena = nueva_contrasena;
                }
                hacer_authenticate(stream, autentificado_ingreso, valido)?;
            }
            Err(e) => {
                error!("Error al validar tokens: {:?}", e);
                send_error(stream, e)?;
            }
        }
    } else {
        verificar_auth_challenge(stream, mensaje, usuario, contrasena, auth_success)?;
    }
    Ok(())
}
fn verificar_auth_response_token(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    autentificado_ingreso: &mut bool,
    valido: bool,
) -> std::io::Result<()> {
    if valido {
        *autentificado_ingreso = true;
        info!("Las credenciales son válidas");
        enviar_auth_challenge(stream)?
    } else {
        warn!("Error, credenciales invalidas");
        send_error(stream, error_codes::ErrorCode::BadCredentials)?;
    }
    Ok(())
}

fn enviar_auth_challenge(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
) -> std::io::Result<()> {
    let token_empty: Vec<u8> = Vec::new();
    info!("Enviando mensaje AUTH_CHALLENGE");
    send(stream, create_request_auth_challenge(&token_empty))?;
    Ok(())
}

fn hacer_startup(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    autentificado: &mut bool,
) -> std::io::Result<()> {
    info!("Mensaje STARTUP recibido");
    if *autentificado {
        info!("Ya se encuentra autenticado el usuario");
        send_error(stream, error_codes::ErrorCode::ProtocolError)?;
    } else {
        // Responder con READY (podemos simular autenticación aquí si es necesario)
        send(stream, create_request_authenticate_message())?;
    }
    Ok(())
}

fn verificar_auth_challenge(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    mensaje: Message,
    usuario: &mut String,
    contrasena: &mut String,
    auth_success: &mut bool,
) -> std::io::Result<()> {
    let body = match mensaje.body {
        Body::AuthResponse(body) => body,
        _ => {
            error!("Error: el cuerpo no está en el formato correcto");
            return Ok(());
        }
    };
    match auth_challenge::revisar_auth_challenge(
        extract_token(&body.token),
        usuario.to_string(),
        contrasena.to_string(),
    ) {
        Ok(()) => {
            let token_empty: Vec<u8> = Vec::new();
            *auth_success = true;
            send(stream, create_response_auth_success(&token_empty))?;
        }
        Err(e) => {
            error!("Error al autenticar: {:?}", e);
            send_error(stream, error_codes::ErrorCode::BadCredentials)?;
        }
    }
    Ok(())
}

// Envía mensaje al stream
fn send(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    message: crate::message::Message,
) -> std::io::Result<()> {
    //println!("Mensaje a enviar: {:?}", message);

    let serialized_message = message.serialize();
    //println!("Mensaje: {:?}", serialized_message);
    stream.write_all(&serialized_message)?;
    //println!("Mensaje enviado");
    stream.flush()?;
    Ok(())
}

fn hacer_query(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    autentificado: &mut bool,
    body: Body,
    nodo_actual: &mut Nodo,
    prepared_store: Arc<Mutex<PreparedStore>>,
) -> std::io::Result<()> {
    //println!("Contenido del body: {:?}", body);

    // Verificamos si está autenticado primero
    if !*autentificado {
        warn!("Error: cliente no autenticado. Se requiere autenticación para ejecutar queries.");
        send_error(stream, ErrorCode::Unauthorized)?;
        return Ok(());
    }
    nodo_actual.actualizar_keyspaces();

    // Manejar el cuerpo del mensaje
    match body {
        Body::Query(query_body) => {
            // Verificamos si la consulta es SELECT o no
            if query_body.query_string.to_uppercase().starts_with("USE ") {
                //CREATE
                //caso keyspace
                let keyspace = query_body.query_string[4..].trim().to_string();
                info!("Cambiando al keyspace: {}", keyspace);
                let set_keyspace_message = Message::new(
                    VERSION_RESPONSE,
                    OPCODE_RESULT,
                    Body::SetKeyspace(BodySetKeyspace { keyspace }),
                );
                send(stream, set_keyspace_message)?;
            } else if is_select_query(&query_body.query_string) {
                info!("Consulta SELECT recibida: {}", &query_body.query_string);
                match handle_query_consistencia(nodo_actual, query_body.query_string.clone()) {
                    Ok((csv_data, responses, ultimo_nodo)) => {
                        let rows_message: Message = create_rows_message(csv_data.as_str());
                        send(stream, rows_message)?;
                        let responses_restantes = handle_query_consistencia_restantes(
                            nodo_actual,
                            query_body.query_string.clone(),
                            ultimo_nodo,
                        )?;

                        let mut responses_totales: Vec<(String, String)> = Vec::new();
                        responses_totales.extend(responses);
                        responses_totales.extend(responses_restantes);

                        handle_read_repair(
                            nodo_actual,
                            responses_totales,
                            &query_body.query_string,
                        );
                    }
                    Err(e) => {
                        error!("Error al manejar la consulta: {:?}", e);
                        send_error(stream, ErrorCode::SyntaxError)?;
                    }
                }
            } else if is_change_type_query_valid(&query_body.query_string) {
                match handle_query_consistencia(nodo_actual, query_body.query_string.clone()) {
                    Ok((_, _, ultimo_nodo)) => {
                        let schema_change_message = create_schema_change_message();
                        send(stream, schema_change_message)?;
                        handle_query_consistencia_restantes(
                            nodo_actual,
                            query_body.query_string,
                            ultimo_nodo,
                        )?;
                    }
                    Err(e) => {
                        error!("Error al manejar la consulta: {:?}", e);
                        send_error(stream, ErrorCode::SyntaxError)?;
                    }
                }
            } else {
                match handle_query_consistencia(nodo_actual, query_body.query_string.clone()) {
                    Ok((_, _, ultimo_nodo)) => {
                        let void_message = create_void_message();
                        send(stream, void_message)?;
                        handle_query_consistencia_restantes(
                            nodo_actual,
                            query_body.query_string,
                            ultimo_nodo,
                        )?;
                    }
                    Err(e) => {
                        error!("Error al manejar la consulta: {:?}", e);
                        send_error(stream, ErrorCode::SyntaxError)?;
                    }
                }
            }
        }
        Body::Execute(body_execute) => {
            let prepared_id = body_execute.query_id; // ID de la consulta preparada
                                                     /*let query_parameters = body_execute.parameters; */ // Parámetros para la consulta

            let store = match prepared_store.lock() {
                Ok(lock) => lock,
                Err(e) => {
                    error!("Error al bloquear el prepared_store: {:?}", e);
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "Mutex envenenado",
                    ));
                }
            };

            if let Some(prepared_query) = store.get_prepared_query(prepared_id) {
                info!(
                    "Consulta preparada encontrada: {}",
                    prepared_query.query_string,
                );
                if prepared_query
                    .query_string
                    .to_uppercase()
                    .starts_with("USE ")
                {
                    //CREATE
                    //caso keyspace
                    let keyspace = prepared_query.query_string[4..].trim().to_string();
                    info!("Cambiando al keyspace: {}", keyspace);
                    let set_keyspace_message = Message::new(
                        VERSION_RESPONSE,
                        OPCODE_RESULT,
                        Body::SetKeyspace(BodySetKeyspace { keyspace }),
                    );
                    send(stream, set_keyspace_message)?;
                } else if is_select_query(&prepared_query.query_string) {
                    info!("Consulta SELECT recibida: {}", &prepared_query.query_string);
                    match handle_query_consistencia(
                        nodo_actual,
                        prepared_query.query_string.clone(),
                    ) {
                        Ok((csv_data, responses, ultimo_nodo)) => {
                            let rows_message: Message = create_rows_message(csv_data.as_str());
                            send(stream, rows_message)?;
                            let responses_restantes = handle_query_consistencia_restantes(
                                nodo_actual,
                                prepared_query.query_string.clone(),
                                ultimo_nodo,
                            )?;

                            let mut responses_totales: Vec<(String, String)> = Vec::new();
                            responses_totales.extend(responses);
                            responses_totales.extend(responses_restantes);

                            handle_read_repair(
                                nodo_actual,
                                responses_totales,
                                &prepared_query.query_string,
                            );
                        }
                        Err(e) => {
                            error!("Error al manejar la consulta: {:?}", e);
                            send_error(stream, ErrorCode::SyntaxError)?;
                        }
                    }
                } else if is_change_type_query_valid(&prepared_query.query_string) {
                    match handle_query_consistencia(
                        nodo_actual,
                        prepared_query.query_string.clone(),
                    ) {
                        Ok((_, _, ultimo_nodo)) => {
                            let schema_change_message = create_schema_change_message();
                            send(stream, schema_change_message)?;
                            handle_query_consistencia_restantes(
                                nodo_actual,
                                prepared_query.query_string.clone(),
                                ultimo_nodo,
                            )?;
                        }
                        Err(e) => {
                            error!("Error al manejar la consulta: {:?}", e);
                            send_error(stream, ErrorCode::SyntaxError)?;
                        }
                    }
                } else {
                    match handle_query_consistencia(
                        nodo_actual,
                        prepared_query.query_string.clone(),
                    ) {
                        Ok((_, _, ultimo_nodo)) => {
                            let void_message = create_void_message();
                            send(stream, void_message)?;
                            handle_query_consistencia_restantes(
                                nodo_actual,
                                prepared_query.query_string.clone(),
                                ultimo_nodo,
                            )?;
                        }
                        Err(e) => {
                            error!("Error al manejar la consulta: {:?}", e);
                            send_error(stream, ErrorCode::SyntaxError)?;
                        }
                    }
                }
            } else {
                error!("Error: ID de consulta preparada no encontrado.");
                send_error(stream, ErrorCode::ProtocolError)?;
            }
        }
        _ => {
            error!("Error: Se esperaba un cuerpo de tipo Query.");
            send_error(stream, ErrorCode::ProtocolError)?;
        }
    }

    Ok(())
}

fn send_error(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    error_code: ErrorCode,
) -> std::io::Result<()> {
    let mut body: String = String::new();

    let u16_error_code = error_code.to_u16();

    body.push_str(&u16_error_code.to_string());
    body.push(' ');

    let description_error = error_code.description();
    body.push_str(description_error);

    info!("Mensaje body a enviar: {:?}", body);

    let error_message = message::Message::new(
        message::VERSION_RESPONSE,
        message::OPCODE_ERROR,
        Body::Raw(body.into_bytes()),
    );

    error!("Mensaje ERROR a enviar: {:?}", error_message);

    stream.write_all(&error_message.serialize())?;
    error!("Mensaje ERROR enviado");

    Ok(())
}

fn has_error(header: [u8; 9]) -> bool {
    let version = header[0];
    let opcode: u8 = header[4];

    if version != message::VERSION_REQUEST {
        return true;
    }
    if !OPCODES_VEC.contains(&opcode) {
        return true;
    }
    false
}

fn return_error(header: [u8; 9]) -> ErrorCode {
    let version = header[0];
    let opcode: u8 = header[4];

    if version != message::VERSION_REQUEST {
        return ErrorCode::ProtocolError;
    }
    if !OPCODES_VEC.contains(&opcode) {
        return ErrorCode::SyntaxError;
    }
    ErrorCode::ServerError
}

fn is_select_query(query: &str) -> bool {
    if query.to_uppercase().starts_with("SELECT") {
        println!(" ");

        println!("Es una consulta SELECT.");
        true
    } else {
        println!("Consulta no es SELECT.");
        false
    }
}

fn is_change_type_query_valid(query: &str) -> bool {
    if query.to_uppercase().starts_with("CREATE") {
        println!(" ");

        println!("Es una consulta ChangeType.");
        true
    } else {
        println!("Consulta no es ChangeType.");
        false
    }
}

fn extract_token(body: &[u8]) -> Vec<u8> {
    // Leer los primeros 4 bytes para obtener el tamaño del token
    let token_len = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) as usize;

    // Extraer el token desde el cuerpo
    body[4..4 + token_len].to_vec()
}

fn split_token(body: Vec<u8>) -> Result<(String, String), ErrorCode> {
    let token = extract_token(body.as_slice());
    let binding = token.iter().map(|&c| c as char).collect::<String>();
    let parts: Vec<&str> = binding.split(':').collect();
    if parts.len() != 2 {
        return Err(error_codes::ErrorCode::BadCredentials);
    }

    let usuario = parts[0];
    let password = parts[1];

    Ok((usuario.to_string(), password.to_string()))
}

fn validate_tokens(
    body: Vec<u8>,
    usuarios: &HashMap<String, String>,
) -> Result<(bool, String, String), ErrorCode> {
    let (usuario, password) = match split_token(body) {
        Ok((usuario, password)) => (usuario, password),
        Err(_e) => return Err(error_codes::ErrorCode::BadCredentials),
    };
    if let Some(contrasena_almacenada) = usuarios.get(&usuario) {
        return Ok((password == *contrasena_almacenada, usuario, password));
    }

    Err(error_codes::ErrorCode::BadCredentials)
}

fn handle_prepare_request(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    autentificado: &mut bool,
    body: Body,
    prepared_store: Arc<Mutex<PreparedStore>>,
) -> std::io::Result<()> {
    if !*autentificado {
        error!("Error: cliente no autenticado. Se requiere autenticación para ejecutar PREPARE.");
        send_error(stream, ErrorCode::Unauthorized)?;
        return Ok(());
    }

    {
        let store = match prepared_store.lock() {
            Ok(lock) => lock,
            Err(e) => {
                error!("Error al bloquear el prepared_store: {:?}", e);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Mutex envenenado",
                ));
            }
        };
        info!(
            "Estado inicial del PreparedStore: {:?}",
            store.prepared_queries
        );
    }

    let body_prepare = match body {
        Body::Prepare(body_prepare) => body_prepare,
        _ => {
            error!("Error: Se esperaba un body de tipo PREPARE.");
            send_error(stream, ErrorCode::ProtocolError)?;
            return Ok(());
        }
    };

    info!("Consulta PREPARE recibida: {}", body_prepare.query_string);

    let mut store = match prepared_store.lock() {
        Ok(lock) => lock,
        Err(e) => {
            error!("Error al bloquear el prepared_store: {:?}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Mutex envenenado",
            ));
        }
    };
    let prepared_metadata = PreparedMetadata {
        consistency: "ONE".to_string(), // Puedes modificar esto según lo necesario
        parameters: vec![],             // Si tienes parámetros, los manejas aquí
    };

    let query_id = store.add_prepared_query(body_prepare.query_string.clone(), prepared_metadata);

    let prepared_result_message = create_prepared_result_message(query_id);

    send(stream, prepared_result_message)?;

    info!("Mensaje de PREPARE enviado con ID: {:?}", query_id);

    info!(
        "Estado final del PreparedStore: {:?}",
        store.prepared_queries
    );

    Ok(())
}

fn load_users(ruta_archivo: &str) -> io::Result<HashMap<String, String>> {
    let mut user_map: HashMap<String, String> = HashMap::new();

    let file = File::open(ruta_archivo)?;
    let reader = io::BufReader::new(file);
    for line in reader.lines() {
        let line = line?;
        let mut token = line.split(';');
        if let (Some(usuario), Some(hash_contraseña)) = (token.next(), token.next()) {
            user_map.insert(usuario.to_string(), hash_contraseña.to_string());
        }
    }
    Ok(user_map)
}
