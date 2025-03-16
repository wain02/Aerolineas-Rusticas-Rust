use crate::ejecutor::{ejecutar_adapt_message_reenviar, parsear_y_ejecutar_query}; // Importar la función del módulo ejecutor
use crate::error::print_error;
use crate::nodo_cassandra_functions::{
    keyspace::Keyspace, primary_key::PrimaryKey, replication_class::ReplicationClass,
    replication_config::ReplicationConfig, table::Table,
};
use crate::parser::{determine_query_type, QueryType};
use crate::parser_functions::{
    condicion_compuesta::CondicionCompuesta, consistency::Consistency,
    elemento_condicion_pila::ElementoCondicionPila, operator::Operator, query_insert::InsertQuery,
};
use log::info;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls::{ServerConnection, ServerName};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::hash::Hasher;
use std::io::{self, BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

type NodoInfo<'a> = Vec<(&'a str, &'a str, Vec<&'a str>, (u64, u64))>;
type NodoResponse = (String, Vec<(String, String)>, usize);
type IoResultNodoResponse = std::io::Result<NodoResponse>;

#[derive(Serialize, Deserialize, Debug)]
struct NodoConfig {
    nodos_type: String,
    nodos: Vec<NodoData>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodoData {
    pub address: String,
    pub puerto: String,
    replication_nodos: Vec<String>,
    pub token_range: [u64; 2],
}

fn iniciar_nodos(address: &str, cantidad_nodos: u8) -> Vec<Nodo> {
    // Carga el JSON directamente como una cadena en tiempo de compilación
    let json_content = include_str!("nodos_initialize.json");
    let nodos_config_json: Vec<NodoConfig> = match serde_json::from_str(json_content) {
        Ok(config) => config,
        Err(e) => {
            println!("Error al parsear nodos_initialize.json: {:?}", e);
            Vec::new()
        }
    };
    // Determina los nodos según la cantidad solicitada
    let nodos_config_json = match cantidad_nodos {
        4 => nodos_config_json
            .iter()
            .find(|n| n.nodos_type == "NODOS_4")
            .map(|n| n.nodos.clone())
            .unwrap_or(Vec::new()),
        5 => nodos_config_json
            .iter()
            .find(|n| n.nodos_type == "NODOS_5")
            .map(|n| n.nodos.clone())
            .unwrap_or(Vec::new()),
        6 => nodos_config_json
            .iter()
            .find(|n| n.nodos_type == "NODOS_6")
            .map(|n| n.nodos.clone())
            .unwrap_or(Vec::new()),
        7 => nodos_config_json
            .iter()
            .find(|n| n.nodos_type == "NODOS_7")
            .map(|n| n.nodos.clone())
            .unwrap_or(Vec::new()),
        8 => nodos_config_json
            .iter()
            .find(|n| n.nodos_type == "NODOS_8")
            .map(|n| n.nodos.clone())
            .unwrap_or(Vec::new()),
        _ => nodos_config_json
            .iter()
            .find(|n| n.nodos_type == "NODOS_6")
            .map(|n| n.nodos.clone())
            .unwrap_or(Vec::new()), // Default en caso de cantidad_nodos fuera de rango
    };

    // Transforma la configuración de nodos en un vector con la estructura adecuada
    let nodos_config: NodoInfo = nodos_config_json
        .iter()
        .map(|n| {
            (
                Box::leak(n.address.clone().into_boxed_str()) as &str,
                Box::leak(n.puerto.clone().into_boxed_str()) as &str,
                n.replication_nodos
                    .iter()
                    .map(|s| Box::leak(s.clone().into_boxed_str()) as &str)
                    .collect(),
                (n.token_range[0], n.token_range[1]),
            )
        })
        .collect();

    println!("Iniciando nodos: {:?}", nodos_config);

    let mut nodos = Vec::new();
    // Crea nodos basados en la configuración filtrada
    for nodo_valores in nodos_config.iter() {
        if nodo_valores.0 != address {
            let nodo = Nodo::new_sin_peers(nodo_valores.0, nodo_valores.1, cantidad_nodos);
            nodos.push(nodo);
        }
    }

    nodos
}
// Definición de Nodo
#[derive(Debug, Clone)]
pub struct Nodo {
    pub address: String,
    pub puerto: String,
    pub replication_nodos: Arc<Mutex<Vec<String>>>,
    pub shared_peers: Vec<Nodo>,
    pub token_range: (u64, u64),
    pub keyspaces: Vec<Keyspace>,
}

impl Nodo {
    /// Crea una nueva instancia de `Nodo` con una lista de peers compartidos inicializada.
    /// la cantidad de nodos que se le pasan como argumento esta entre 4 a 8
    pub fn new(address: &str, puerto: &str, cantidad_nodos: u8) -> Nodo {
        println!(
            "Iniciando nodo con dirección: {} y cantidad de nodos: {}",
            address, cantidad_nodos
        );

        // Carga el JSON directamente como una cadena en tiempo de compilación
        let json_content = include_str!("nodos_initialize.json");
        let nodos_config_json: Vec<NodoConfig> = match serde_json::from_str(json_content) {
            Ok(config) => config,
            Err(e) => {
                println!("Error al parsear nodos_initialize.json: {:?}", e);
                Vec::new()
            }
        };

        // Determina los nodos según la cantidad solicitada
        let nodos_config_json = match cantidad_nodos {
            4 => nodos_config_json
                .iter()
                .find(|n| n.nodos_type == "NODOS_4")
                .map(|n| n.nodos.clone())
                .unwrap_or(Vec::new()),
            5 => nodos_config_json
                .iter()
                .find(|n| n.nodos_type == "NODOS_5")
                .map(|n| n.nodos.clone())
                .unwrap_or(Vec::new()),
            6 => nodos_config_json
                .iter()
                .find(|n| n.nodos_type == "NODOS_6")
                .map(|n| n.nodos.clone())
                .unwrap_or(Vec::new()),
            7 => nodos_config_json
                .iter()
                .find(|n| n.nodos_type == "NODOS_7")
                .map(|n| n.nodos.clone())
                .unwrap_or(Vec::new()),
            8 => nodos_config_json
                .iter()
                .find(|n| n.nodos_type == "NODOS_8")
                .map(|n| n.nodos.clone())
                .unwrap_or(Vec::new()),
            _ => nodos_config_json
                .iter()
                .find(|n| n.nodos_type == "NODOS_6")
                .map(|n| n.nodos.clone())
                .unwrap_or(Vec::new()), // Default en caso de cantidad_nodos fuera de rango
        };

        let nodos: NodoInfo = nodos_config_json
            .iter()
            .map(|n| {
                (
                    Box::leak(n.address.clone().into_boxed_str()) as &str,
                    Box::leak(n.puerto.clone().into_boxed_str()) as &str,
                    n.replication_nodos
                        .iter()
                        .map(|s| Box::leak(s.clone().into_boxed_str()) as &str)
                        .collect(),
                    (n.token_range[0], n.token_range[1]),
                )
            })
            .collect();

        Nodo {
            address: address.to_string(),
            puerto: puerto.to_string(),
            replication_nodos: Arc::new(Mutex::new(
                nodos
                    .iter()
                    .find(|&&(ip, _, _, _)| ip == address)
                    .map(|(_, _, nodos, _)| nodos.iter().map(|&s| s.to_string()).collect())
                    .unwrap_or_else(Vec::new),
            )),
            shared_peers: iniciar_nodos(address, cantidad_nodos),
            token_range: nodos
                .iter()
                .find(|&&(ip, _, _, _)| ip == address)
                .map(|&(_, _, _, rango)| rango)
                .unwrap_or((0, 0)), // Default en caso de no encontrar coincidencia
            keyspaces: Vec::new(),
        }
    }

    /// Crea una nueva instancia de `Nodo` sin peers compartidos.
    pub fn new_sin_peers(address: &str, puerto: &str, cantidad_nodos: u8) -> Nodo {
        // Carga el JSON directamente como una cadena en tiempo de compilación
        let json_content = include_str!("nodos_initialize.json");
        let nodos_config_json: Vec<NodoConfig> = match serde_json::from_str(json_content) {
            Ok(config) => config,
            Err(e) => {
                println!("Error al parsear nodos_initialize.json: {:?}", e);
                Vec::new()
            }
        };

        // Determina los nodos según la cantidad solicitada
        let nodos_config_json = match cantidad_nodos {
            4 => nodos_config_json
                .iter()
                .find(|n| n.nodos_type == "NODOS_4")
                .map(|n| n.nodos.clone())
                .unwrap_or(Vec::new()),
            5 => nodos_config_json
                .iter()
                .find(|n| n.nodos_type == "NODOS_5")
                .map(|n| n.nodos.clone())
                .unwrap_or(Vec::new()),
            6 => nodos_config_json
                .iter()
                .find(|n| n.nodos_type == "NODOS_6")
                .map(|n| n.nodos.clone())
                .unwrap_or(Vec::new()),
            7 => nodos_config_json
                .iter()
                .find(|n| n.nodos_type == "NODOS_7")
                .map(|n| n.nodos.clone())
                .unwrap_or(Vec::new()),
            8 => nodos_config_json
                .iter()
                .find(|n| n.nodos_type == "NODOS_8")
                .map(|n| n.nodos.clone())
                .unwrap_or(Vec::new()),
            _ => nodos_config_json
                .iter()
                .find(|n| n.nodos_type == "NODOS_6")
                .map(|n| n.nodos.clone())
                .unwrap_or(Vec::new()), // Default en caso de cantidad_nodos fuera de rango
        };

        // Transforma la configuración de nodos en un vector con la estructura adecuada
        let nodos: NodoInfo = nodos_config_json
            .iter()
            .map(|n| {
                (
                    Box::leak(n.address.clone().into_boxed_str()) as &str,
                    Box::leak(n.puerto.clone().into_boxed_str()) as &str,
                    n.replication_nodos
                        .iter()
                        .map(|s| Box::leak(s.clone().into_boxed_str()) as &str)
                        .collect(),
                    (n.token_range[0], n.token_range[1]),
                )
            })
            .collect();

        Nodo {
            address: address.to_string(),
            puerto: puerto.to_string(),
            replication_nodos: Arc::new(Mutex::new(
                nodos
                    .iter()
                    .find(|&&(ip, _, _, _)| ip == address)
                    .map(|(_, _, nodos, _)| nodos.iter().map(|&s| s.to_string()).collect())
                    .unwrap_or_else(Vec::new),
            )),
            shared_peers: Vec::new(), // Dejar vacío el peers
            token_range: nodos
                .iter()
                .find(|&&(ip, _, _, _)| ip == address)
                .map(|&(_, _, _, rango)| rango)
                .unwrap_or((0, 0)), // Default en caso de no encontrar coincidencia
            keyspaces: Vec::new(),
        }
    }

    // Esta función lee y arma los keyspaces que hay en el nodo
    pub fn armar_keyspaces(&mut self, posible_cantidad: Option<u8>) -> Result<(), Box<dyn Error>> {
        let mut cantidad_nodos_en_cluster = read_actual_nodos_from_file();
        let mut contador = 0;
        while cantidad_nodos_en_cluster == 0 && contador <= 10 {
            cantidad_nodos_en_cluster = read_actual_nodos_from_file();
            contador += 1;
        }

        let cantidad_nodos = match posible_cantidad {
            None => cantidad_nodos_en_cluster,
            Some(cantidad) => cantidad,
        };

        if cantidad_nodos_en_cluster != cantidad_nodos {
            println!("Cantidad de nodos en el cluster no coincide con la cantidad de nodos en el archivo de configuración.");
        }
        let nodo_actual = Nodo::new(&self.address, &self.puerto, cantidad_nodos);

        *self = nodo_actual;

        // Obtener ruta absoluta al directorio "keyspaces_info"
        let keyspaces_info_path = std::env::current_dir()?.join("keyspaces_info");

        // Verificar si el directorio existe, si no, crearlo
        if !keyspaces_info_path.exists() {
            if let Err(_e) = fs::create_dir_all(&keyspaces_info_path) {
                return Ok(()); // Continuar sin detener la ejecución
            }
        }

        // Intentar leer el contenido del directorio
        let keyspaces_info_folder = match fs::read_dir(&keyspaces_info_path) {
            Ok(folder) => folder,
            Err(_e) => {
                return Ok(()); // Continuar sin detener la ejecución
            }
        };

        // Iterar sobre las carpetas dentro del directorio "keyspaces_info"
        for keyspace_folder in keyspaces_info_folder {
            let keyspace_path = keyspace_folder?.path();
            if keyspace_path.is_dir() {
                // Leer la información del keyspace desde su archivo info.txt
                let keyspace = leer_info_keyspace(&keyspace_path)?;
                self.keyspaces.push(keyspace);
            }
        }

        println!("Keyspaces armados exitosamente.");
        Ok(())
    }

    /// Actualiza la lista de `keyspaces` del nodo.
    pub fn actualizar_keyspaces(&mut self) {
        self.keyspaces.clear(); // Limpiar todos los keyspaces
        if let Err(e) = self.armar_keyspaces(None) {
            println!("Error al armar keyspaces: {:?}", e);
        }
        //println!("Keyspaces actualizados: {:?}", self.keyspaces);
    }

    /// Agrega un `keyspace` nuevo a la lista de `keyspaces` del nodo.
    pub fn agregar_keyspace(&mut self, keyspace: Keyspace) {
        self.keyspaces.push(keyspace);
    }
    /// Agrega una `table` a un `keyspace` existente en el nodo.
    ///
    /// Busca el `keyspace` con el nombre proporcionado en la lista de `keyspaces`. Si lo encuentra,
    /// inserta la nueva `table` en el `HashMap` de tablas dentro del `keyspace`.
    pub fn agregar_tabla(&mut self, keyspace_name: &str, table: Table) {
        if let Some(keyspace) = self.keyspaces.iter_mut().find(|k| k.name == keyspace_name) {
            keyspace.tables.insert(table.name.clone(), table);
        }
    }

    fn extraer_keyspace_tabla(
        &self,
        query_type: QueryType,
    ) -> Result<(String, String, Option<String>), String> {
        match query_type {
            QueryType::CreateTable(_) | QueryType::CreateKeyspace(_) => {
                // Para CREATE TABLE o CREATE KEYSPACE, devolvemos true directamente
                println!("Query es CREATE TABLE o CREATE KEYSPACE, devolviendo true.");
                Ok((String::new(), String::new(), None))
            }
            QueryType::Select(select_query) => {
                println!(
                    "Query es SELECT, keyspace: {}, tabla: {}",
                    select_query.keyspace, select_query.tabla
                );
                let partition_key_value =
                    self.obtener_valor_partition_key(&select_query.condiciones)?;
                Ok((
                    select_query.keyspace,
                    select_query.tabla,
                    partition_key_value,
                ))
            }
            QueryType::Insert(insert_query) => {
                println!(
                    "Query es INSERT, keyspace: {}, tabla: {}",
                    insert_query.keyspace, insert_query.tabla
                );
                let partition_key_value = self.obtener_valor_partition_key_insert(&insert_query)?;
                Ok((
                    insert_query.keyspace,
                    insert_query.tabla,
                    partition_key_value,
                ))
            }
            QueryType::Update(update_query) => {
                println!(
                    "Query es UPDATE, keyspace: {}, tabla: {}",
                    update_query.keyspace, update_query.tabla
                );
                let partition_key_value =
                    self.obtener_valor_partition_key(&update_query.condiciones)?;
                Ok((
                    update_query.keyspace,
                    update_query.tabla,
                    partition_key_value,
                ))
            }
            QueryType::Delete(delete_query) => {
                println!(
                    "Query es DELETE, keyspace: {}, tabla: {}",
                    delete_query.keyspace, delete_query.tabla
                );
                let partition_key_value =
                    self.obtener_valor_partition_key(&delete_query.condiciones)?;
                Ok((
                    delete_query.keyspace,
                    delete_query.tabla,
                    partition_key_value,
                ))
            }
            QueryType::Adapt(_) => Ok((String::new(), String::new(), None)),
        }
    }

    fn buscar_keyspace_table(
        &self,
        keyspace_name: &str,
        table_name: &str,
    ) -> Result<&Keyspace, String> {
        //println!("Buscando keyspace: {}", keyspace_name);
        //println!("Keyspaces en este nodo: {:?}", self.keyspaces);
        let keyspace = self
            .keyspaces
            .iter()
            .find(|ks| ks.name == keyspace_name)
            .ok_or_else(|| format!("Keyspace {} no encontrado en este nodo", keyspace_name))?;

        println!(
            "Buscando tabla: {} en keyspace: {}",
            table_name, keyspace_name
        );
        keyspace.tables.get(table_name).ok_or_else(|| {
            format!(
                "Tabla {} no encontrada en el keyspace {}",
                table_name, keyspace_name
            )
        })?;
        Ok(keyspace)
    }

    fn obtener_partition_key_hash_y_range(&self, partition_key_value: Option<String>) -> bool {
        let partition_key_str =
            partition_key_value.unwrap_or_else(|| "default_partition_key".to_string());
        //println!("Partition key value: {}", partition_key_str);
        let partition_key_hash = hash_partition_key(&partition_key_str);
        //println!("Hash de la partition key: {}", partition_key_hash);

        // 6. Verificar si el hash está dentro del rango de tokens del nodo
        if self.token_range.0 == 0 && self.token_range.1 == 0 {
            return false;
        }

        if self.token_range.0 < self.token_range.1 {
            // Rango normal
            self.token_range.0 <= partition_key_hash && partition_key_hash < self.token_range.1
        } else {
            // Rango cruzando el máximo
            (self.token_range.0 <= partition_key_hash)
                || (/*0 <= partition_key_hash &&*/partition_key_hash < self.token_range.1)
        }

        //println!("Resultado de la verificación: {}", resultado);
    }

    /// Determina si una consulta (`query_str`) corresponde al nodo actual basado en el keyspace,
    /// tabla y valor de la clave de partición.
    pub fn corresponde_a_este_nodo(&mut self, query_str: String) -> Result<bool, String> {
        self.actualizar_keyspaces();
        // 1. Parsear la query usando tipo_query()
        //println!("Parsing query: {}", query_str);
        let query_type = determine_query_type(&query_str)
            .map_err(|e| format!("Error al parsear la query: {:?}", e))?;

        if let QueryType::Adapt(_) = query_type {
            return Ok(true);
        }
        // 2. Extraer el keyspace y tabla según el tipo de query
        let (keyspace_name, table_name, partition_key_value) =
            self.extraer_keyspace_tabla(query_type)?;
        if keyspace_name.is_empty() && table_name.is_empty() && partition_key_value.is_none() {
            return Ok(true); // Si es CREATE TABLE o CREATE KEYSPACE, devolver true
        }

        // 3. Buscar el keyspace dentro del nodo
        // 4. Buscar la tabla dentro del keyspace
        let _keyspace = self.buscar_keyspace_table(&keyspace_name, &table_name)?;

        // 5. Obtener el hash del valor de la partition key
        let resultado = self.obtener_partition_key_hash_y_range(partition_key_value);
        Ok(resultado)
    }

    // Función para obtener el valor de la partition key desde las condiciones
    fn obtener_valor_partition_key(
        &self,
        condiciones: &CondicionCompuesta,
    ) -> Result<Option<String>, String> {
        for elemento in &condiciones.pila_condiciones {
            if let ElementoCondicionPila::SimpleCondition(cond) = elemento {
                if cond.operador == Operator::Equal && cond.valor.is_some() {
                    return Ok(cond.valor.clone());
                }
            }
        }
        Err("No se encontró la clave de partición en las condiciones".to_string())
    }

    // Función para obtener el valor de la partition key en un INSERT
    fn obtener_valor_partition_key_insert(
        &self,
        insert_query: &InsertQuery,
    ) -> Result<Option<String>, String> {
        // Suponiendo que la partition key es la primera columna
        let partition_key_value = insert_query
            .valores
            .first()
            .and_then(|row| row.first())
            .cloned();
        if partition_key_value.is_none() {
            return Err("No se encontró valor para la clave de partición en el INSERT".to_string());
        }
        Ok(partition_key_value)
    }
}

fn load_tls_config() -> Result<Arc<ClientConfig>, std::io::Error> {
    let mut root_cert_store = RootCertStore::empty();

    // Cambiar al archivo correcto del certificado del servidor
    let cert_file = File::open("server.crt")?; // Cambiado a "server.crt"
    let mut reader = BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut reader)?;

    // Añadir los certificados al almacén de certificados raíz
    for cert in certs {
        root_cert_store
            .add(&rustls::Certificate(cert))
            .map_err(|_| std::io::Error::new(ErrorKind::InvalidData, "Certificado no válido"))?;
    }
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

fn connect_to_node_with_tls(
    address: &str,
) -> Result<StreamOwned<ClientConnection, TcpStream>, std::io::Error> {
    let config = load_tls_config()?;
    let server_name = ServerName::try_from("localhost").map_err(|_| {
        std::io::Error::new(ErrorKind::InvalidInput, "Nombre del servidor no válido")
    })?;

    // Establecer conexión TCP
    let stream = TcpStream::connect(address)?;
    let client = ClientConnection::new(config, server_name).map_err(|e| {
        std::io::Error::new(
            ErrorKind::InvalidData,
            format!("Error al crear conexión TLS: {:?}", e),
        )
    })?;

    Ok(StreamOwned::new(client, stream))
}

fn ejecutar_query_en_nodo_actual_consistencia(
    query: String,
    nodo_actual: &mut Nodo,
) -> IoResultNodoResponse {
    println!("Query SI me corresponde ");
    let mut responses;
    let last_node;
    //hago una asamblea y le pregunto a mis replicados que tienen
    if query.contains("CREATE TABLE") || query.contains("CREATE KEYSPACE") {
        println!("Query de creación, ejecutada localmente y a todos");
        let (responses_vec, last_node_pos) =
            reenviar_a_nodos_correspondientes_consistencia(&query, nodo_actual);
        responses = responses_vec;
        last_node = last_node_pos;
    } else {
        // No es un query de creación
        println!("Query no de creación, ejecutada localmente y a todos");
        let (responses_vec, last_node_pos) =
            reenviar_a_nodos_replicados_consistencia(&query, nodo_actual);
        responses = responses_vec;
        last_node = last_node_pos;
    }
    // Ejecutar el query localmente
    match parsear_y_ejecutar_query(&query, &mut nodo_actual.clone()) {
        Ok(resultado_local) => {
            println!("1.Ejecutada localmente, Respuesta: {:?}", resultado_local);

            let response;
            if query.to_uppercase().contains("SELECT") {
                // cambio los saltos de linea por //////.
                let mut resultado_local = resultado_local.replace("\n", "//////");
                resultado_local.push('\n');
                responses.push((nodo_actual.address.clone(), resultado_local.clone()));
                let responses_sin_adress: Vec<String> =
                    responses.iter().map(|(_, val)| val.clone()).collect();
                response = realizar_quorum(responses_sin_adress);
                println!("el quorum fue: {:?}", response);
            } else {
                response = resultado_local;
            }
            println!("Respuesta final: {:?}", response);
            Ok((response, responses, last_node))
        }
        Err(e) => {
            let error_message = format!("Error: {:?}", e);
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                error_message,
            ))
        }
    }
}
fn ejecutar_query_en_nodo_actual_consistencia_restantes(
    query: String,
    nodo_actual: &mut Nodo,
    ultimo_nodo: usize,
) -> std::io::Result<Vec<(String, String)>> {
    println!("Query SI me corresponde ");
    let mut responses;

    //hago una asamblea y le pregunto a mis replicados que tienen
    if query.contains("CREATE TABLE") || query.contains("CREATE KEYSPACE") {
        println!("Query de creación, ejecutada localmente y a todos");
        responses = reenviar_a_nodos_correspondientes_consistencia_restantes(
            &query,
            nodo_actual,
            ultimo_nodo,
        );
    } else {
        // No es un query de creación
        println!("Query no de creación, ejecutada localmente y a todos");
        responses =
            reenviar_a_nodos_replicados_consistencia_restantes(&query, nodo_actual, ultimo_nodo);
    }
    // Ejecutar el query localmente
    match parsear_y_ejecutar_query(&query, &mut nodo_actual.clone()) {
        Ok(resultado_local) => {
            println!("2.Ejecutada localmente, Respuesta: {:?}", resultado_local);
            if query.to_uppercase().contains("SELECT") {
                // cambio los saltos de linea por //////
                let mut resultado_local = resultado_local.replace("\n", "//////");
                resultado_local.push('\n');
                responses.push((
                    nodo_actual.address.clone(),
                    resultado_local.trim().to_string().clone(),
                ));
            }
            println!("2.Respuesta final: {:?}", resultado_local);
            println!("3.Respuesta final: {:?}", responses);
            Ok(responses)
        }
        Err(e) => {
            let error_message = format!("Error: {:?}", e);
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                error_message,
            ))
        }
    }
}

/// Maneja una consulta entrante, determinando si el nodo actual es responsable de procesarla.
/// Si corresponde, la ejecuta en el nodo actual; de lo contrario, la reenvía a los nodos correspondientes.
pub fn handle_query_consistencia(nodo_actual: &mut Nodo, query: String) -> IoResultNodoResponse {
    nodo_actual.actualizar_keyspaces();

    println!("Query recibida en handle query: {:?}", query);
    nodo_actual.actualizar_keyspaces();
    match nodo_actual.corresponde_a_este_nodo(query.to_string()) {
        Ok(true) => {
            let (response, responses, ultimo_nodo) =
                ejecutar_query_en_nodo_actual_consistencia(query, nodo_actual)?;
            Ok((response, responses, ultimo_nodo))
        }
        Ok(false) => {
            println!("Query NO me corresponde, reenviada a nodos que sí le corresponden.");
            let (responses, ultimo_nodo) =
                reenviar_a_nodos_correspondientes_consistencia(&query, nodo_actual);
            let responses_sin_adress: Vec<String> =
                responses.iter().map(|(_, val)| val.clone()).collect();
            let response = realizar_quorum(responses_sin_adress);
            Ok((response, responses, ultimo_nodo))
        }
        Err(e) => {
            let error_message = format!("Error: {}", e);
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                error_message,
            ))
        }
    }
}
/// Maneja una consulta entrante, determinando si el nodo actual es responsable de procesarla.
/// Si corresponde, la ejecuta en el nodo actual; de lo contrario, la reenvía a los nodos correspondientes.
pub fn handle_query_consistencia_restantes(
    nodo_actual: &mut Nodo,
    query: String,
    ultimo_nodo: usize,
) -> std::io::Result<Vec<(String, String)>> {
    nodo_actual.actualizar_keyspaces();

    println!("Query recibida en handle query: {:?}", query);
    nodo_actual.actualizar_keyspaces();
    match nodo_actual.corresponde_a_este_nodo(query.to_string()) {
        Ok(true) => {
            let responses = ejecutar_query_en_nodo_actual_consistencia_restantes(
                query,
                nodo_actual,
                ultimo_nodo,
            )?;
            Ok(responses)
        }
        Ok(false) => {
            println!("Query NO me correspode, reenviada a nodos que si le corresponden ");
            // Reenviar query a nodos que les correspondan
            let responses = reenviar_a_nodos_correspondientes_consistencia_restantes(
                &query,
                nodo_actual,
                ultimo_nodo,
            );
            println!(
                "Reenvie a los nodos que si debian ejecutarlo, las respuestas fueron: {:?}",
                responses
            );
            println!(
                "Respuestas de los nodos correspondientes restantes: {:?}",
                responses
            );

            Ok(responses)
        }
        Err(e) => {
            let error_message = format!("Error: {}", e);
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                error_message,
            ))
        }
    }
}

fn realizar_quorum(responses: Vec<String>) -> String {
    use std::collections::HashMap;

    let mut frequency_map = HashMap::new();
    let mut max_count = 0;
    let mut quorum_value = String::new();

    // Contar las ocurrencias de cada string en el vector
    for response in &responses {
        let count = frequency_map.entry(response.clone()).or_insert(0);
        *count += 1;

        // Si este string tiene más ocurrencias que el máximo actual, actualizar
        if *count > max_count {
            max_count = *count;
            quorum_value = response.clone(); // Guardar el string más frecuente
        }
    }

    // Si no hay un valor que se repita, devolver el último string
    if max_count > 1 {
        quorum_value
    } else {
        // responses.last().cloned().unwrap_or_default() // Devolver el último o vacío si el vector está vacío
        quorum_value
    }
}

fn realizar_quorum_read_reapir(responses: Vec<String>) -> String {
    use std::collections::HashMap;

    let mut frequency_map = HashMap::new();
    let mut max_count = 0;
    let mut quorum_value = String::new();

    // Contar las ocurrencias de cada string en el vector
    for response in &responses {
        let count = frequency_map.entry(response.clone()).or_insert(0);
        *count += 1;

        // Si este string tiene más ocurrencias que el máximo actual, actualizar
        if *count > max_count {
            max_count = *count;
            quorum_value = response.clone(); // Guardar el string más frecuente
        }
    }

    // Si no hay un valor que se repita, devolver el último string
    if max_count > 1 {
        quorum_value
    } else {
        // responses.last().cloned().unwrap_or_default() // Devolver el último o vacío si el vector está vacío
        quorum_value
    }
}
fn construir_tabla_desde_info(
    keyspace_name: &str,
    table_name: &str,
    nodo_actual: &mut Nodo,
) -> Result<(), Box<dyn Error>> {
    // Ruta del archivo de información
    let archivo_ruta_info = format!("keyspaces_info/{}/{}.txt", keyspace_name, table_name);

    // Leer el contenido del archivo
    println!("[INFO] Leyendo el archivo: {}", archivo_ruta_info);
    let contenido = fs::read_to_string(&archivo_ruta_info)?;
    println!("[INFO] Contenido del archivo:\n{}", contenido);

    // Extraer columnas y clave primaria del archivo
    let mut columnas = String::new();
    let mut partition_keys = Vec::new();
    let mut clustering_keys = Vec::new();

    for linea in contenido.lines() {
        if let Some(stripped) = linea.strip_prefix("Columns:") {
            columnas = stripped.trim().to_string();
        } else if let Some(stripped) = linea.strip_prefix("Partition Key:") {
            let partition_key = stripped
                .trim()
                .trim_matches(['[', ']'].as_ref())
                .to_string();
            if !partition_key.is_empty() {
                partition_keys.push(partition_key);
            }
        } else if let Some(stripped) = linea.strip_prefix("Clustering Key:") {
            let clustering_key = stripped
                .trim()
                .trim_matches(['[', ']'].as_ref())
                .to_string();
            if !clustering_key.is_empty() {
                clustering_keys.push(clustering_key);
            }
        }
    }

    // Validar que se hayan extraído datos necesarios
    if columnas.is_empty() {
        return Err(Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            "El archivo no contiene columnas o clave primaria válidas.",
        )));
    }

    // Construir la consulta `CREATE TABLE`
    let create_table_query = format!(
        "CREATE TABLE {}.{} ({}, PRIMARY KEY (({}), {}));",
        keyspace_name,
        table_name,
        columnas,
        partition_keys.join(", "),
        clustering_keys.join(", ")
    );
    println!(
        "[INFO] Consulta CREATE TABLE generada:\n{}",
        create_table_query
    );

    match handle_query_consistencia(nodo_actual, create_table_query.clone()) {
        Ok((_, _, ultimo_nodo)) => {
            handle_query_consistencia_restantes(
                nodo_actual,
                create_table_query.clone(),
                ultimo_nodo,
            )?;
        }
        Err(e) => {
            println!("Error al manejar la consulta: {:?}", e);
        }
    }

    println!(
        "[INFO] Proceso completado con éxito para la tabla: {}.{}",
        keyspace_name, table_name
    );
    Ok(())
}

pub fn change_token_range(cantidad_nodos: u8) -> io::Result<()> {
    println!("Cambiando el rango de tokens del nodo...");
    let archivo_info = "keyspaces_info/info.txt";

    let mut archivo = match File::create(archivo_info) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("Error al crear el archivo {}: {:?}", archivo_info, e);
            return Ok(()); // Retorna Ok para no interrumpir el programa
        }
    };

    let cantidad_nueva = cantidad_nodos;

    match writeln!(archivo, "{}", cantidad_nueva) {
        Ok(_) => {
            println!(
                "Cambio finalizado del keyspaces_info/info.txt con el valor de {}",
                cantidad_nueva
            );
        }
        Err(e) => {
            eprintln!("Error al escribir en el archivo {}: {:?}", archivo_info, e);
        }
    }

    Ok(())
}

pub fn reenviar_todos_registros_adapt(nodo_actual: &mut Nodo) -> std::io::Result<()> {
    let keyspaces = nodo_actual.keyspaces.clone();

    for keyspace in &keyspaces {
        println!("Debug 1: Reenviando keyspaces {}", keyspace.name);
        reenviar_keyspace(keyspace, nodo_actual)?;
        println!("Debug 1: Fin reenviar keyspaces {}", keyspace.name);

        for (table_name, table) in &keyspace.tables {
            // Ruta del archivo original
            let tabla_data = format!("{}/{}.csv", keyspace.name, table_name);

            // Ruta del archivo de copia
            let copia_tabla = format!("{}/{}_copia.csv", keyspace.name, table_name);

            // Copiar archivo
            fs::copy(&tabla_data, &copia_tabla).map_err(|e| {
                eprintln!(
                    "Error al copiar archivo de {} a {}: {}",
                    tabla_data, copia_tabla, e
                );
                e
            })?;

            if let Err(e) = construir_tabla_desde_info(&keyspace.name, table_name, nodo_actual) {
                eprintln!("Error al construir la tabla desde info: {:?}", e);
            }

            // Copiar archivo
            fs::copy(&copia_tabla, &tabla_data).map_err(|e| {
                eprintln!(
                    "Error al copiar archivo de {} a {}: {}",
                    tabla_data, tabla_data, e
                );
                e
            })?;

            if let Err(e) = procesar_archivo_tabla(&keyspace.name, table_name, table, nodo_actual) {
                eprintln!(
                    "Error al procesar tabla {}.{}: {:?}",
                    keyspace.name, table_name, e
                );
            }
            println!("Fin procesar archivo tabla");
            // Eliminar archivo de copia
            fs::remove_file(&copia_tabla).map_err(|e| {
                eprintln!("Error al eliminar archivo de copia {}: {}", copia_tabla, e);
                e
            })?;
        }
    }

    Ok(())
}

fn reenviar_keyspace(keyspace: &Keyspace, nodo_actual: &mut Nodo) -> std::io::Result<()> {
    let create_keyspace_query = format!(
        "CREATE KEYSPACE {} WITH REPLICATION = {{'class': 'SimpleStrategy', 'replication_factor': '3'}};",
        keyspace.name
    );

    match handle_query_consistencia(nodo_actual, create_keyspace_query.clone()) {
        Ok((_, _, ultimo_nodo)) => {
            handle_query_consistencia_restantes(
                nodo_actual,
                create_keyspace_query.clone(),
                ultimo_nodo,
            )?;
        }
        Err(e) => {
            println!("Error al manejar la consulta: {:?}", e);
        }
    }
    Ok(())
}

fn procesar_archivo_tabla(
    keyspace_name: &str,
    table_name: &str,
    table: &Table,
    nodo_actual: &mut Nodo,
) -> std::io::Result<()> {
    let archivo_ruta = format!("{}/{}_copia.csv", keyspace_name, table_name);
    let archivo_tabla = File::open(&archivo_ruta).map_err(|e| {
        eprintln!("Error al abrir archivo {}: {}", archivo_ruta, e);
        e
    })?;

    let reader = io::BufReader::new(archivo_tabla);
    let mut lineas = reader.lines();

    let nombres_columnas = match lineas.next() {
        Some(Ok(linea)) => linea,
        _ => {
            eprintln!("Archivo {} no contiene columnas válidas.", archivo_ruta);
            return Ok(());
        }
    };

    for linea in lineas {
        if let Ok(linea_datos) = linea {
            procesar_linea_tabla(
                keyspace_name,
                table_name,
                &nombres_columnas,
                &linea_datos,
                table,
                nodo_actual,
            );
        } else {
            eprintln!("Error al procesar línea en archivo {}.", archivo_ruta);
        }
    }

    Ok(())
}

fn procesar_linea_tabla(
    keyspace_name: &str,
    table_name: &str,
    nombres_columnas: &str,
    linea_datos: &str,
    _table: &Table,
    nodo_actual: &mut Nodo,
) {
    let valores: Vec<String> = linea_datos
        .split(',')
        .take(linea_datos.split(',').count() - 1)
        .map(|valor| format!("'{}'", valor.trim()))
        .collect();

    let insert_query = format!(
        "INSERT INTO {}.{} ({}) USING CONSISTENCY QUORUM VALUES ({});",
        keyspace_name,
        table_name,
        nombres_columnas,
        valores.join(", ")
    );

    println!("Insert query en adapt: {:?}", insert_query);

    match handle_query_consistencia(nodo_actual, insert_query.clone()) {
        Ok((_, _, ultimo_nodo)) => {
            let _ =
                handle_query_consistencia_restantes(nodo_actual, insert_query.clone(), ultimo_nodo);
        }
        Err(e) => {
            println!("Error al manejar la consulta: {:?}", e);
        }
    }
    println!("paso a sigueinte fase des procesar_linea_tabla");

    if let Ok(false) = nodo_actual.corresponde_a_este_nodo(insert_query.clone()) {
        let nombres_columnas: Vec<&str> = nombres_columnas.split(',').collect();
        let valores: Vec<&str> = linea_datos.split(',').collect();
        let condiciones: Vec<String> = nombres_columnas
            .iter()
            .zip(valores.iter())
            .map(|(col, val)| format!("{} = '{}'", col.trim(), val.trim()))
            .collect();

        let delete_query = format!(
            "DELETE FROM {}.{} USING CONSISTENCY QUORUM WHERE {};",
            keyspace_name,
            table_name,
            condiciones.join(" AND ")
        );

        println!("\n Delete query en adapt: {:?}\n", delete_query);

        if let Err(e) = parsear_y_ejecutar_query(&delete_query, nodo_actual) {
            eprintln!("Error al ejecutar DELETE query: {:?}", e);
        }
    }
}

pub fn read_actual_nodos_from_file() -> u8 {
    let archivo_info: &str = "keyspaces_info/info.txt";
    let max_reintentos = 5;
    let mut intentos = 0;

    while intentos < max_reintentos {
        match File::open(archivo_info) {
            Ok(mut archivo) => {
                let mut contenido = String::new();
                if let Err(e) = archivo.read_to_string(&mut contenido) {
                    eprintln!(
                        "Error al leer el archivo {}: {:?}. Reintentando...",
                        archivo_info, e
                    );
                } else if let Ok(cantidad_nodos) = contenido.trim().parse::<u8>() {
                    return cantidad_nodos;
                } else {
                    eprintln!("Error al parsear la cantidad de nodos. Reintentando...");
                }
            }
            Err(e) => eprintln!(
                "Error al abrir el archivo {}: {:?}. Reintentando...",
                archivo_info, e
            ),
        }

        intentos += 1;
        thread::sleep(Duration::from_secs(1)); // Espera 1 segundo antes de reintentar
    }

    eprintln!(
        "No se pudo leer el archivo después de {} intentos. Usando valor por defecto: 6",
        max_reintentos
    );
    6 // Valor por defecto si no se logra leer el archivo correctamente
}

fn reenviar_a_nodos_correspondientes_consistencia(
    query: &str,
    nodo_actual: &mut Nodo,
) -> (Vec<(String, String)>, usize) {
    nodo_actual.actualizar_keyspaces();

    println!("Reenviando a nodos correspondientes con consistencia");
    let mut responses = Vec::new(); // Cambiamos a un vector de Strings

    let mut keyspace = String::new();
    let consistencia: Consistency;
    match determine_query_type(query) {
        Ok(QueryType::Select(select_query)) => {
            keyspace = select_query.keyspace.clone();
            consistencia = select_query.consistency;
        }
        Ok(QueryType::Insert(insert_query)) => {
            keyspace = insert_query.keyspace.clone();
            consistencia = insert_query.consistency;
        }
        Ok(QueryType::Update(update_query)) => {
            keyspace = update_query.keyspace.clone();
            consistencia = update_query.consistency;
        }
        Ok(QueryType::Delete(delete_query)) => {
            keyspace = delete_query.keyspace.clone();
            consistencia = delete_query.consistency;
        }
        Ok(QueryType::CreateTable(create_table_query)) => {
            keyspace = create_table_query.keyspace.clone();
            consistencia = Consistency::ALL;
        }
        Ok(QueryType::CreateKeyspace(_)) => {
            consistencia = Consistency::ALL;
        }
        Ok(QueryType::Adapt(_)) => {
            consistencia = Consistency::ALL;
        }
        Err(e) => {
            println!("Error procesando el query: {:?}", e);
            consistencia = Consistency::ONE;
        }
    }

    let replicacion_necesaria = nodo_actual
        .keyspaces
        .iter()
        .find(|k| k.name == keyspace)
        .map(|k| k.replication_strategy.replication_factor)
        .unwrap_or(1) as usize;

    let mut replicas_por_procesar = match consistencia {
        Consistency::ALL => replicacion_necesaria,
        Consistency::QUORUM => replicacion_necesaria / 2,
        Consistency::ONE => 1,
    };

    let mut i: usize = 0;

    while replicas_por_procesar > 0 && i < nodo_actual.shared_peers.len() {
        let nodo = &mut nodo_actual.shared_peers[i];
        nodo.actualizar_keyspaces();
        if let Ok(true) = nodo.corresponde_a_este_nodo(query.to_string()) {
            println!("dio true, osea debo conectarme a:\n {:?}\n", nodo.address);
            if let Ok(mut tls_stream) = connect_to_node_with_tls(nodo.address.as_str()) {
                println!("Conectado a nodo replicado: {:?}\n", nodo.address);
                // Construimos el prefijo de 0xFF, 0xFF, 0xFFFF, 0xFF, 0xFFFFFFFF
                let mut prefijo: Vec<u8> = vec![
                    0xFF, // Primer byte
                    0xFF, // Segundo byte
                    0xFF,
                    0xFF, // Dos bytes para 0xFFFF
                    0xFF, // Otro byte
                    //tamaño del query
                    (query.len() as u32).to_be_bytes()[0], // Primer byte del tamaño de la query
                    (query.len() as u32).to_be_bytes()[1], // Segundo byte del tamaño de la query
                    (query.len() as u32).to_be_bytes()[2], // Tercer byte del tamaño de la query
                    (query.len() as u32).to_be_bytes()[3], // Cuarto byte del tamaño de la query
                ];
                // El mensaje de query a enviar
                let message = query.to_string();
                // Concatenamos el prefijo con el mensaje
                prefijo.extend_from_slice(message.as_bytes());
                prefijo.push(b'\n'); // Añadimos un salto de línea
                                     // Enviamos el mensaje con el prefijo
                tls_stream
                    .write_all(&prefijo)
                    .unwrap_or_else(|e| println!("Error al enviar el mensaje al nodo: {:?}", e));
                tls_stream.write_all(b"\n").unwrap_or_else(|e| {
                    println!("Error al enviar el salto de línea al nodo: {:?}", e)
                });
                tls_stream
                    .flush()
                    .unwrap_or_else(|e| println!("Error al hacer flush en el nodo: {:?}", e));
                let mut response = String::new();
                let mut reader = BufReader::new(tls_stream);
                if reader.read_line(&mut response).is_ok() {
                    responses.push((nodo.address.clone(), response.trim().to_string()));
                    println!("Respuesta de {:?} es: {:?}", nodo.address, response);
                    replicas_por_procesar -= 1;
                } else {
                    println!(
                        "Error al leer la respuesta del nodo replicado: {:?}",
                        nodo.address
                    );
                }
            } else {
                println!("No se pudo conectar al nodo replicado: {:?}", nodo.address);
            }
        }
        i += 1;
    }

    println!("Respuestas de los nodos correspondientes : {:?}", responses);
    println!(
        "FIN de correspondientes con consistencia, ultimo fue: {:?}",
        i
    );
    (responses, i) // Devolvemos el vector de respuestas y la posición del último nodo
}

fn reenviar_a_nodos_correspondientes_consistencia_restantes(
    query: &str,
    nodo_actual: &mut Nodo,
    ultimo_nodo: usize,
) -> Vec<(String, String)> {
    nodo_actual.actualizar_keyspaces();

    let mut responses = Vec::new(); // Cambiamos a un vector de Strings

    for i in ultimo_nodo..nodo_actual.shared_peers.len() {
        let nodo = &mut nodo_actual.shared_peers[i];
        nodo.actualizar_keyspaces();
        if let Ok(true) = nodo.corresponde_a_este_nodo(query.to_string()) {
            println!("dio true, osea debo conectarme a:\n {:?}\n", nodo.address);
            if let Ok(mut tls_stream) = connect_to_node_with_tls(nodo.address.as_str()) {
                println!("Conectado a nodo replicado restantes: {:?}\n", nodo.address);
                // Construimos el prefijo de 0xFF, 0xFF, 0xFFFF, 0xFF, 0xFFFFFFFF
                let mut prefijo: Vec<u8> = vec![
                    0xFF, // Primer byte
                    0xFF, // Segundo byte
                    0xFF,
                    0xFF, // Dos bytes para 0xFFFF
                    0xFF, // Otro byte
                    //tamaño del query
                    (query.len() as u32).to_be_bytes()[0], // Primer byte del tamaño de la query
                    (query.len() as u32).to_be_bytes()[1], // Segundo byte del tamaño de la query
                    (query.len() as u32).to_be_bytes()[2], // Tercer byte del tamaño de la query
                    (query.len() as u32).to_be_bytes()[3], // Cuarto byte del tamaño de la query
                ];
                // El mensaje de query a enviar
                let message = query.to_string();
                // Concatenamos el prefijo con el mensaje
                prefijo.extend_from_slice(message.as_bytes());
                prefijo.push(b'\n'); // Añadimos un salto de línea
                                     // Enviamos el mensaje con el prefijo
                tls_stream
                    .write_all(&prefijo)
                    .unwrap_or_else(|e| println!("Error al enviar el mensaje al nodo: {:?}", e));
                tls_stream.write_all(b"\n").unwrap_or_else(|e| {
                    println!("Error al enviar el salto de línea al nodo: {:?}", e)
                });
                tls_stream
                    .flush()
                    .unwrap_or_else(|e| println!("Error al hacer flush en el nodo: {:?}", e));
                let mut response = String::new();
                let mut reader = BufReader::new(tls_stream);
                if reader.read_line(&mut response).is_ok() {
                    responses.push((nodo.address.clone(), response.trim().to_string()));
                    println!("Respuesta de {:?} es: {:?}", nodo.address, response);
                } else {
                    println!(
                        "Error al leer la respuesta del nodo replicado: {:?}",
                        nodo.address
                    );
                }
            } else {
                println!("No se pudo conectar al nodo replicado: {:?}", nodo.address);
            }
        }
    }

    println!(
        "Respuestas de los nodos correspondientes consistencia restantes: {:?}",
        responses
    );
    responses // Devolvemos el vector de respuestas y la posición del último nodo
}

pub fn enviar_mensaje_a_replicado(query: String, nodo: &str) -> Result<String, String> {
    println!("[INFO] Intentando conectar al nodo replicado: {}", nodo);

    match connect_to_node_with_tls(nodo) {
        Ok(mut tls_stream) => {
            info!("Conexión exitosa con el nodo: {}", nodo);

            // Construcción del mensaje con prefijo y longitud
            let mut prefijo: Vec<u8> = vec![
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                (query.len() as u32).to_be_bytes()[0],
                (query.len() as u32).to_be_bytes()[1],
                (query.len() as u32).to_be_bytes()[2],
                (query.len() as u32).to_be_bytes()[3],
            ];

            prefijo.extend_from_slice(query.as_bytes());
            prefijo.push(b'\n');

            if let Err(e) = tls_stream.write_all(&prefijo) {
                return Err(format!(
                    "[ERROR] Falló el envío del mensaje al nodo {}: {:?}",
                    nodo, e
                ));
            }

            if let Err(e) = tls_stream.write_all(b"\n") {
                return Err(format!(
                    "[ERROR] Falló el envío del salto de línea al nodo {}: {:?}",
                    nodo, e
                ));
            }

            if let Err(e) = tls_stream.flush() {
                return Err(format!(
                    "[ERROR] Falló el flush del mensaje al nodo {}: {:?}",
                    nodo, e
                ));
            }

            info!("Mensaje enviado exitosamente al nodo: {}", nodo);

            // Lectura de la respuesta
            let mut response = String::new();
            let mut reader = BufReader::new(&mut tls_stream);

            match reader.read_line(&mut response) {
                Ok(_) => {
                    println!(
                        "[INFO] Respuesta recibida del nodo {}: {}",
                        nodo,
                        response.trim()
                    );
                    info!("Respuesta recibida del nodo {}: {}", nodo, response.trim());

                    if let Err(e) = tls_stream.sock.shutdown(Shutdown::Both) {
                        println!(
                            "[WARN] Falló al cerrar la conexión con el nodo {}: {:?}",
                            nodo, e
                        );
                    }
                    Ok(response.trim().to_string())
                }
                Err(e) => {
                    println!(
                        "[ERROR] Falló la lectura de la respuesta del nodo {}: {:?}",
                        nodo, e
                    );

                    if let Err(e) = tls_stream.sock.shutdown(Shutdown::Both) {
                        println!("[WARN] Falló al cerrar la conexión con el nodo {} tras error de lectura: {:?}", nodo, e);
                    }

                    Err(format!(
                        "[ERROR] No se pudo leer la respuesta del nodo {}: {:?}",
                        nodo, e
                    ))
                }
            }
        }
        Err(e) => {
            // Error al conectar al nodo
            let error_message = format!(
                "[ERROR] No se pudo conectar al nodo replicado {}: {:?}",
                nodo, e
            );
            println!("{}", error_message);
            Err(error_message)
        }
    }
}

fn reenviar_a_nodos_replicados_consistencia(
    query: &str,
    nodo_actual: &mut Nodo,
) -> (Vec<(String, String)>, usize) {
    println!("INICIO de replicados con consistencia");
    let mut responses = Vec::new();

    let nodos_a_replicar = match nodo_actual.replication_nodos.lock() {
        Ok(guard) => guard,
        Err(_) => {
            println!("Error al obtener el lock de replication_nodos");
            return (Vec::new(), 0);
        }
    };

    println!(
        "Reenviando: {:?} , a los nodos replicados: {:?}",
        query, nodos_a_replicar
    );

    let mut keyspace = String::new();
    let consistencia: Consistency;
    match determine_query_type(query) {
        Ok(QueryType::Select(select_query)) => {
            keyspace = select_query.keyspace.clone();
            consistencia = select_query.consistency;
        }
        Ok(QueryType::Insert(insert_query)) => {
            keyspace = insert_query.keyspace.clone();
            consistencia = insert_query.consistency;
        }
        Ok(QueryType::Update(update_query)) => {
            keyspace = update_query.keyspace.clone();
            consistencia = update_query.consistency;
        }
        Ok(QueryType::Delete(delete_query)) => {
            keyspace = delete_query.keyspace.clone();
            consistencia = delete_query.consistency;
        }
        Ok(QueryType::CreateTable(create_table_query)) => {
            keyspace = create_table_query.keyspace.clone();
            consistencia = Consistency::ALL;
        }
        Ok(QueryType::CreateKeyspace(_)) => {
            consistencia = Consistency::ALL;
        }
        Ok(QueryType::Adapt(_)) => {
            consistencia = Consistency::ALL;
        }
        Err(e) => {
            println!("Error procesando el query: {:?}", e);
            consistencia = Consistency::ONE;
        }
    }

    let replicacion_necesaria = nodo_actual
        .keyspaces
        .iter()
        .find(|k| k.name == keyspace)
        .map(|k| k.replication_strategy.replication_factor)
        .unwrap_or(1) as usize;

    let mut replicas_por_procesar = match consistencia {
        Consistency::ALL => replicacion_necesaria - 1,
        Consistency::QUORUM => replicacion_necesaria / 2,
        Consistency::ONE => 0,
    };

    let mut i: usize = 0;
    while replicas_por_procesar > 0 && i < nodos_a_replicar.len() {
        let nodo_adress = &nodos_a_replicar[i];
        println!("[DEBUG] Enviando query al nodo replicado: {}", nodo_adress);

        match enviar_mensaje_a_replicado(query.to_string(), nodo_adress) {
            Ok(response) => {
                println!(
                    "[INFO] Respuesta recibida del nodo {}: {}",
                    nodo_adress,
                    response.trim()
                );
                responses.push((nodo_adress.clone(), response.trim().to_string()));
                replicas_por_procesar -= 1;
            }
            Err(e) => {
                println!(
                    "[ERROR] Fallo al enviar query al nodo {}: {:?}",
                    nodo_adress, e
                );
            }
        }
        i += 1;
    }

    if replicas_por_procesar > 0 {
        println!(
            "[WARNING] No se pudieron procesar todas las réplicas. Réplicas restantes: {}",
            replicas_por_procesar
        );
    } else {
        println!("[INFO] Todas las réplicas necesarias fueron procesadas.");
    }

    println!("Respuestas de los nodos replicados: {:?}", responses);
    println!(
        "[INFO] FIN de replicados con consistencia. Último nodo procesado: {}",
        i
    );
    (responses, i)
}

fn reenviar_a_nodos_replicados_consistencia_restantes(
    query: &str,
    nodo_actual: &mut Nodo,
    ultimo_nodo: usize,
) -> Vec<(String, String)> {
    println!("INICIO de replicados con consistencia");
    let mut responses = Vec::new();

    let nodos_a_replicar = match nodo_actual.replication_nodos.lock() {
        Ok(guard) => guard,
        Err(_) => {
            eprintln!("No se pudo bloquear replication_nodos, se devuelve el vector vacío.");
            return Vec::new();
        }
    };

    println!(
        "Reenviando: {:?} , a los nodos replicados restantes a partir del nodo {:?}",
        query, ultimo_nodo
    );

    let mut keyspace = String::new();
    match determine_query_type(query) {
        Ok(QueryType::Select(select_query)) => {
            keyspace = select_query.keyspace.clone();
        }
        Ok(QueryType::Insert(insert_query)) => {
            keyspace = insert_query.keyspace.clone();
        }
        Ok(QueryType::Update(update_query)) => {
            keyspace = update_query.keyspace.clone();
        }
        Ok(QueryType::Delete(delete_query)) => {
            keyspace = delete_query.keyspace.clone();
        }
        Ok(QueryType::CreateTable(create_table_query)) => {
            keyspace = create_table_query.keyspace.clone();
        }
        Ok(QueryType::CreateKeyspace(_)) => {}
        Ok(QueryType::Adapt(_)) => {}
        Err(e) => {
            println!("Error procesando el query: {:?}", e);
        }
    }

    let replicacion_necesaria = nodo_actual
        .keyspaces
        .iter()
        .find(|k| k.name == keyspace)
        .map(|k| k.replication_strategy.replication_factor)
        .unwrap_or(1) as usize;

    let mut replicas_por_procesar = replicacion_necesaria - 1;

    for i in ultimo_nodo..nodos_a_replicar.len() {
        if replicas_por_procesar == 0 {
            break;
        }

        let nodo_adress = &nodos_a_replicar[i];
        let resultado = enviar_mensaje_a_replicado(query.to_string(), nodo_adress);
        if let Ok(response) = resultado {
            responses.push((nodo_adress.clone(), response.trim().to_string()));
            replicas_por_procesar -= 1;
        }
    }

    if replicas_por_procesar > 0 {
        println!(
            "No se pudieron procesar todas las réplicas. Réplicas restantes: {}",
            replicas_por_procesar
        );
    }

    println!(
        "Respuestas de los nodos replicados restantes: {:?}",
        responses
    );
    println!("FIN de replicados con consistencia");
    responses
}

pub fn handle_read_repair(nodo_actual: &mut Nodo, responses: Vec<(String, String)>, query: &str) {
    // Extraer solo los valores de las respuestas sin las direcciones.
    let responses_sin_adress: Vec<String> = responses.iter().map(|(_, val)| val.clone()).collect();

    // Determinar el valor del quorum a partir de las respuestas.
    let quorum = realizar_quorum_read_reapir(responses_sin_adress.clone());
    println!("El quorum fue: {:?}", quorum);
    let lineas_quorum = quorum.lines().collect::<Vec<&str>>();

    // Recorrer cada respuesta para verificar si coincide con el quorum.
    for (address, valor) in responses {
        if valor != quorum {
            println!(
                "Inconsistencia detectada en nodo: {}\nValor: {}\nQuorum: {}\n",
                address, valor, quorum
            );

            for linea in lineas_quorum.clone() {
                if !valor.contains(linea) {
                    println!(
                        "Línea del quorum no encontrada en el valor del nodo: {}\nLínea: {}\n",
                        address, linea
                    );
                    // Enviar una actualización para sincronizar el nodo con el valor del quorum.
                    reenviar_actualizacion_del_quorum(
                        nodo_actual,
                        address.clone(),
                        linea.to_string(),
                        query,
                    );
                }
            }
        } else {
            println!("Nodo: {} está sincronizado con el quorum.\n", address);
        }
    }
}

fn obtener_columnas(ruta: &str) -> Result<Option<Vec<String>>, Box<dyn Error>> {
    let file = File::open(ruta)?;
    let reader = BufReader::new(file);
    let mut columnas = Vec::new();

    for line in reader.lines() {
        let line = line?;
        if let Some(cols_str) = line.strip_prefix("Columns: ") {
            let cols: Vec<&str> = cols_str.split(", ").collect();
            for col in cols {
                let col_parts: Vec<&str> = col.split(" ").collect();
                if col_parts.len() == 2 {
                    columnas.push(col_parts[0].to_string());
                }
            }
            return Ok(Some(columnas));
        }
    }

    Ok(None)
}

fn reenviar_actualizacion_del_quorum(
    _nodo_actual: &mut Nodo,
    address: String,
    quorum: String,
    query: &str,
) {
    let query_type = match determine_query_type(query) {
        Ok(QueryType::Select(select_query)) => select_query,
        Ok(_) => {
            println!("llego a read-repair un no select");
            return;
        }
        Err(e) => {
            println!("Error procesando el query: {:?}", e);
            return;
        }
    };

    if let Ok(mut tls_stream) = connect_to_node_with_tls(address.clone().as_str()) {
        println!("Conectado a nodo replicado quorum: {:?}", address);

        // Descomprimir la ruta y obtener el nombre del keyspace y la tabla

        let ruta_info = format!(
            "keyspaces_info/{}/{}.txt",
            query_type.keyspace, query_type.tabla
        );
        let columnas = match obtener_columnas(&ruta_info) {
            Ok(Some(cols)) => cols,
            Ok(None) => {
                println!("No se encontraron columnas en la ruta: {}", ruta_info);
                return;
            }
            Err(e) => {
                println!("Error al obtener columnas: {:?}", e);
                return;
            }
        };

        let columnas_string: String = columnas.join(" ,");
        let valores = quorum.split("//////").nth(1).unwrap_or_default();

        // Construir el query de actualización basado en las condiciones y el valor del quorum
        let mut query = format!(
            "INSERT INTO {}.{} ({}) USING CONSISTENCY ONE VALUES ({}); ",
            query_type.keyspace, query_type.tabla, columnas_string, valores
        );
        println!("Query de actualización a enviar: {}", query);
        query.push(';');

        let mut prefijo: Vec<u8> = vec![
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            0xFF,
            (query.len() as u32).to_be_bytes()[0],
            (query.len() as u32).to_be_bytes()[1],
            (query.len() as u32).to_be_bytes()[2],
            (query.len() as u32).to_be_bytes()[3],
        ];

        prefijo.extend_from_slice(query.as_bytes());
        prefijo.push(b'\n');

        tls_stream.write_all(&prefijo).unwrap_or_else(|e| {
            println!("Error al enviar el mensaje al nodo: {:?}", e);
        });
        tls_stream.write_all(b"\n").unwrap_or_else(|e| {
            println!("Error al enviar el salto de línea al nodo: {:?}", e);
        });
        tls_stream.flush().unwrap_or_else(|e| {
            println!("Error al hacer flush en el nodo: {:?}", e);
        });

        let mut response = String::new();
        let mut reader = BufReader::new(&mut tls_stream);

        if reader.read_line(&mut response).is_ok() {
            println!("Respuesta de {:?} es: {:?}", address, response);
        } else {
            println!(
                "No se pudo leer la respuesta del nodo replicado: {:?}",
                address
            );
        }

        tls_stream
            .sock
            .shutdown(Shutdown::Both)
            .unwrap_or_else(|e| {
                println!("Error al cerrar la conexión con el nodo: {:?}", e);
            });
    } else {
        println!("No se pudo conectar al nodo replicado: {:?}", address);
    }
}

/// Maneja las consultas recibidas en el nodo actual a través de una conexión TCP.
pub fn handle_nodo(
    stream: &mut StreamOwned<ServerConnection, TcpStream>,
    nodo_actual: &mut Nodo,
    message: String,
) -> std::io::Result<()> {
    let _reader = BufReader::new(stream.sock.try_clone()?);

    println!(
        "Soy {}, recibi el query: {}\n",
        nodo_actual.address, message
    );

    print!("Ejecutando el query: {}", message);
    let response;
    nodo_actual.actualizar_keyspaces();
    match parsear_y_ejecutar_query(&message, nodo_actual) {
        Ok(resultado) => {
            if message.contains("SELECT") {
                // Muestra el resultado si es un SELECT y hay contenido
                println!("Resultado de la consulta SELECT:\n{}", resultado);
                // cambio los saltos de linea por //////
                let mut resultado = resultado.replace("\n", "//////");
                resultado.push('\n');
                response = resultado;
                println!("Respuesta enviada: {:?}", response);
                stream.write_all(response.as_bytes())?;
                stream.flush()?;
            } else if message.contains("ADAPT") {
                println!("Consulta adapt");
                let _ = parsear_y_ejecutar_query(&message, nodo_actual);

                response = "todo bien\n".to_string();
                println!("Respuesta enviada: {:?}", response);
                stream.write_all(response.as_bytes())?;
                stream.flush()?;

                match determine_query_type(&message) {
                    Ok(QueryType::Adapt(adapt_msg)) => {
                        let _ = ejecutar_adapt_message_reenviar(&adapt_msg, nodo_actual);
                    }
                    Ok(_) => {
                        eprintln!(
                            "Error: Expected an adapt message but got a different query type"
                        );
                    }
                    Err(e) => {
                        eprintln!("Error determining query type: {:?}", e);
                    }
                }
            } else {
                // Mensaje opcional si no hay resultados en la selección
                println!("Consulta No SELECT ejecutada correctamente\n");
                response = "todo bien\n".to_string();
                println!("Respuesta enviada: {:?}", response);
                stream.write_all(response.as_bytes())?;
                stream.flush()?;
            }
        }
        Err(e) => {
            // Manejo de errores si la consulta de selección falla
            print_error(e, "Error durante la ejecución de la consulta SELECT");
            response = "Error durante la ejecución de la consulta SELECT\n".to_string();
            println!("Respuesta enviada: {:?}", response);
            stream.write_all(response.as_bytes())?;
            stream.flush()?;
        }
    }

    Ok(())
}

// Función para hashear el valor de la partition key (ejemplo simple usando un hash)
fn hash_partition_key(partition_key: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&partition_key, &mut hasher);
    hasher.finish() // Devuelve directamente el valor como u64
}

// Función para leer el archivo info.txt del keyspace
fn leer_info_keyspace(keyspace_path: &std::path::Path) -> Result<Keyspace, Box<dyn Error>> {
    let info_path = keyspace_path.join("info.txt");
    let info_file = File::open(&info_path)?;
    let reader = BufReader::new(info_file);

    let mut keyspace_name = String::new();
    let mut _replication_class = String::new();
    let mut replication_factor = 0;

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split(": ").collect();
        if parts.len() == 2 {
            match parts[0] {
                "Keyspace" => keyspace_name = parts[1].to_string(),
                "Replication Class" => _replication_class = parts[1].to_string(),
                "Replication Factor" => replication_factor = parts[1].parse()?,
                "Tables" => {
                    // Aquí se maneja la parte de las tablas que se leerán después
                }
                _ => {}
            }
        }
    }

    // Convertir replication_class a Enum
    let replication_strategy = ReplicationConfig {
        class: ReplicationClass::SimpleStrategy,
        replication_factor,
    };

    // Leer las tablas del keyspace
    let tables = leer_tablas_keyspace(keyspace_path)?;

    Ok(Keyspace {
        name: keyspace_name,
        replication_strategy,
        tables,
    })
}

// Función para leer las tablas del keyspace
fn leer_tablas_keyspace(
    keyspace_path: &std::path::Path,
) -> Result<HashMap<String, Table>, Box<dyn Error>> {
    let mut tables = HashMap::new();
    let table_files = fs::read_dir(keyspace_path)?;

    for table_file in table_files {
        let table_path = table_file?.path();
        if table_path.is_file() && table_path.file_name().unwrap_or_default() == "info.txt" {
            continue;
        }

        if table_path.is_file() && table_path.extension().unwrap_or_default() == "txt" {
            let table = leer_info_tabla(&table_path)?;
            tables.insert(table.name.clone(), table);
        }
    }

    Ok(tables)
}

// Función para leer la info de una tabla desde su archivo txt
fn leer_info_tabla(table_path: &std::path::Path) -> Result<Table, Box<dyn Error>> {
    let file = File::open(table_path)?;
    let reader = BufReader::new(file);

    let mut table_name = String::new();
    let mut partition_key = Vec::new();
    let mut clustering_key = Vec::new();
    let mut columnas = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.split(": ").collect();
        if parts.len() == 2 {
            match parts[0] {
                "Table" => table_name = parts[1].to_string(),
                "Partition Key" => {
                    partition_key = parts[1]
                        .trim_matches(&['[', ']'][..])
                        .split(", ")
                        .map(|s| s.to_string())
                        .collect();
                }
                "Clustering Key" => {
                    clustering_key = parts[1]
                        .trim_matches(&['[', ']'][..])
                        .split(", ")
                        .map(|s| s.to_string())
                        .collect();
                }
                "Columns" => {
                    let cols: Vec<&str> = parts[1].split(", ").collect();
                    for col in cols {
                        let col_parts: Vec<&str> = col.split(" ").collect();
                        if col_parts.len() == 2 {
                            columnas.insert(col_parts[0].to_string(), col_parts[1].to_string());
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(Table {
        name: table_name,
        primary_key: PrimaryKey {
            partition_key,
            clustering_key,
        },
        columnas,
    })
}

// Función para calcular un token hash simple a partir de la partition_key
/*
fn calculate_token(partition_key: &Vec<String>) -> i64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    partition_key.hash(&mut hasher);
    hasher.finish() as i64 // Devolvemos el valor hash como token
} */
