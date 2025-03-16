use crate::error::{print_error, ErrorType};
use crate::nodo_cassandra::{change_token_range, reenviar_todos_registros_adapt, Nodo};
use crate::nodo_cassandra_functions::{keyspace::Keyspace, table::Table};
use crate::parser::{determine_query_type, QueryType};
use crate::parser_functions::adapt::AdaptMessage;
use crate::parser_functions::{
    condicion_compuesta::CondicionCompuesta, create_keyspace_query::CreateKeyspaceQuery,
    elemento_condicion_pila::ElementoCondicionPila, operator::Operator,
    query_create_table::CreateTableQuery, query_delete::DeleteQuery, query_insert::InsertQuery,
    query_select::SelectQuery, query_update::UpdateQuery, simple_condition::SimpleCondition,
};
use chrono::{FixedOffset, Utc};
use log::{error, info};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

/// Función que parsea una consulta SQL y la ejecuta, devolviendo un String con el resultado.
pub fn parsear_y_ejecutar_query(consulta_sql: &str, nodo: &mut Nodo) -> Result<String, ErrorType> {
    // Evaluar y manejar los resultados de tipo_query
    let result_query = match determine_query_type(consulta_sql) {
        Ok(query) => query,
        Err(e) => {
            print_error(
                ErrorType::InvalidSyntax("Error al procesar la consulta".to_string()),
                &format!("Error al procesar la consulta: {}", e),
            );
            return Err(ErrorType::InvalidSyntax(e.to_string()));
        }
    };

    // Determina el nombre de la tabla y el keyspace según el tipo de consulta
    let (keyspace, tabla) = match &result_query {
        QueryType::Select(q) => (q.keyspace.clone(), q.tabla.clone()),
        QueryType::Update(q) => (q.keyspace.clone(), q.tabla.clone()),
        QueryType::Insert(q) => (q.keyspace.clone(), q.tabla.clone()),
        QueryType::Delete(q) => (q.keyspace.clone(), q.tabla.clone()),
        QueryType::CreateTable(q) => (q.keyspace.clone(), q.tabla.clone()),
        QueryType::CreateKeyspace(q) => (q.name.clone(), String::from("default_table")),
        QueryType::Adapt(_q) => (
            String::from("default_keyspace"),
            String::from("default_table"),
        ),
    };

    if keyspace != "default_keyspace" {
        // Construye la ruta del archivo CSV
        match verificar_partition_keys(&keyspace, &tabla, &result_query) {
            Ok(_) => {}
            Err(e) => return Err(ErrorType::Error(e.to_string())),
        }
    }

    let ruta_tabla = format!("{}/{}.csv", keyspace, tabla);

    // Ejecuta la consulta utilizando `ejecutar_query`
    match ejecutar_query(&result_query, &ruta_tabla, nodo) {
        Ok(resultado) => {
            info!("Query ejecutada con éxito: {}", consulta_sql);
            Ok(resultado)
        } // Devolver el string del resultado
        Err(e) => {
            print_error(
                ErrorType::Error("Error al ejecutar la consulta".to_string()),
                &format!("{}", e),
            );
            Err(ErrorType::Error(e.to_string()))
        }
    }
}

// Función principal para ejecutar la consulta una vez parseada
pub fn ejecutar_query(
    query: &QueryType,
    ruta_tablas: &str,
    nodo: &mut Nodo,
) -> Result<String, Box<dyn Error>> {
    match query {
        QueryType::Select(select_query) => ejecutar_select(select_query, ruta_tablas),
        QueryType::Insert(insert_query) => {
            ejecutar_insert(insert_query, ruta_tablas)?;
            Ok(String::new()) // Devolver un string vacío
        }
        QueryType::Update(update_query) => {
            ejecutar_update(ruta_tablas, update_query)?;
            Ok(String::new()) // Devolver un string vacío
        }
        QueryType::Delete(delete_query) => {
            ejecutar_delete(delete_query, ruta_tablas)?;
            Ok(String::new()) // Devolver un string vacío
        }
        QueryType::CreateTable(create_table_query) => {
            ejecutar_create_table(create_table_query, nodo)?;
            Ok(String::new()) // Devolver un string vacío
        }
        QueryType::CreateKeyspace(create_keyspace_query) => {
            ejecutar_create_keyspace(create_keyspace_query, nodo)?;
            Ok(String::new()) // Devolver un string vacío
        }
        QueryType::Adapt(adapt_message) => {
            ejecutar_adapt_message(adapt_message, nodo)?;
            Ok(String::new())
        }
    }
}

// Crea una tabla en el sistema especificado por CreateTableQuery, que incluye la escritura de la estructura de la tabla en un archivo de texto y la creación de un archivo CSV con los nombres de las columnas.
pub fn ejecutar_create_table(
    query: &CreateTableQuery,
    nodo: &mut Nodo,
) -> Result<(), Box<dyn Error>> {
    if Path::new(&format!("{}/{}.csv", &query.keyspace, &query.tabla)).exists() {
        return Ok(());
    }

    // Ruta donde se guardará la tabla dentro de "keyspaces_info"
    let table_info_path = Path::new("keyspaces_info")
        .join(&query.keyspace)
        .join(format!("{}.txt", query.tabla));

    // Crea las carpetas necesarias para el keyspace si no existen
    if let Some(parent_path) = table_info_path.parent() {
        fs::create_dir_all(parent_path)?;
    } else {
        return Err(Box::new(ErrorType::Error(
            "No se pudo determinar el directorio padre".to_string(),
        )));
    }

    // Crear la estructura de la tabla con su primary key
    let table_info = format!(
        "Table: {}\nPartition Key: [{}]\nClustering Key: [{}]\nColumns: {}",
        query.tabla,
        query.primary_key.partition_key.join(", "), // Unir sin comillas
        query.primary_key.clustering_key.join(", "), // Unir sin comillas
        query
            .columnas
            .iter()
            .map(|(col_name, col_type)| format!("{} {}", col_name, col_type)) // Sin comillas en el nombre
            .collect::<Vec<String>>()
            .join(", ")
    );

    // Crear o sobrescribir el archivo info.txt para la tabla
    let mut file = File::create(&table_info_path)?;
    file.write_all(table_info.as_bytes())?;

    //println!("INFO DE LA TABLA GUARDADA EN: {:?}", table_info_path);

    // Crear el archivo CSV correspondiente a la tabla con las columnas separadas por comas
    let table_csv_path = Path::new(&query.keyspace).join(format!("{}.csv", query.tabla));

    // Crea las carpetas necesarias para el keyspace si no existen
    if let Some(parent_path) = table_csv_path.parent() {
        fs::create_dir_all(parent_path)?;
    } else {
        return Err(Box::new(ErrorType::Error(
            "No se pudo determinar el directorio padre".to_string(),
        )));
    }

    // Escribe las columnas en el archivo CSV
    let mut csv_file = File::create(&table_csv_path)?;
    let columnas_csv = query
        .columnas
        .iter()
        .map(|(col_name, _)| col_name.clone()) // Sin comillas en el nombre
        .collect::<Vec<String>>()
        .join(",");

    // Añade un salto de línea al final de las columnas
    csv_file.write_all(format!("{}\n", columnas_csv).as_bytes())?;

    // Convertir el Vec<(String, String)> en HashMap<String, String>
    let columnas_hashmap: HashMap<String, String> = query
        .columnas
        .iter()
        .cloned() // Clonar cada tupla (col_name, col_type)
        .collect();

    // Agregar la tabla al nodo
    let nueva_tabla = Table {
        name: query.tabla.clone(),
        primary_key: query.primary_key.clone(),
        columnas: columnas_hashmap, // Ahora es un HashMap
    };
    nodo.agregar_tabla(&query.keyspace, nueva_tabla);

    Ok(())
}

// Función para ejecutar la creación del keyspace
fn ejecutar_create_keyspace(
    query: &CreateKeyspaceQuery,
    nodo: &mut Nodo,
) -> Result<(), Box<dyn Error>> {
    if Path::new(&query.name).exists() {
        return Ok(());
    }
    // Crear el directorio principal para el keyspace donde se almacenarán las tablas en formato .csv
    let keyspace_path = Path::new(&query.name);
    fs::create_dir_all(keyspace_path)?; // Crea la carpeta para el keyspace

    // Crear la carpeta dentro de "keyspaces_info/" para almacenar la información del keyspace
    let keyspace_info_path = Path::new("keyspaces_info").join(&query.name);
    fs::create_dir_all(&keyspace_info_path)?; // Crea la carpeta de keyspace en keyspaces_info

    // Guardar la información del keyspace en una variable (con su estrategia de replicación)
    let keyspace_info = format!(
        "Keyspace: {}\nReplication Class: {:?}\nReplication Factor: {}\nTables: []",
        query.name, query.replication_strategy.class, query.replication_strategy.replication_factor,
    );
    //println!("INFO A GUARDAR DEL KEYSPACE: {}", keyspace_info);

    // Crear el archivo "info.txt" dentro de la carpeta de keyspace en "keyspaces_info/"
    let info_file_path = keyspace_info_path.join("info.txt");
    let mut file = File::create(info_file_path)?; // Crear el archivo info.txt
    file.write_all(keyspace_info.as_bytes())?; // Escribir la información del keyspace en info.txt

    // Agregar el keyspace al nodo
    let nuevo_keyspace = Keyspace {
        name: query.name.clone(),
        replication_strategy: query.replication_strategy.clone(),
        tables: HashMap::new(),
    };
    nodo.agregar_keyspace(nuevo_keyspace);

    Ok(())
}

// Función para ejecutar la creación del keyspace
pub fn ejecutar_adapt_message(query: &AdaptMessage, nodo: &mut Nodo) -> Result<(), Box<dyn Error>> {
    info!(" Iniciando la ejecución de adapt_message.");

    let cantidad_nodos = query.nodos_cantidad;
    info!(
        "[INFO] Preparando nuevo nodo por ADAPT con dirección: {} y puerto: {} y cantidad: {}",
        nodo.address, nodo.puerto, cantidad_nodos,
    );

    let nodo_nuevo = Nodo::new(&nodo.address, &nodo.puerto, cantidad_nodos);
    info!(
        "[INFO] ADAPT Nodo nuevo creado con rango de tokens: {:?}, cantidad de nodos: {}",
        nodo_nuevo.token_range, cantidad_nodos
    );

    *nodo = nodo_nuevo;

    println!(
        "[INFO] ADAPT Actualizando nodo con cantidad de nodo , con change token range{}.",
        cantidad_nodos
    );

    if let Err(e) = change_token_range(cantidad_nodos) {
        return Err(Box::new(ErrorType::Error(format!(
            "ADAPT Error al cambiar el rango de tokens: {}",
            e
        ))));
    }

    info!("[INFO]ADAPT  Nodo actualizado. Nuevo estado:  {:?}", nodo);

    if let Err(e) = nodo.armar_keyspaces(Some(cantidad_nodos)) {
        let error_message = format!("[ERROR] Error al armar keyspaces: {}", e);
        println!("{}", error_message);
        error!("{}", error_message);
        return Err(Box::new(ErrorType::Error(error_message)));
    }

    info!("Ejecución de adapt_message completada con éxito.");
    Ok(())
}

pub fn ejecutar_adapt_message_reenviar(
    query: &AdaptMessage,
    nodo: &mut Nodo,
) -> Result<(), Box<dyn Error>> {
    info!("Reenviando registros que no pertenecen al nodo actual.");
    let _ = query;
    if let Err(e) = reenviar_todos_registros_adapt(nodo) {
        let error_message = format!(
            "[ERROR] Error al reenviar registros que no pertenecen al nodo: {}",
            e
        );
        println!("{}", error_message);
        return Err(Box::new(ErrorType::Error(error_message)));
    }

    info!("Ejecución de adapt_message completada con éxito.");
    Ok(())
}

// Ejecuta una consulta SELECT y devuelve un Result con un String
fn ejecutar_select(query: &SelectQuery, ruta_tablas: &str) -> Result<String, Box<dyn Error>> {
    let columnas_utilizadas: Vec<String> = if query.columnas.contains(&"*".to_string()) {
        let archivo = File::open(ruta_tablas)?;
        let mut reader = BufReader::new(archivo);
        let mut primera_linea = String::new();
        reader.read_line(&mut primera_linea)?;

        primera_linea
            .trim()
            .split(',')
            .map(|s| s.to_owned())
            .collect()
    } else {
        query.columnas.iter().map(|s| s.to_owned()).collect()
    };

    let archivo = File::open(ruta_tablas)?;
    let mut reader = BufReader::new(archivo);
    let mut primera_linea = String::new();
    reader.read_line(&mut primera_linea)?;

    let columnas_utilizadas: Vec<&str> = columnas_utilizadas.iter().map(|s| s.as_str()).collect();
    verificar_columnas(&columnas_utilizadas, &primera_linea)?;

    let mut resultado = columnas_utilizadas.join(", ");
    resultado.push('\n');
    let primera_linea = primera_linea.trim();

    // Si no tengo que ordenar, acumulo los resultados directamente
    if query.order_by.is_empty() {
        for linea in reader.lines() {
            let linea = linea?;

            if cumple_condiciones(&linea, &query.condiciones, Some(primera_linea))? {
                resultado.push_str(&imprimir_fila(&linea, &columnas_utilizadas, primera_linea)?);
                resultado.push('\n');
            }
        }
    } else {
        // Tengo que ordenar
        let mut lineas_que_cumplen: Vec<String> = Vec::new();

        for linea in reader.lines() {
            let linea = linea?;

            if cumple_condiciones(&linea, &query.condiciones, Some(primera_linea))? {
                lineas_que_cumplen.push(linea);
            }
        }

        let lineas_ordenadas = ordenar_lineas(lineas_que_cumplen, &query.order_by, primera_linea)?;

        resultado.push_str(&imprimir_filas(
            lineas_ordenadas,
            columnas_utilizadas,
            primera_linea,
        )?);
    }

    Ok(resultado)
}

fn descomprimir_ruta(ruta_tablas: &str) -> Option<(String, String)> {
    // Dividimos la ruta usando "/" como delimitador
    let partes: Vec<&str> = ruta_tablas.split('/').collect();

    // Verificamos si tenemos exactamente dos partes: el keyspace y la tabla.csv
    if partes.len() == 2 {
        let keyspace = partes[0].to_string(); // El keyspace es la primera parte
        let tabla = partes[1].strip_suffix(".csv")?.to_string(); // Quitamos el ".csv" de la tabla
        Some((keyspace, tabla))
    } else {
        None // Retornamos None si no tiene el formato esperado
    }
}

fn obtener_partition_keys(ruta_archivo: &str) -> std::io::Result<Vec<String>> {
    let path = Path::new(ruta_archivo);
    let file = File::open(path)?;
    let reader = std::io::BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        // Buscamos la línea que contiene "Partition Key:"
        if line.starts_with("Partition Key: ") {
            // Extraemos el contenido dentro de los corchetes "[ ]"
            if let Some(inicio) = line.find('[') {
                if let Some(fin) = line.rfind(']') {
                    let keys = &line[inicio + 1..fin];
                    // Convertimos los keys en un vector, eliminando espacios
                    let partition_keys: Vec<String> =
                        keys.split(',').map(|key| key.trim().to_string()).collect();
                    return Ok(partition_keys);
                }
            }
        }
    }

    // Si no se encuentra, retornamos un vector vacío
    Ok(Vec::new())
}

fn obtener_clustering_keys(ruta_archivo: &str) -> std::io::Result<Vec<String>> {
    let path = Path::new(ruta_archivo);
    let file = File::open(path)?;
    let reader = std::io::BufReader::new(file);

    for line in reader.lines() {
        let line = line?;
        // Buscamos la línea que contiene "Partition Key:"
        if line.starts_with("Clustering Key:") {
            // Extraemos el contenido dentro de los corchetes "[ ]"
            if let Some(inicio) = line.find('[') {
                if let Some(fin) = line.rfind(']') {
                    let keys = &line[inicio + 1..fin];
                    // Convertimos los keys en un vector, eliminando espacios
                    let clustering_keys: Vec<String> =
                        keys.split(',').map(|key| key.trim().to_string()).collect();
                    return Ok(clustering_keys);
                }
            }
        }
    }
    // Si no se encuentra, retornamos un vector vacío
    Ok(Vec::new())
}

fn verificar_partition_keys(
    keyspace: &String,
    tabla: &String,
    query_completa: &QueryType,
) -> Result<(), Box<dyn Error>> {
    let condiciones_compuestas = match query_completa {
        QueryType::Select(select_query) => &select_query.condiciones,
        QueryType::Update(update_query) => &update_query.condiciones,
        QueryType::Delete(delete_query) => &delete_query.condiciones,
        _ => return Ok(()),
    };
    let ruta_info = format!("keyspaces_info/{}/{}.txt", keyspace, tabla);
    let partition_keys = obtener_partition_keys(&ruta_info)?;

    if partition_keys.is_empty() {
        return Err("No se encontraron Partition Keys en la tabla".into());
    }

    let mut cumple_partition_key = false;
    for token in &condiciones_compuestas.pila_condiciones {
        if cumple_partition_key {
            return Ok(());
        };
        if let ElementoCondicionPila::SimpleCondition(condicion) = token {
            for key in &partition_keys {
                if condicion.columna1 == *key {
                    cumple_partition_key = true;
                    break;
                } else if let Some(columna2) = &condicion.columna2 {
                    if columna2 == key {
                        cumple_partition_key = true;
                        break;
                    }
                }
            }
        }
    }

    if !cumple_partition_key {
        return Err("No se cumple con las Partition Keys".into());
    }
    Ok(())
}

// Ejecuta una consulta INSERT y devuelve un Result
fn ejecutar_insert(query: &InsertQuery, ruta_tablas: &str) -> Result<(), Box<dyn Error>> {
    // Descomprimir la ruta y obtener el nombre del keyspace y la tabla
    let (keyspace, tabla) = match descomprimir_ruta(ruta_tablas) {
        Some((keyspace, tabla)) => (keyspace, tabla),
        None => {
            println!("La ruta no tiene el formato esperado.");
            return Err("Formato de ruta inválido".into());
        }
    };

    let ruta_info = format!("keyspaces_info/{}/{}.txt", keyspace, tabla);
    let partition_keys = obtener_partition_keys(&ruta_info)?;
    let clustering_keys = obtener_clustering_keys(&ruta_info)?;

    if partition_keys.is_empty() {
        return Err("No se encontraron Partition Keys en la tabla".into());
    }

    // Abrir el archivo de la tabla
    let archivo = File::open(ruta_tablas)?;
    let mut reader = BufReader::new(archivo);

    // Leer la primera línea del archivo para obtener los índices de las columnas
    let mut primera_linea = String::new();
    reader.read_line(&mut primera_linea)?;

    let columnas_tabla: Vec<String> = primera_linea
        .trim()
        .split(',')
        .map(|s| s.to_owned())
        .collect();

    // Identificar los índices de las Partition Keys en la tabla
    let mut indices_partition_keys = Vec::new();
    for key in &partition_keys {
        if let Some(indice) = columnas_tabla.iter().position(|c| c == key) {
            indices_partition_keys.push(indice);
        } else {
            return Err(format!("Partition Key '{}' no existe en la tabla", key).into());
        }
    }

    let mut indices_clustering_keys = Vec::new();
    for key in &clustering_keys {
        if let Some(indice) = columnas_tabla.iter().position(|c| c == key) {
            indices_clustering_keys.push(indice);
        } else {
            return Err(format!("Clustering Key '{}' no existe en la tabla", key).into());
        }
    }

    let mut existe = false;
    let mut lineas_actualizadas: Vec<String> = Vec::new();

    // Iterar por cada línea del archivo después de la primera
    for linea in reader.lines() {
        let linea = linea?;
        let columnas: Vec<&str> = linea.split(',').collect();

        // Verificar si los valores de las Partition Keys coinciden con los valores del INSERT
        let mut coincide = true;
        for (i, indice) in indices_partition_keys.iter().enumerate() {
            let valor_insert = &query.valores[0][i]; // Aquí usamos la primera fila de valores del insert
            if columnas[*indice] != valor_insert {
                coincide = false;
                break;
            }
        }

        if coincide {
            existe = true;

            // Si existe, preparamos la línea para actualización
            let mut valores_actualizados: Vec<String> =
                columnas.iter().map(|&s| s.to_string()).collect();

            // Actualizar los valores de las columnas especificadas en el insert
            for (i, columna) in query.columnas.iter().enumerate() {
                if let Some(pos) = columnas_tabla.iter().position(|c| c == columna) {
                    let valor = &query.valores[0][i];
                    valores_actualizados[pos] = valor.to_string();
                } else {
                    return Err(format!("La columna '{}' no existe en la tabla.", columna).into());
                }
            }

            // Actualizar el valor del timestamp en la zona horaria de Argentina
            let offset = FixedOffset::west_opt(3 * 3600).unwrap_or_else(|| {
                FixedOffset::east_opt(0).expect("El offset de fallback debe ser válido")
            });

            let timestamp = Utc::now()
                .with_timezone(&offset)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();

            valores_actualizados.pop(); // Elimina el timestamp anterior
            valores_actualizados.push(timestamp.to_string()); // Convierte el timestamp a string y lo añade a valores_completos
            lineas_actualizadas.push(valores_actualizados.join(","));
        } else {
            // Si no coincide, mantenemos la línea original
            lineas_actualizadas.push(linea);
        }
    }

    // Si no existe, procedemos con el INSERT
    if !existe {
        let mut valores_completos: Vec<String> = vec!["".to_string(); columnas_tabla.len()]; // Asigna "" por defecto

        // Asocia valores con columnas específicas del insert
        for (i, columna) in query.columnas.iter().enumerate() {
            if let Some(pos) = columnas_tabla.iter().position(|c| c == columna) {
                let valor = &query.valores[0][i];
                valores_completos[pos] = valor.to_string();
            } else {
                return Err(format!("La columna '{}' no existe en la tabla.", columna).into());
            }
        }
        // Actualizar el valor del timestamp en la zona horaria de Argentina
        let offset = FixedOffset::west_opt(3 * 3600).unwrap_or_else(|| {
            FixedOffset::east_opt(0).expect("El offset de fallback debe ser válido")
        });

        let timestamp = Utc::now()
            .with_timezone(&offset)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        //valores_completos.pop(); // Elimina el timestamp anterior
        valores_completos.push(timestamp.to_string()); // Convierte el timestamp a string y lo añade a valores_completos
        lineas_actualizadas.push(valores_completos.join(","));
    }

    lineas_actualizadas.sort_by(|a, b| {
        for &indice in &indices_clustering_keys {
            let a_keys: Vec<&str> = a.split(',').collect();
            let b_keys: Vec<&str> = b.split(',').collect();

            // Verificamos si el índice es válido antes de acceder
            let a_key = a_keys.get(indice);
            let b_key = b_keys.get(indice);

            match (a_key, b_key) {
                (Some(a_val), Some(b_val)) => match a_val.cmp(b_val) {
                    Ordering::Equal => continue,
                    other => return other,
                },
                (None, Some(_)) => return Ordering::Less, // Si a no tiene el índice, va antes
                (Some(_), None) => return Ordering::Greater, // Si b no tiene el índice, va después
                (None, None) => continue, // Si ambos no tienen el índice, seguir con el próximo
            }
        }
        Ordering::Equal
    });

    // Escribir las líneas actualizadas (ya sea insertadas o modificadas) en el archivo
    let mut writer = BufWriter::new(File::create(ruta_tablas)?);
    writeln!(writer, "{}", primera_linea.trim())?; // Escribir encabezado

    for linea in lineas_actualizadas {
        writeln!(writer, "{}", linea)?;
    }

    writer.flush()?;

    Ok(())
}

// Ejecuta una consulta UPDATE y devuelve un Result
fn ejecutar_update(ruta_tablas: &str, query: &UpdateQuery) -> Result<(), Box<dyn Error>> {
    // Abrir el archivo de la tabla
    let archivo = File::open(ruta_tablas)?;
    let mut reader = BufReader::new(archivo);

    // Leer la primera línea del archivo para obtener los índices de las columnas
    let mut primera_linea = String::new();
    reader.read_line(&mut primera_linea)?;
    let primera_linea = primera_linea.trim();

    // Crear un archivo temporal para escribir los registros actualizados
    let archivo_temporal = format!("{}_temp", ruta_tablas);
    let mut writer = BufWriter::new(File::create(&archivo_temporal)?);

    // Escribir la primera línea (encabezado) en el archivo temporal
    writeln!(writer, "{}", primera_linea)
        .map_err(|e| format!("No se pudo escribir en el archivo temporal: {}", e))?;

    // Iterar por cada línea del archivo después de la primera
    for linea in reader.lines() {
        let mut linea =
            linea.map_err(|e| format!("No se pudo leer una línea del archivo: {}", e))?;

        // Verificar si la línea cumple con las condiciones
        if cumple_condiciones(&linea, &query.condiciones, Some(primera_linea))? {
            // La línea cumple con las condiciones, actualizar los campos especificados
            let mut campos: Vec<&str> = linea.split(',').collect();
            for (columna, nuevo_valor) in &query.set {
                let indice = obtener_indice_columna(columna, Some(primera_linea))?;
                if let Some(campo) = campos.get_mut(indice) {
                    *campo = nuevo_valor.trim_matches('\''); // Eliminar las comillas simples alrededor del valor
                }
            }

            let offset = FixedOffset::west_opt(3 * 3600).unwrap_or_else(|| {
                FixedOffset::east_opt(0).expect("El offset de fallback debe ser válido")
            });

            let timestamp = Utc::now()
                .with_timezone(&offset)
                .format("%Y-%m-%d %H:%M:%S")
                .to_string();

            campos.pop(); // Elimina el timestamp anterior
            campos.push(&timestamp); // Convierte el timestamp a string y lo añade a valores_completos
            linea = campos.join(","); // Construir la línea actualizada
        }
        writeln!(writer, "{}", linea)
            .map_err(|e| format!("No se pudo escribir en el archivo temporal: {}", e))?;
        // Escribir la línea (actualizada o no) en el archivo temporal
    }
    writer.flush()?;
    drop(writer); // Cerrar el archivo temporal

    fs::rename(&archivo_temporal, ruta_tablas)?; // Reemplazar el archivo original con el archivo temporal

    Ok(())
}

// Ejecuta una consulta DELETE y devuelve un Result
fn ejecutar_delete(query: &DeleteQuery, ruta_tablas: &str) -> Result<(), Box<dyn Error>> {
    // Abrir el archivo de la tabla
    let archivo = File::open(ruta_tablas)?;
    let mut reader = BufReader::new(archivo);

    // Leer la primera línea del archivo para obtener los índices de las columnas
    let mut primera_linea = String::new();
    reader.read_line(&mut primera_linea)?;
    let primera_linea = primera_linea.trim();

    // Crear un archivo temporal para escribir los registros que no se eliminarán
    let archivo_temporal = format!("{}_temp", ruta_tablas);
    let mut writer = BufWriter::new(File::create(&archivo_temporal)?);

    // Escribir la primera línea (encabezado) en el archivo temporal
    writeln!(writer, "{}", primera_linea)?;

    // Iterar por cada línea del archivo después de la primera
    for linea in reader.lines() {
        let linea = linea.map_err(|e| format!("No se pudo leer una línea del archivo: {}", e))?;

        // Verificar si la línea cumple con las condiciones
        if !cumple_condiciones(&linea, &query.condiciones, Some(primera_linea))? {
            // La línea no cumple con las condiciones, se debe mantener en el archivo temporal
            writeln!(writer, "{}", linea)?;
        }
    }
    // Cerrar el archivo de escritura temporal
    writer.flush()?;
    drop(writer); // Cerrar el archivo temporal

    // Reemplazar el archivo original con el archivo temporal
    fs::rename(&archivo_temporal, ruta_tablas)?;

    Ok(())
}

// Función para obtener el índice de la columna
fn obtener_indice_columna(
    nombre_columna: &str,
    primera_linea: Option<&str>,
) -> Result<usize, Box<dyn Error>> {
    if let Some(linea) = primera_linea {
        let columnas: Vec<&str> = linea.split(',').collect();
        if let Some(indice) = columnas.iter().position(|&col| col == nombre_columna) {
            return Ok(indice);
        }
    }
    //el ultimovalor de usize
    Err(Box::new(ErrorType::InvalidColumn(
        "Invalid column".to_string(),
    )))
}

// Función para ordenar líneas
fn ordenar_lineas(
    lineas: Vec<String>,
    order_by: &[(String, bool)],
    primera_linea: &str,
) -> Result<Vec<String>, Box<dyn Error>> {
    let mut lineas_ordenadas = lineas;

    // Obtén los índices de las columnas antes de ordenar
    let mut indices = Vec::new();
    for (campo, _) in order_by {
        let indice = obtener_indice_columna(campo, Some(primera_linea))?;
        indices.push(indice);
    }

    // Ordena las líneas
    lineas_ordenadas.sort_by(|a, b| {
        for (i, (_campo, ascendente)) in order_by.iter().enumerate() {
            let indice_campo = indices[i];

            let a_valor = a.split(',').nth(indice_campo).unwrap_or("");
            let b_valor = b.split(',').nth(indice_campo).unwrap_or("");

            let cmp_result = if *ascendente {
                a_valor.cmp(b_valor)
            } else {
                b_valor.cmp(a_valor)
            };

            if cmp_result != std::cmp::Ordering::Equal {
                return cmp_result;
            }
        }

        std::cmp::Ordering::Equal
    });

    Ok(lineas_ordenadas)
}

fn cumple_condiciones(
    linea: &str,
    condiciones_compuestas: &CondicionCompuesta,
    primera_linea: Option<&str>,
) -> Result<bool, Box<dyn Error>> {
    // Si no hay condiciones, se considera que cumple
    if condiciones_compuestas.pila_condiciones.is_empty() {
        return Ok(true);
    }

    let mut stack: Vec<bool> = Vec::new();

    for token in &condiciones_compuestas.pila_condiciones {
        match token {
            // Caso para SimpleCondition
            ElementoCondicionPila::SimpleCondition(condicion) => {
                let resultado_actual = evaluar_condicion(linea, condicion, primera_linea)?;
                stack.push(resultado_actual);
            }
            // Caso para Operator
            ElementoCondicionPila::Operator(operador) => {
                match operador {
                    Operator::And => {
                        let right = stack.pop().unwrap_or(false);
                        let left = stack.pop().unwrap_or(false);
                        let resultado = right && left;
                        stack.push(resultado);
                    }
                    Operator::Or => {
                        let right = stack.pop().unwrap_or(false);
                        let left = stack.pop().unwrap_or(false);
                        let resultado = right || left;
                        stack.push(resultado);
                    }
                    Operator::Not => {
                        let operand = stack.pop().unwrap_or(false);
                        let resultado = !operand;
                        stack.push(resultado);
                    }
                    // Otros operadores que no se manejan aquí
                    _ => {}
                }
            }
        }
    }

    // El último elemento en la pila será el resultado final
    Ok(stack.pop().unwrap_or(false))
}

// Evalúa una condición simple en una línea dada
fn evaluar_condicion(
    linea: &str,
    condicion: &SimpleCondition,
    primera_linea: Option<&str>,
) -> Result<bool, Box<dyn Error>> {
    let columnas: Vec<&str> = linea.split(',').collect();
    let index = obtener_indice_columna(&condicion.columna1, primera_linea)?;

    if condicion.es_comparacion_columnas {
        // Obtener índice de la segunda columna
        let index2 =
            obtener_indice_columna(condicion.columna2.as_deref().unwrap_or(""), primera_linea)?;

        // Verificar que ambos índices son válidos y obtener los valores
        if index < columnas.len() && index2 < columnas.len() {
            let valor1 = columnas[index];
            let valor2 = columnas[index2];

            // Comparar los valores de ambas columnas
            match condicion.operador {
                Operator::Equal => Ok(valor1 == valor2),
                Operator::NotEqual => Ok(valor1 != valor2),
                Operator::GreaterThan => Ok(valor1 > valor2),
                Operator::LessThan => Ok(valor1 < valor2),
                Operator::GreaterThanOrEqual => Ok(valor1 >= valor2),
                Operator::LessThanOrEqual => Ok(valor1 <= valor2),
                _ => Err(Box::new(ErrorType::InvalidSyntax(
                    "Invalid syntax".to_string(),
                ))),
            }
        } else {
            Err(Box::new(ErrorType::InvalidSyntax(
                "Invalid syntax".to_string(),
            )))
        }
    } else {
        // Verificar que el índice es válido y obtener el valor
        if index < columnas.len() {
            let valor_actual = columnas[index];

            // Comparar el valor de la columna con un valor constante
            match condicion.operador {
                Operator::Equal => Ok(valor_actual == condicion.valor.as_deref().unwrap_or("")),
                Operator::NotEqual => Ok(valor_actual != condicion.valor.as_deref().unwrap_or("")),
                Operator::GreaterThan => {
                    Ok(valor_actual > condicion.valor.as_deref().unwrap_or(""))
                }
                Operator::LessThan => Ok(valor_actual < condicion.valor.as_deref().unwrap_or("")),
                Operator::GreaterThanOrEqual => {
                    Ok(valor_actual >= condicion.valor.as_deref().unwrap_or(""))
                }
                Operator::LessThanOrEqual => {
                    Ok(valor_actual <= condicion.valor.as_deref().unwrap_or(""))
                }
                _ => Err(Box::new(ErrorType::InvalidSyntax(
                    "Invalid syntax".to_string(),
                ))),
            }
        } else {
            Err(Box::new(ErrorType::InvalidSyntax(
                "Invalid syntax".to_string(),
            )))
        }
    }
}

// Modifica imprimir_fila para devolver un String
fn imprimir_fila(
    linea: &str,
    columnas_utilizadas: &Vec<&str>,
    primera_linea: &str,
) -> Result<String, Box<dyn Error>> {
    let campos: Vec<&str> = linea.split(',').collect();
    let mut resultado = String::new();

    for columna in columnas_utilizadas {
        let indice = obtener_indice_columna(columna, Some(primera_linea))?;
        if let Some(valor) = campos.get(indice) {
            resultado.push_str(valor);
            resultado.push(',');
        }
    }
    resultado.pop(); // Remover la coma final
    Ok(resultado)
}

// Modifica imprimir_filas para devolver un String
fn imprimir_filas(
    lineas_ordenadas: Vec<String>,
    columnas_utilizadas: Vec<&str>,
    primera_linea: &str,
) -> Result<String, Box<dyn Error>> {
    let mut resultado = String::new();
    for linea in lineas_ordenadas {
        resultado.push_str(&imprimir_fila(&linea, &columnas_utilizadas, primera_linea)?);
        resultado.push('\n');
    }
    Ok(resultado)
}

//Verifica que todas las columnas especificadas estén presentes en primera_linea
pub fn verificar_columnas(columnas: &[&str], primera_linea: &str) -> Result<(), ErrorType> {
    let columnas_utilizadas: Vec<String> = columnas.iter().map(|&s| s.to_owned()).collect();
    for columna in &columnas_utilizadas {
        if !primera_linea.contains(columna) {
            return Err(ErrorType::InvalidColumn("Invalid column".to_string()));
        }
    }
    Ok(())
}
