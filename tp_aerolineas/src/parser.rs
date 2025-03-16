use crate::error::ErrorType;
use crate::nodo_cassandra_functions::{
    primary_key::PrimaryKey, replication_class::ReplicationClass,
    replication_config::ReplicationConfig,
};
use crate::parser_functions::{
    adapt::AdaptMessage, condicion_compuesta::CondicionCompuesta, consistency::Consistency,
    create_keyspace_query::CreateKeyspaceQuery, elemento_condicion_pila::ElementoCondicionPila,
    operator::Operator, query_create_table::CreateTableQuery, query_delete::DeleteQuery,
    query_insert::InsertQuery, query_select::SelectQuery, query_update::UpdateQuery,
    simple_condition::SimpleCondition,
};
use crate::postfija::{parser_postfix, shunting_yard}; // Reemplaza `create` por `crate`

// Tipos de consulta
#[derive(Debug)]
pub enum QueryType {
    Select(SelectQuery),
    Insert(InsertQuery),
    Update(UpdateQuery),
    Delete(DeleteQuery),
    CreateTable(CreateTableQuery),
    CreateKeyspace(CreateKeyspaceQuery),
    Adapt(AdaptMessage),
}

//Evalua si eso no columna un valor
fn is_column(operando: &str) -> bool {
    if operando.starts_with('\'') && operando.ends_with('\'') {
        return false;
    }

    if operando.parse::<f64>().is_ok() {
        return false;
    }

    true
}

// Recibe el query, el contenido que se quiere buscar y los posibles delimitadores a cuando termina ese contenido
pub fn find_content(query: &str, parametro: &str, delimitadores: &[&str]) -> Option<String> {
    let start_index = match query.find(parametro) {
        Some(index) => index + parametro.len(),
        None => return None,
    };

    let remaining_query = &query[start_index..];

    let mut all_delimitadores = delimitadores.to_vec();
    all_delimitadores.push(";");

    let end_content_index = all_delimitadores
        .iter()
        .filter_map(|&delim| remaining_query.find(delim))
        .min()
        .unwrap_or(remaining_query.len());

    let content = &remaining_query[..end_content_index];
    let trimmed_content = content.trim();

    if trimmed_content.is_empty() {
        return Some(String::new());
    }

    Some(trimmed_content.to_string())
}

//se encarga de parsear los operadores
fn parse_operator(op_str: &str) -> Result<Operator, ErrorType> {
    match op_str {
        "=" => Ok(Operator::Equal),
        "!=" => Ok(Operator::NotEqual),
        ">" => Ok(Operator::GreaterThan),
        "<" => Ok(Operator::LessThan),
        ">=" => Ok(Operator::GreaterThanOrEqual),
        "<=" => Ok(Operator::LessThanOrEqual),
        "AND" => Ok(Operator::And),
        "OR" => Ok(Operator::Or),
        "NOT" => Ok(Operator::Not),
        _ => Err(ErrorType::InvalidSyntax("Invalid operator".to_string())),
    }
}
//parsea las partes de una condicion simple, de manera de admitir espacios en los trings
fn parse_simple_condition_parts(cond_str: &str) -> Result<Vec<&str>, ErrorType> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut inside_string = false;

    for (i, c) in cond_str.char_indices() {
        match c {
            ' ' if !inside_string => {
                if start != i {
                    parts.push(&cond_str[start..i]); // Guardo la referencia del substring original
                }
                start = i + 1; // Actualizo el inicio al siguiente carácter
            }
            '\'' => {
                inside_string = !inside_string;
            }
            _ => {}
        }
    }

    if start < cond_str.len() {
        parts.push(&cond_str[start..]);
    }

    if parts.len() < 3 {
        return Err(ErrorType::InvalidSyntax("Invalid syntax".to_string()));
    }

    Ok(parts)
}

fn parse_simple_condition(cond_str: &str) -> Result<SimpleCondition, ErrorType> {
    let parts: Vec<&str> = parse_simple_condition_parts(cond_str)?;
    if parts.len() < 3 {
        return Err(ErrorType::InvalidSyntax(
            "Menos de 3 partes en una condicion simple".to_string(),
        ));
    }
    let columna1;
    let operador;
    let valor;
    let columna2;
    let es_comparacion_columnas;

    if parts[0] == "NOT" {
        columna1 = parts[1].to_string();
        operador = parse_operator(parts[2])?;
        if is_column(parts[3]) {
            columna2 = Some(parts[3].to_string());
            valor = None;
            es_comparacion_columnas = true;
        } else {
            columna2 = None;
            valor = Some(parts[3..].join(" ").trim_matches('\'').to_string());
            es_comparacion_columnas = false;
        }
    } else {
        columna1 = parts[0].to_string();
        operador = parse_operator(parts[1])?;
        if is_column(parts[2]) {
            columna2 = Some(parts[2].to_string());
            valor = None;
            es_comparacion_columnas = true;
        } else {
            columna2 = None;
            valor = Some(parts[2..].join(" ").trim_matches('\'').to_string());
            es_comparacion_columnas = false;
        }
    }
    Ok(SimpleCondition {
        columna1,
        operador,
        columna2,
        valor,
        es_comparacion_columnas,
    })
}

fn parse_conditions(where_str: &str) -> Result<CondicionCompuesta, ErrorType> {
    let query = where_str.to_string();

    let mut condiciones = CondicionCompuesta {
        pila_condiciones: Vec::new(),
    };

    let postfija = shunting_yard(&query);

    let nueva_postfija = parser_postfix(postfija);

    for token in nueva_postfija {
        if token == "AND" || token == "OR" || token == "NOT" {
            let operador = parse_operator(&token)?;
            condiciones
                .pila_condiciones
                .push(ElementoCondicionPila::Operator(operador));
        } else {
            let condicion = parse_simple_condition(&token)?;
            condiciones
                .pila_condiciones
                .push(ElementoCondicionPila::SimpleCondition(condicion));
        }
    }
    Ok(condiciones)
}
// Función para analizar la cláusula ORDER BY
fn parse_order_by(order_by_str: &str) -> Vec<(String, bool)> {
    let mut order_by = Vec::new();
    let parts: Vec<&str> = order_by_str.split(',').map(|s| s.trim()).collect();

    for part in parts {
        let mut tokens = part.split_whitespace();
        let column = match tokens.next() {
            Some(col) => col.to_string(),
            None => continue,
        };

        let direction = match tokens.next() {
            Some(dir) => dir.to_uppercase(),
            None => "ASC".to_string(), // Por defecto, asumimos ASC
        };

        let is_ascending = direction != "DESC";
        order_by.push((column, is_ascending));
    }

    order_by
}

fn handle_select_query(query: &str) -> Result<QueryType, ErrorType> {
    let columns = find_content(
        query,
        "SELECT",
        &["FROM", "USING CONSISTENCY", "WHERE", "ORDER BY"],
    )
    .unwrap_or_default();
    let table = find_content(query, "FROM", &["USING CONSISTENCY", "WHERE", "ORDER BY"])
        .unwrap_or_default();
    let consistency_str =
        find_content(query, "USING CONSISTENCY", &["WHERE", "ORDER BY"]).unwrap_or_default();
    let conditions_str = find_content(query, "WHERE", &["ORDER BY"]).unwrap_or_default();
    let order_by_str = find_content(query, "ORDER BY", &[]).unwrap_or_default();

    let order_by = parse_order_by(&order_by_str);

    let conditions = if !conditions_str.is_empty() {
        parse_conditions(&conditions_str)?
    } else {
        CondicionCompuesta {
            pila_condiciones: Vec::new(),
        }
    };

    // Llamamos a la nueva función modularizada para extraer el keyspace y el nombre de la tabla
    let (keyspace, table_name) = extract_keyspace_and_table(&table)?;

    let consistency = match consistency_str.to_uppercase().as_str() {
        "QUORUM" => Consistency::QUORUM,
        "ONE" => Consistency::ONE,
        _ => {
            return Err(ErrorType::InvalidSyntax(
                "Invalid consistency level".to_string(),
            ))
        }
    };

    Ok(QueryType::Select(SelectQuery {
        columnas: columns.split(',').map(|s| s.trim().to_string()).collect(),
        tabla: table_name,
        keyspace,
        condiciones: conditions,
        order_by,
        consistency,
    }))
}

fn handle_insert_query(query: &str) -> Result<QueryType, ErrorType> {
    let table = find_content(query, "INTO", &["("]).unwrap_or_default();
    let columns = find_content(query, "(", &["USING CONSISTENCY", "VALUES"])
        .unwrap_or_default()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .to_string();
    let consistency_str = find_content(query, "USING CONSISTENCY", &["VALUES"]).unwrap_or_default();
    let values_str = find_content(query, "VALUES", &[";"]).unwrap_or_default();
    let values_str = values_str.trim();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut current_row: Vec<String> = Vec::new();
    let mut current_value = String::new();
    let mut inside_value = false;
    for c in values_str.chars() {
        match c {
            '(' => {
                current_row = Vec::new();
                current_value.clear();
            }
            ')' => {
                current_row.push(current_value.trim().to_string());
                rows.push(current_row.clone());
                current_value.clear();
            }
            ',' => {
                if inside_value {
                    current_value.push(c);
                } else {
                    current_row.push(current_value.trim().to_string());
                    current_value.clear();
                }
            }
            '\'' | '"' => {
                inside_value = !inside_value;
            }
            _ => {
                current_value.push(c);
            }
        }
    }
    // Llamamos a la nueva función modularizada para extraer el keyspace y el nombre de la tabla
    let (keyspace, table_name) = extract_keyspace_and_table(&table)?;

    let consistency = match consistency_str.to_uppercase().as_str() {
        "QUORUM" => Consistency::QUORUM,
        "ONE" => Consistency::ONE,
        _ => {
            return Err(ErrorType::InvalidSyntax(
                "Invalid consistency level".to_string(),
            ))
        }
    };

    Ok(QueryType::Insert(InsertQuery {
        tabla: table_name,
        keyspace,
        columnas: columns.split(',').map(|s| s.trim().to_string()).collect(),
        valores: rows,
        consistency,
    }))
}

// Función para analizar la cláusula SET
fn parse_set(set_str: &str) -> Result<Vec<(String, String)>, ErrorType> {
    let mut set = Vec::new();
    let parts: Vec<&str> = set_str.split(',').map(|s| s.trim()).collect();

    for part in parts {
        let mut tokens = part.split('=').map(|s| s.trim());
        let column = match tokens.next() {
            Some(col) => col.to_string(),
            None => return Err(ErrorType::InvalidSyntax("No hay token columna".to_string())),
        };

        let value = match tokens.next() {
            Some(val) => val.to_string(),
            None => return Err(ErrorType::InvalidSyntax("No hay token valor".to_string())),
        };

        set.push((column, value));
    }

    Ok(set)
}

pub fn handle_adapt_node(query: &str) -> Result<QueryType, ErrorType> {
    let cantidad_nodos = find_content(query, "ADAPT NODE TO:", &[";"]).unwrap_or_default();

    Ok(QueryType::Adapt(AdaptMessage {
        nodos_cantidad: cantidad_nodos
            .parse::<u8>()
            .map_err(|_| ErrorType::InvalidSyntax("Invalid node count".to_string()))?,
    }))
}

fn handle_update_query(query: &str) -> Result<QueryType, ErrorType> {
    let table =
        find_content(query, "UPDATE", &["SET", "USING CONSISTENCY", "WHERE"]).unwrap_or_default();
    let set_str = find_content(query, "SET", &["USING CONSISTENCY", "WHERE"]).unwrap_or_default();
    let consistency_str = find_content(query, "USING CONSISTENCY", &["WHERE"]).unwrap_or_default();
    let conditions_str = find_content(query, "WHERE", &[]).unwrap_or_default();

    let set = parse_set(&set_str)?;

    let conditions = if !conditions_str.is_empty() {
        parse_conditions(&conditions_str)?
    } else {
        CondicionCompuesta {
            pila_condiciones: Vec::new(),
        }
    };

    // Llamamos a la nueva función modularizada para extraer el keyspace y el nombre de la tabla
    let (keyspace, table_name) = extract_keyspace_and_table(&table)?;

    let consistency = match consistency_str.to_uppercase().as_str() {
        "QUORUM" => Consistency::QUORUM,
        "ONE" => Consistency::ONE,
        _ => {
            return Err(ErrorType::InvalidSyntax(
                "Invalid consistency level".to_string(),
            ))
        }
    };

    Ok(QueryType::Update(UpdateQuery {
        tabla: table_name,
        keyspace,
        set,
        condiciones: conditions,
        consistency,
    }))
}

fn handle_delete_query(query: &str) -> Result<QueryType, ErrorType> {
    let table =
        find_content(query, "DELETE FROM", &["USING CONSISTENCY", "WHERE"]).unwrap_or_default();
    let consistency_str = find_content(query, "USING CONSISTENCY", &["WHERE"]).unwrap_or_default();
    let conditions_str = find_content(query, "WHERE", &[]).unwrap_or_default();

    let conditions = if !conditions_str.is_empty() {
        parse_conditions(&conditions_str)?
    } else {
        CondicionCompuesta {
            pila_condiciones: Vec::new(),
        }
    };

    // Llamamos a la nueva función modularizada para extraer el keyspace y el nombre de la tabla
    let (keyspace, table_name) = extract_keyspace_and_table(&table)?;

    let consistency = match consistency_str.to_uppercase().as_str() {
        "QUORUM" => Consistency::QUORUM,
        "ONE" => Consistency::ONE,
        _ => {
            return Err(ErrorType::InvalidSyntax(
                "Invalid consistency level".to_string(),
            ))
        }
    };

    Ok(QueryType::Delete(DeleteQuery {
        tabla: table_name,
        keyspace,
        condiciones: conditions,
        consistency,
    }))
}

fn split_columns_and_keys(input: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = String::new();
    let mut in_parentheses = false;

    let (columns, primary_key_string) = if let Some(index) = input.find("PRIMARY KEY") {
        input.split_at(index)
    } else {
        (input, "")
    };

    for c in columns.chars() {
        if c == '(' {
            in_parentheses = true;
        } else if c == ')' {
            in_parentheses = false;
        }

        if c == ',' && !in_parentheses {
            // Si no estamos dentro de paréntesis, consideramos que es un delimitador de columna
            result.push(current.trim().to_string());
            current.clear();
        } else {
            // Si estamos dentro de paréntesis, seguimos agregando a la cadena actual
            current.push(c);
        }
    }

    result.push(primary_key_string.trim().to_string());

    if !current.is_empty() {
        result.push(current.trim().to_string());
    }

    result
}

/// Procesa una consulta `CREATE TABLE` y devuelve un `QueryType::CreateTable`
/// en caso de éxito o un `ErrorType` si hay algún error de sintaxis.
pub fn handle_create_table_query(query: &str) -> Result<QueryType, ErrorType> {
    // Extraemos el nombre de la tabla
    let table = find_content(query, "CREATE TABLE", &["("])
        .unwrap_or_default()
        .trim()
        .to_string();
    // Extraemos las columnas y la clave primaria
    let columns_and_keys = find_content(query, "(", &[");"]).unwrap_or_default();
    // Separamos las definiciones de columnas y claves respetando los paréntesis
    let column_definitions = split_columns_and_keys(&columns_and_keys);
    let mut columns = Vec::new();
    let mut primary_key = PrimaryKey {
        partition_key: Vec::new(),
        clustering_key: Vec::new(),
    };
    let mut found_primary_key = false;
    for def in column_definitions {
        let trimmed_def = def.trim();
        if trimmed_def.is_empty() {
            continue;
        }
        if trimmed_def.contains("PRIMARY KEY") {
            if found_primary_key {
                return Err(ErrorType::InvalidSyntax(
                    "Sólo se puede definir una clave primaria".to_string(),
                ));
            }
            found_primary_key = true;
            process_primary_key(trimmed_def, &mut primary_key, &mut columns)?;
        //}  else if trimmed_def.contains("CLUSTERING KEY") {
        //process_clustering_key(trimmed_def, &mut primary_key)?;
        } else {
            // Aquí llamamos a la nueva función para manejar las definiciones de columnas
            match process_column_definition(trimmed_def, &mut columns) {
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
    }
    validate_columns_and_keys(&columns, &primary_key)?;
    // Llamamos a la nueva función modularizada para extraer el keyspace y el nombre de la tabla
    let (keyspace, table_name) = extract_keyspace_and_table(&table)?;
    // Envolvemos el resultado en QueryType::CreateTable
    Ok(QueryType::CreateTable(CreateTableQuery {
        tabla: table_name,
        columnas: columns,
        primary_key,
        keyspace,
    }))
}

fn process_primary_key(
    trimmed_def: &str,
    primary_key: &mut PrimaryKey,
    columns: &mut Vec<(String, String)>,
) -> Result<(), ErrorType> {
    if trimmed_def.starts_with("PRIMARY KEY") {
        if let (Some(start), Some(end)) = (trimmed_def.find('('), trimmed_def.rfind(')')) {
            let trimmed_start = &trimmed_def[start + 1..end];
            if let (Some(start2), Some(end2)) = (trimmed_start.find('('), trimmed_start.find(')')) {
                let key_parts: Vec<&str> = trimmed_start[start2 + 1..end2]
                    .split(',')
                    .map(|s| s.trim())
                    .collect();
                for key in key_parts {
                    primary_key.partition_key.push(key.to_string());
                }
                let clustering_parts: Vec<&str> = trimmed_start[end2 + 2..]
                    .split(',')
                    .map(|s| s.trim())
                    .collect();
                for key in clustering_parts {
                    primary_key.clustering_key.push(key.to_string());
                }
            } else {
                let key_parts: Vec<&str> = trimmed_def[start + 1..end]
                    .split(',')
                    .map(|s| s.trim())
                    .collect();
                let mut primera = false;
                for key in key_parts {
                    if !primera {
                        primary_key.partition_key.push(key.to_string());
                        primera = true;
                    } else {
                        primary_key.clustering_key.push(key.to_string());
                    }
                }
            }
        }
    } else {
        let trimmed_def_replaced = trimmed_def.replace("PRIMARY KEY", "");
        let trimmed_def_replaced = trimmed_def_replaced.trim();
        let column_parts: Vec<&str> = trimmed_def_replaced.split_whitespace().collect();

        if column_parts.len() == 2 {
            let column_name = column_parts[0].to_string();
            primary_key.partition_key.push(column_name);
            process_column_definition(trimmed_def_replaced, columns)?;
        } else {
            return Err(ErrorType::InvalidSyntax(
                "Definición de columna inválida".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_columns_and_keys(
    columns: &[(String, String)],
    primary_key: &PrimaryKey,
) -> Result<(), ErrorType> {
    // Verificación adicional: ¿Hay columnas definidas?
    if columns.is_empty() {
        return Err(ErrorType::InvalidSyntax(
            "No se definieron columnas en la tabla".to_string(),
        ));
    }

    // Verificación adicional: ¿Existe una clave primaria?
    if primary_key.partition_key.is_empty() {
        return Err(ErrorType::InvalidSyntax(
            "No se definió una clave primaria".to_string(),
        ));
    }

    // Verificación adicional: Si alguna columna tiene un tipo de datos incompleto (posible caso de paréntesis sin cerrar)
    for (_col_name, col_type) in columns {
        if !col_type.contains(")") && col_type.contains("(") {
            return Err(ErrorType::InvalidSyntax(
                "Tipo de dato malformado, falta cerrar paréntesis".to_string(),
            ));
        }
    }
    Ok(())
}

// Función modularizada para extraer keyspace y nombre de la tabla
fn extract_keyspace_and_table(table: &str) -> Result<(String, String), ErrorType> {
    let keyspace;
    let table_name;

    if table.contains(".") {
        // Definido el keyspace
        let table_parts: Vec<&str> = table.split('.').collect();
        if table_parts.len() != 2 {
            return Err(ErrorType::InvalidSyntax(
                "Nombre de tabla inválido".to_string(),
            ));
        } else {
            table_name = table_parts[1].trim().to_string();
            keyspace = table_parts[0].trim().to_string();
        }
    } else {
        keyspace = "default_keyspace".to_string();
        table_name = table.to_string();
    }

    Ok((keyspace, table_name))
}

// Nueva función para manejar las definiciones de columnas
fn process_column_definition(
    definition: &str,
    columns: &mut Vec<(String, String)>,
) -> Result<(), ErrorType> {
    let column_parts: Vec<&str> = definition.split_whitespace().collect();
    if column_parts.len() < 2 {
        return Err(ErrorType::InvalidSyntax(
            "Definición de columna inválida".to_string(),
        ));
    }
    let column_name = column_parts[0].to_string();
    let column_type = column_parts[1].to_string(); // Puedes agregar más validaciones aquí
    columns.push((column_name, column_type));
    Ok(())
}

// Función que maneja el parsing de la consulta CREATE KEYSPACE
pub fn handle_create_keyspace_query(query: &str) -> Result<QueryType, ErrorType> {
    let keyspace_name = find_content(query, "CREATE KEYSPACE", &["WITH"])
        .unwrap_or_default()
        .trim()
        .to_string();

    let replication_settings = find_content(query, "WITH REPLICATION = {", &["};"])
        .unwrap_or_default()
        .trim()
        .to_string();

    // Parsear los detalles de la configuración de replicación
    let replication_config = parse_replication_settings(&replication_settings)?;

    if keyspace_name.is_empty() {
        return Err(ErrorType::InvalidSyntax(
            "No se definió el nombre del keyspace".to_string(),
        ));
    }

    Ok(QueryType::CreateKeyspace(CreateKeyspaceQuery {
        name: keyspace_name,
        replication_strategy: replication_config,
    }))
}

// Función para parsear las configuraciones de replicación
fn parse_replication_settings(settings: &str) -> Result<ReplicationConfig, ErrorType> {
    // Identificar la estrategia de replicación (SimpleStrategy o NetworkTopologyStrategy)
    if settings.contains("SimpleStrategy") {
        let replication_factor = parse_replication_factor(settings)?;
        Ok(ReplicationConfig {
            class: ReplicationClass::SimpleStrategy,
            replication_factor,
        })
    } else if settings.contains("NetworkTopologyStrategy") {
        // Para NetworkTopologyStrategy, se debe manejar una configuración más compleja.
        // Aquí solo lo simplificamos al factor de replicación.
        let replication_factor = parse_replication_factor(settings)?;
        Ok(ReplicationConfig {
            class: ReplicationClass::NetworkTopologyStrategy,
            replication_factor,
        })
    } else {
        Err(ErrorType::InvalidSyntax(
            "Estrategia de replicación no soportada".to_string(),
        ))
    }
}

// Función para parsear el factor de replicación
fn parse_replication_factor(settings: &str) -> Result<u32, ErrorType> {
    if let Some(pos) = settings.find("'replication_factor':") {
        let after_rf = &settings[pos + "'replication_factor':".len()..];
        let replication_factor: u32 = after_rf
            .trim_matches(&[' ', '\''][..])
            .split(',')
            .next()
            .ok_or_else(|| {
                ErrorType::InvalidSyntax("No se encontró el factor de replicación".to_string())
            })?
            .trim()
            .parse()
            .map_err(|_| {
                ErrorType::InvalidSyntax("Error al parsear el factor de replicación".to_string())
            })?;
        Ok(replication_factor)
    } else {
        Err(ErrorType::InvalidSyntax(
            "No se especificó 'replication_factor'".to_string(),
        ))
    }
}

//Procesa el query y parsea el tipo de query, devolviendolo en un Result
pub fn determine_query_type(query: &str) -> Result<QueryType, ErrorType> {
    if query.starts_with("SELECT") {
        handle_select_query(query)
    } else if query.starts_with("INSERT") {
        handle_insert_query(query)
    } else if query.starts_with("UPDATE") {
        handle_update_query(query)
    } else if query.starts_with("DELETE") {
        handle_delete_query(query)
    } else if query.starts_with("CREATE TABLE") {
        handle_create_table_query(query)
    } else if query.starts_with("CREATE KEYSPACE") {
        handle_create_keyspace_query(query)
    } else if query.starts_with("ADAPT NODE TO:") {
        handle_adapt_node(query)
    } else {
        Err(ErrorType::InvalidSyntax("Invalid query type".to_string()))
    }
}
