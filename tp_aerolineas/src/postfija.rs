use std::collections::VecDeque;

fn get_operator_precedence(op: &str) -> u8 {
    match op {
        "NOT" => 3,
        "AND" => 2,
        "OR" => 1,
        _ => 0, // Para parentesis
    }
}

// Dice si el operador es asociativo por la izquierda
fn is_left_associative(op: &str) -> bool {
    match op {
        "NOT" => false,       // NOT es asociativo por la derecha
        "AND" | "OR" => true, // AND y OR son asociativos por la izquierda
        _ => true,
    }
}

// Tokenizador mejorado que maneja operadores y valores entre comillas
fn tokenize_expression(expression: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current_token = String::new();
    let mut in_quotes = false;

    for c in expression.chars() {
        match c {
            // Manejar comillas simples para literales de texto
            '\'' => {
                current_token.push(c);
                in_quotes = !in_quotes;
            }
            // Manejar espacios dentro de literales entre comillas
            ' ' if in_quotes => current_token.push(c),
            // Manejar operadores y paréntesis
            ' ' | '(' | ')' if !in_quotes => {
                if !current_token.is_empty() {
                    tokens.push(current_token.clone());
                    current_token.clear();
                }
                if c != ' ' {
                    tokens.push(c.to_string());
                }
            }
            // Para otros caracteres (parte de operadores o valores)
            _ => current_token.push(c),
        }
    }

    // Añadir el último token, si existe
    if !current_token.is_empty() {
        tokens.push(current_token);
    }

    tokens
}

// Función que convierte una expresión infija a postfija usando Shunting Yard
pub fn shunting_yard(expression: &str) -> Vec<String> {
    let mut output_queue: VecDeque<String> = VecDeque::new();
    let mut operator_stack: Vec<String> = Vec::new();

    // Tokenizar la expresión
    let tokens = tokenize_expression(expression);

    for token in tokens {
        match token.as_str() {
            // Si es un paréntesis izquierdo, lo apilamos
            "(" => operator_stack.push(token.to_string()),
            // Si es un paréntesis derecho, desapilamos hasta encontrar el paréntesis izquierdo
            ")" => {
                while let Some(op) = operator_stack.pop() {
                    if op == "(" {
                        break;
                    } else {
                        output_queue.push_back(op);
                    }
                }
            }
            // Si es un operador (AND, OR, NOT)
            "AND" | "OR" | "NOT" => {
                while let Some(op) = operator_stack.last() {
                    if (is_left_associative(&token)
                        && get_operator_precedence(&token) <= get_operator_precedence(op))
                        || (!is_left_associative(&token)
                            && get_operator_precedence(&token) < get_operator_precedence(op))
                    {
                        output_queue.push_back(operator_stack.pop().unwrap_or_default());
                    } else {
                        break;
                    }
                }
                operator_stack.push(token.to_string());
            }
            // Si es un operando
            _ => output_queue.push_back(token.to_string()),
        }
    }

    // Desapilar todos los operadores restantes
    while let Some(op) = operator_stack.pop() {
        output_queue.push_back(op);
    }

    // Convertir la cola de salida en un vector
    output_queue.into_iter().collect()
}

//Post-procesa la expresión postfija para reordenar operadores y operandos si es necesario, donde los operadores relacionales se colocan correctamente.
pub fn parser_postfix(postfija: Vec<String>) -> Vec<String> {
    let mut new_postfix = Vec::new();
    for token in postfija {
        if let Some(prev_token) = new_postfix.last() {
            if prev_token == "="
                || prev_token == ">"
                || prev_token == "<"
                || prev_token == "<="
                || prev_token == ">="
                || prev_token == "!="
            {
                let right = match new_postfix.pop() {
                    Some(val) => val,
                    None => return vec![], // Manejar el error devolviendo un vector vacío
                };
                let left = match new_postfix.pop() {
                    Some(val) => val,
                    None => return vec![], // Manejar el error devolviendo un vector vacío
                };
                new_postfix.push(format!("{} {} {} ", left, right, token));
            } else {
                // Es un operando (condición como nombre = 'Tomas', etc.)
                new_postfix.push(token);
            }
        } else {
            // Es un operando (condición como nombre = 'Tomas', etc.)
            new_postfix.push(token);
        }
    }
    new_postfix
}
