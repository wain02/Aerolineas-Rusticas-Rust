// error.rs

use std::fmt;

// Define los tipos de errores
#[derive(Debug)]
pub enum ErrorType {
    InvalidTable(String),
    InvalidColumn(String),
    InvalidSyntax(String),
    Error(String),
}

// Implementa fmt::Display para ErrorType
impl fmt::Display for ErrorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorType::InvalidTable(description) => {
                write!(f, "Invalid table name: {}", description)
            }
            ErrorType::InvalidColumn(description) => {
                write!(f, "Invalid column name: {}", description)
            }
            ErrorType::InvalidSyntax(description) => {
                write!(f, "Invalid query syntax: {}", description)
            }
            ErrorType::Error(description) => write!(f, "Error: {}", description),
        }
    }
}

// Implementa el trait std::error::Error para ErrorType
impl std::error::Error for ErrorType {}

// Función para imprimir errores, la dejo para el main
pub fn print_error(error_type: ErrorType, description: &str) {
    println!("[{:?}]: {}", error_type, description);
}
