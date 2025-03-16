// error_codes.rs

#[derive(Debug)]
pub enum ErrorCode {
    ServerError,
    ProtocolError,
    BadCredentials,
    UnavailableException,
    Overloaded,
    IsBootstrapping,
    TruncateError,
    WriteTimeout,
    ReadTimeout,
    SyntaxError,
    Unauthorized,
    InvalidQuery,
    ConfigError,
    AlreadyExists,
    Unprepared,
    Unknown(u16), // Para cualquier código de error no documentado
}

impl ErrorCode {
    /// Convierte un código de error de tipo u16 en un variante de ErrorCode.
    pub fn from_u16(code: u16) -> Self {
        match code {
            0x0000 => ErrorCode::ServerError,
            0x000A => ErrorCode::ProtocolError,
            0x0100 => ErrorCode::BadCredentials,
            0x1000 => ErrorCode::UnavailableException,
            0x1001 => ErrorCode::Overloaded,
            0x1002 => ErrorCode::IsBootstrapping,
            0x1003 => ErrorCode::TruncateError,
            0x1100 => ErrorCode::WriteTimeout,
            0x1200 => ErrorCode::ReadTimeout,
            0x2000 => ErrorCode::SyntaxError,
            0x2100 => ErrorCode::Unauthorized,
            0x2200 => ErrorCode::InvalidQuery,
            0x2300 => ErrorCode::ConfigError,
            0x2400 => ErrorCode::AlreadyExists,
            0x2500 => ErrorCode::Unprepared,
            _ => ErrorCode::Unknown(code),
        }
    }

    /// Convierte una variante de ErrorCode de nuevo a su representación u16 correspondiente.
    pub fn to_u16(&self) -> u16 {
        match *self {
            ErrorCode::ServerError => 0x0000,
            ErrorCode::ProtocolError => 0x000A,
            ErrorCode::BadCredentials => 0x0100,
            ErrorCode::UnavailableException => 0x1000,
            ErrorCode::Overloaded => 0x1001,
            ErrorCode::IsBootstrapping => 0x1002,
            ErrorCode::TruncateError => 0x1003,
            ErrorCode::WriteTimeout => 0x1100,
            ErrorCode::ReadTimeout => 0x1200,
            ErrorCode::SyntaxError => 0x2000,
            ErrorCode::Unauthorized => 0x2100,
            ErrorCode::InvalidQuery => 0x2200,
            ErrorCode::ConfigError => 0x2300,
            ErrorCode::AlreadyExists => 0x2400,
            ErrorCode::Unprepared => 0x2500,
            ErrorCode::Unknown(code) => code, // Devuelve el código directamente si es Unknown
        }
    }

    /// Proporciona una descripción para cada variante de error.
    pub fn description(&self) -> &'static str {
        match self {
            ErrorCode::ServerError => "Server error: something unexpected happened. This indicates a server-side bug.",
            ErrorCode::ProtocolError => "Protocol error: some client message triggered a protocol violation.",
            ErrorCode::BadCredentials => "Bad credentials: the CREDENTIALS request failed because the server did not accept the provided credentials.",
            ErrorCode::UnavailableException => "Unavailable exception: not enough nodes are available to process the request.",
            ErrorCode::Overloaded => "Overloaded: the coordinator node is overloaded and cannot process the request.",
            ErrorCode::IsBootstrapping => "Is_bootstrapping: the coordinator node is bootstrapping.",
            ErrorCode::TruncateError => "Truncate_error: an error occurred during a truncation operation.",
            ErrorCode::WriteTimeout => "Write_timeout: a timeout occurred during a write request.",
            ErrorCode::ReadTimeout => "Read_timeout: a timeout occurred during a read request.",
            ErrorCode::SyntaxError => "Syntax_error: the submitted query has a syntax error.",
            ErrorCode::Unauthorized => "Unauthorized: the logged-in user does not have permission to perform the query.",
            ErrorCode::InvalidQuery => "Invalid: the query is syntactically correct but invalid.",
            ErrorCode::ConfigError => "Config_error: the query is invalid due to a configuration issue.",
            ErrorCode::AlreadyExists => "Already_exists: the query attempted to create a keyspace or table that already exists.",
            ErrorCode::Unprepared => "Unprepared: the prepared statement ID is not known by this host.",
            ErrorCode::Unknown(_) => "Unknown error code.",
        }
    }

    /// Maneja los códigos de error imprimiendo sus descripciones.
    pub fn handle_error_code(error_code: u16) {
        let error = ErrorCode::from_u16(error_code);
        println!("Error: {}", error.description());
    }
}
