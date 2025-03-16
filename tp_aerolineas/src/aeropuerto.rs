use crate::avion::{AirFlights, AirportFlights, AirportFlightsData};
use crate::cliente::{
    handle_authentication_request, handle_query, handle_startup, load_root_certificates,
    request_user_credentials,
};
use crate::threadpool_functions::threadpool;
use rustls::{ClientConfig, ClientConnection, ServerName, StreamOwned};
use serde::Deserialize;
use std::fmt;
use std::io::{Error, ErrorKind};
use std::net::TcpStream;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread::{self};
use std::time::Duration;
/// Estructura que representa el pool de hilos.
/// Se utiliza para manejar múltiples tareas concurrentemente, distribuyendo trabajos entre un conjunto fijo de hilos.

/// Enum que representa los códigos de aeropuertos internacionales.
/// Cada variante corresponde a un código IATA específico para aeropuertos en América del Sur.
#[derive(Debug, Clone, Deserialize)]
pub enum AirportCodes {
    /// Ezeiza, Buenos Aires, Argentina
    EZE,
    /// Santiago, Chile
    SCL,
    /// São Paulo, Brasil
    GRU,
    /// Bogotá, Colombia
    BOG,
    /// Lima, Perú
    LIM,
    /// Caracas, Venezuela
    CCS,
}
impl FromStr for AirportCodes {
    type Err = ();

    fn from_str(input: &str) -> Result<AirportCodes, Self::Err> {
        match input {
            "EZE" => Ok(AirportCodes::EZE),
            "SCL" => Ok(AirportCodes::SCL),
            "GRU" => Ok(AirportCodes::GRU),
            "BOG" => Ok(AirportCodes::BOG),
            "LIM" => Ok(AirportCodes::LIM),
            "CCS" => Ok(AirportCodes::CCS),
            _ => Err(()),
        }
    }
}

// Estructura para representar un aeropuerto
pub struct Airport {
    pub name: AirportCodes,
    pub position: (f64, f64),
    pub ip: String,
    pub socket: Option<StreamOwned<ClientConnection, TcpStream>>,
    pub upcoming_flights: Vec<AirportFlights>,
    pub incoming_flights: Vec<AirFlights>,
    pub outgoing_flights: Vec<AirFlights>,
}

impl AirportCodes {
    pub fn get_coordinates(&self) -> (f64, f64) {
        match self {
            AirportCodes::EZE => (9.0219, -9.0000),
            AirportCodes::SCL => (15.0219, -78.1469),
            AirportCodes::GRU => (32.4356, 25.0000),
            AirportCodes::BOG => (69.8000, -78.1469),
            AirportCodes::LIM => (48.8000, -89.1469),
            AirportCodes::CCS => (82.0000, -51.1469),
        }
    }

    pub fn get_airport_code(&self) -> &'static str {
        match self {
            AirportCodes::EZE => "EZE",
            AirportCodes::SCL => "SCL",
            AirportCodes::GRU => "GRU",
            AirportCodes::BOG => "BOG",
            AirportCodes::LIM => "LIM",
            AirportCodes::CCS => "CCS",
        }
    }
}

impl fmt::Display for AirportCodes {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.get_airport_code())
    }
}
pub fn load_aircraft_from_json(json_content: &str) -> Vec<AirportFlights> {
    let aviones_data: Vec<AirportFlightsData> =
        serde_json::from_str(json_content).expect("Error al parsear JSON");
    aviones_data
        .into_iter()
        .map(|data| data.to_airportflights())
        .collect()
}

pub fn ask_for_user_password() -> Result<(String, String), Error> {
    match request_user_credentials() {
        Ok((usuario, password)) => Ok((usuario, password)),
        Err(e) => {
            println!("Error al obtener usuario y contraseña: {}", e);
            Err(e)
        }
    }
}

pub fn authenticate_user(
    tls_stream: &mut StreamOwned<ClientConnection, TcpStream>,
    user: &str,
    password: &str,
) -> Result<(), Error> {
    match handle_authentication_request(tls_stream, user.to_string(), password.to_string()) {
        Ok(()) => {
            println!("Autenticación exitosa");
            Ok(())
        }
        Err(e) => {
            println!("Error al autenticar: {:?}", e);
            Err(e)
        }
    }
}

type TlsStream = Arc<Mutex<StreamOwned<ClientConnection, TcpStream>>>;
type ConnectionResult = Result<(TcpStream, TlsStream), Error>;

pub fn create_connection_stream(
    config: Arc<ClientConfig>,
    server_name: ServerName,
    stream: TcpStream,
    user: String,
    password: String,
) -> ConnectionResult {
    let client = ClientConnection::new(config.clone(), server_name.clone()).map_err(|e| {
        Error::new(
            ErrorKind::InvalidData,
            format!("Error al crear conexión TLS: {:?}", e),
        )
    })?;

    let cloned_stream = stream.try_clone().map_err(|e| {
        Error::new(
            ErrorKind::Other,
            format!("Error al clonar el stream TCP: {:?}", e),
        )
    })?;

    let tls_stream = Arc::new(Mutex::new(StreamOwned::new(client, cloned_stream)));

    {
        let mut tls_guard = tls_stream.lock().map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Error al adquirir el lock del stream TLS: {:?}", e),
            )
        })?;
        handle_startup(&mut tls_guard)?;
    }

    {
        let mut tls_guard = tls_stream.lock().map_err(|e| {
            Error::new(
                ErrorKind::Other,
                format!("Error al adquirir el lock del stream TLS: {:?}", e),
            )
        })?;
        authenticate_user(&mut tls_guard, &user, &password)?;
    }

    Ok((stream, tls_stream))
}

pub fn find_connection() -> Result<TcpStream, Error> {
    let connections = vec![
        "localhost:8080",
        "localhost:8081",
        "localhost:8082",
        "localhost:8083",
    ];

    for _ in 0..3 {
        for address in &connections {
            match TcpStream::connect(address) {
                Ok(s) => {
                    println!("Conectado al servidor {}", address);
                    return Ok(s);
                }
                Err(e) => {
                    println!("Error al conectar con {}: {}", address, e);
                    thread::sleep(Duration::from_secs(2));
                }
            }
        }
    }
    Err(Error::new(
        ErrorKind::NotConnected,
        "No se pudo conectar a ningún servidor",
    ))
}

pub fn try_connection(stream: &TcpStream) -> bool {
    let mut buffer = [0; 1];

    // Establecer modo no bloqueante
    if let Err(e) = stream.set_nonblocking(true) {
        eprintln!("Error al configurar modo no bloqueante: {}", e);
        return false;
    }

    match stream.peek(&mut buffer) {
        Ok(0) => false,
        Ok(_) => {
            println!("Continúo conectada");
            true
        }
        Err(e) if e.kind() == ErrorKind::WouldBlock => {
            println!("Continúo conectada");
            true
        }

        Err(_) => false,
    }
}

pub fn airport_run() -> std::io::Result<()> {
    let root_cert_store = load_root_certificates()?;
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    let config = Arc::new(config);
    let server_name = ServerName::try_from("localhost")
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "Nombre del servidor no válido"))?;

    let json_content = include_str!("aeropuertos_initialize.json");

    let aviones: Arc<Mutex<Vec<AirportFlights>>> =
        Arc::new(Mutex::new(load_aircraft_from_json(json_content)));

    let (user, password) = ask_for_user_password()?;
    let stream = find_connection()?;
    let (_, mut tls_stream) = match create_connection_stream(
        config.clone(),
        server_name.clone(),
        stream,
        user.clone(),
        password.clone(),
    ) {
        Ok((stream, tls_stream)) => (stream, tls_stream),
        Err(e) => {
            eprintln!("Error al crear el stream de conexión: {:?}", e);
            return Err(e);
        }
    };
    let pool = threadpool::ThreadPool::new(3)?;
    loop {
        let tls_stream_clone = tls_stream.clone();

        if let Ok(mut tls_guard) = tls_stream_clone.lock() {
            if !try_connection(tls_guard.get_mut()) {
                println!("No se pudo conectar, buscando nueva conexión.");
                let stream = find_connection()?;
                tls_stream = match create_connection_stream(
                    config.clone(),
                    server_name.clone(),
                    stream,
                    user.clone(),
                    password.clone(),
                ) {
                    Ok((_, new_tls_stream)) => new_tls_stream,
                    Err(e) => {
                        eprintln!("Error al crear el stream de conexión: {:?}", e);
                        return Err(e);
                    }
                };
            }
        } else {
            eprintln!("Error al adquirir el lock del stream TLS");
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "No se pudo adquirir el lock del stream TLS",
            ));
        }

        let aviones = Arc::clone(&aviones);
        let _ = pool.execute({
            let tls_stream = Arc::clone(&tls_stream);
            let aviones = Arc::clone(&aviones);

            move || {
                let mut stream = tls_stream.lock().unwrap_or_else(|e| {
                    eprintln!("Error al adquirir el lock del stream TLS: {:?}", e);
                    std::process::exit(1);
                });

                let mut aviones = aviones.lock().unwrap_or_else(|e| {
                    eprintln!("Error al adquirir el lock de aviones: {:?}", e);
                    std::process::exit(1);
                });
                for avion in aviones.iter_mut() {
                    let delta_time = 30.0;
                    avion.refresh_flight_status(delta_time);

                    let query = avion.generate_insert_query();
                    println!(
                        "Enviando actualización de posición y combustible: {}",
                        query
                    );

                    if let Err(e) = handle_query(&mut stream, query) {
                        eprintln!("Error al enviar la consulta: {}", e);
                    }
                }
            }
        });

        thread::sleep(Duration::from_secs(10));
    }
}
