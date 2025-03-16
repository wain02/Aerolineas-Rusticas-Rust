use crate::aeropuerto::{self, AirportCodes};
use crate::cliente::{handle_query, load_root_certificates};
use crate::threadpool_functions::threadpool;
use rustls::{ClientConfig, ServerName};
use serde::Deserialize;
use std::fmt;
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread::{self};
use std::time::Duration;

/// Estructura para encapsular los parámetros necesarios para crear un AirFlight.
pub struct AirFlightParameters {
    pub flight_number: String,
    pub origin: AirportCodes,
    pub destination: AirportCodes,
    pub altitude: String,
    pub speed: String,
    pub airline: String,
    pub position: (f64, f64),
    pub direction: Direction,
    pub fuel_percentage: f64,
    pub status: Status,
    pub date: String,
}

/// Estructura para encapsular los parámetros necesarios para crear un AirportFlights.
pub struct AirportFlightParameters {
    pub flight_number: String,
    pub origin: AirportCodes,
    pub destination: AirportCodes,
    pub airline: String,
    pub status: Status,
    pub departure: String,
    pub date: String,
}

/// Representa el tipo de vuelo según su dirección en el sistema.
/// Puede ser Entrante, Saliente o Próximo.
pub enum FlightType {
    IncomingFlight,
    OutgoingFlight,
    UpcomingFlight,
}

/// Enum que representa las direcciones cardinales.
/// Incluye Norte, Sur, Este y Oeste.
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    North,
    South,
    East,
    West,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let direction_str = match self {
            Direction::North => "Norte",
            Direction::South => "Sur",
            Direction::East => "Este",
            Direction::West => "Oeste",
        };
        write!(f, "{}", direction_str)
    }
}

/// Enum que representa el estado de un vuelo.
/// Incluye estados como Demorado, A Tiempo, Adelantado, Cancelado y Embarcando.
#[derive(Debug, Clone, PartialEq)]
pub enum Status {
    Delayed,
    OnTime,
    Early,
    Cancelled,
    Boarding,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Status::Delayed => write!(f, "Demorado"),
            Status::OnTime => write!(f, "A Tiempo"),
            Status::Early => write!(f, "Adelantado"),
            Status::Cancelled => write!(f, "Cancelado"),
            Status::Boarding => write!(f, "Embarcando"),
        }
    }
}

#[derive(Deserialize)]
struct AirFlightData {
    flight_number: String,
    origin: String,
    destination: String,
    altitude: String,
    speed: String,
    airline: String,
    position: (f64, f64),
    direction: String,
    fuel_percentage: f64,
    status: String,
    date: String,
}

impl AirFlightData {
    fn to_airflight(&self) -> AirFlights {
        AirFlights {
            flight_number: self.flight_number.clone(),
            origin: AirportCodes::from_str(&self.origin)
                .expect("Error al convertir el origen a DatosAeropuerto"),
            destination: AirportCodes::from_str(&self.destination)
                .expect("Error al convertir el destino a DatosAeropuerto"),
            altitude: self.altitude.clone(),
            speed: self.speed.clone(),
            airline: self.airline.clone(),
            position: self.position,
            direction: match self.direction.as_str() {
                "Norte" => Direction::North,
                "Sur" => Direction::South,
                "Este" => Direction::East,
                "Oeste" => Direction::West,
                _ => Direction::North,
            },
            fuel_percentage: self.fuel_percentage,
            estado: match self.status.as_str() {
                "Demorado" => Status::Delayed,
                "ATiempo" => Status::OnTime,
                "Adelantado" => Status::Early,
                "Cancelado" => Status::Cancelled,
                "Embarcando" => Status::Boarding,
                _ => Status::Delayed,
            },
            date: self.date.clone(),
        }
    }
}

/// Estructura que representa un vuelo en el aire, incluyendo información
/// sobre la posición, dirección, aerolínea, y estado del vuelo.
#[derive(Clone)]
pub struct AirFlights {
    pub flight_number: String,
    pub origin: AirportCodes,
    pub destination: AirportCodes,
    pub position: (f64, f64),
    pub altitude: String,
    pub speed: String,
    pub airline: String,
    pub direction: Direction,
    pub fuel_percentage: f64,
    pub estado: Status,
    pub date: String,
}

impl AirFlights {
    /// Crea una nueva instancia de AirFlights con los datos proporcionados.
    pub fn new(params: AirFlightParameters) -> AirFlights {
        AirFlights {
            flight_number: params.flight_number,
            origin: params.origin,
            destination: params.destination,
            altitude: params.altitude,
            speed: params.speed,
            airline: params.airline,
            position: params.position,
            direction: params.direction,
            fuel_percentage: params.fuel_percentage,
            estado: params.status,
            date: params.date,
        }
    }

    /// Actualiza la posición del vuelo en función del tiempo transcurrido (delta_time).
    /// Calcula la nueva posición según la velocidad y reduce el combustible.
    pub fn update_position(&mut self, delta_time: f64) {
        let (current_lat, current_lon) = self.position;
        let (dest_lat, dest_lon) = self.destination.get_coordinates();

        let direction_lat = dest_lat - current_lat;
        let direction_lon = dest_lon - current_lon;
        let distance = (direction_lat.powi(2) + direction_lon.powi(2)).sqrt();

        if distance > 0.0 {
            let speed_kmh = self.speed.parse::<f64>().unwrap_or(800.0);
            let move_by = speed_kmh * (delta_time / 3600.0);

            let new_lat = current_lat + (direction_lat / distance) * move_by;
            let new_lon = current_lon + (direction_lon / distance) * move_by;
            self.position = (new_lat, new_lon);

            let consumo_combustible_por_km = 0.02;
            let distancia_recorrida = move_by;
            let consumo_nafta = distancia_recorrida * consumo_combustible_por_km;

            self.reduce_fuel(consumo_nafta);
        }
    }

    /// Reduce el porcentaje de combustible en función del consumo especificado.
    pub fn reduce_fuel(&mut self, consumo_nafta: f64) {
        if self.fuel_percentage > consumo_nafta {
            self.fuel_percentage -= consumo_nafta;
        } else {
            self.fuel_percentage = 0.0;
        }
    }

    /// Genera una consulta SQL de tipo INSERT para insertar los datos del vuelo en la base de datos.
    pub fn generate_insert_query(&self) -> String {
        format!(
            "INSERT INTO keyspace1.aviones_volando (flight_number, origin, destination, lat, lon, altitude, speed, airline, direction, fuel_percentage, status, fecha) \
            USING CONSISTENCY ONE VALUES ({}, '{}', '{}', {}, {}, '{}', {}, '{}', '{}', {}, '{}', '{}');",
            self.flight_number,
            self.origin,
            self.destination,
            self.position.0,
            self.position.1,
            self.altitude,
            self.speed,
            self.airline,
            self.direction,
            self.fuel_percentage,
            self.estado,
            self.date,
        )
    }
}

/// Estructura que representa vuelos en el aeropuerto, incluyendo
/// información sobre la aerolínea, el estado, y los tiempos de salida.
#[derive(Deserialize)]
pub struct AirportFlightsData {
    pub flight_number: String,
    pub origin: AirportCodes,
    pub destination: AirportCodes,
    pub airline: String,
    pub status: String,
    pub departure: String,
    pub date: String,
}

impl AirportFlightsData {
    pub fn to_airportflights(&self) -> AirportFlights {
        AirportFlights {
            flight_number: self.flight_number.clone(),
            origin: AirportCodes::from_str(&self.origin.to_string())
                .expect("Error al convertir el origen a DatosAeropuerto"),
            destination: AirportCodes::from_str(&self.destination.to_string())
                .expect("Error al convertir el destino a DatosAeropuerto"),
            airline: self.airline.clone(),
            status: match self.status.as_str() {
                "Demorado" => Status::Delayed,
                "ATiempo" => Status::OnTime,
                "Adelantado" => Status::Early,
                "Cancelado" => Status::Cancelled,
                "Embarcando" => Status::Boarding,
                _ => Status::Delayed,
            },
            departure: self.departure.clone(),
            date: self.date.clone(),
        }
    }
}
pub struct AirportFlights {
    pub flight_number: String,
    pub origin: AirportCodes,
    pub destination: AirportCodes,
    pub airline: String,
    pub status: Status,
    pub departure: String,
    pub date: String,
}
impl AirportFlights {
    /// Crea una nueva instancia de AirportFlights con los datos proporcionados.
    pub fn new(params: AirportFlightParameters) -> AirportFlights {
        AirportFlights {
            flight_number: params.flight_number,
            origin: params.origin,
            destination: params.destination,
            airline: params.airline,
            status: params.status,
            departure: params.departure,
            date: params.date,
        }
    }

    /// Actualiza el estado del vuelo en el aeropuerto de manera cíclica entre
    /// los estados ATiempo, Adelantado, y Demorado.
    pub fn refresh_flight_status(&mut self, _delta_time: f64) {
        self.status = match self.status {
            Status::OnTime => Status::Early,
            Status::Early => Status::Delayed,
            _ => Status::OnTime,
        };
    }

    /// Genera una consulta SQL de tipo INSERT para insertar los datos del vuelo en la base de datos.
    pub fn generate_insert_query(&self) -> String {
        format!(
            "INSERT INTO keyspace2.aviones_en_aeropuerto (flight_number, origin, destination, airline, departure, state, fecha) \
            USING CONSISTENCY QUORUM VALUES ('{}', '{}', '{}', '{}', '{}', '{}', '{}') ;",
            self.flight_number,
            self.origin,
            self.destination,
            self.airline,
            self.departure,
            self.status,
            self.date,
        )
    }

    /// Imprime un mensaje que indica la actualización del estado del vuelo .
    pub fn update_flight_status(&mut self) {
        println!("Actualizando estado del vuelo {}", self.flight_number);
    }
}

pub fn load_flights_from_json(json_content: &str) -> Vec<AirFlights> {
    let aviones_data: Vec<AirFlightData> =
        serde_json::from_str(json_content).expect("Error al parsear JSON");
    aviones_data
        .into_iter()
        .map(|data| data.to_airflight())
        .collect()
}

/// Ejecuta la conexión del avión al servidor TCP en la dirección especificada.
/// Intenta conectar al servidor en `localhost:8081` y muestra un mensaje en la consola
/// al establecer una conexión exitosa.

/// Ejecuta la conexión del avión al servidor TCP en la dirección especificada.
pub fn avion_run() -> std::io::Result<()> {
    let root_cert_store = load_root_certificates()?;
    let config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    let config = Arc::new(config);
    let server_name = ServerName::try_from("localhost")
        .map_err(|_| Error::new(ErrorKind::InvalidInput, "Nombre del servidor no válido"))?;

    // Carga el JSON directamente como una cadena en tiempo de compilación
    let json_content = include_str!("aviones_initialize.json");
    let aviones: Arc<Mutex<Vec<AirFlights>>> =
        Arc::new(Mutex::new(load_flights_from_json(json_content)));

    let (user, password) = aeropuerto::ask_for_user_password()?;
    let stream = aeropuerto::find_connection()?;
    let (_, mut tls_stream) = match aeropuerto::create_connection_stream(
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
            if !aeropuerto::try_connection(tls_guard.get_mut()) {
                println!("No se pudo conectar, buscando nueva conexión.");
                let stream = aeropuerto::find_connection()?;
                tls_stream = match aeropuerto::create_connection_stream(
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
        let tls_stream = Arc::clone(&tls_stream);

        let _ = pool.execute(move || {
            let mut aviones_lock = match aviones.lock() {
                Ok(lock) => lock,
                Err(e) => {
                    eprintln!("Error al adquirir el lock del vector de aviones: {:?}", e);
                    return;
                }
            };

            // Fragmentar y procesar en lotes
            let aviones_chunks: Vec<Vec<_>> = aviones_lock
                .chunks_mut(10)
                .map(|chunk| chunk.iter_mut().collect())
                .collect();

            for set in aviones_chunks {
                let mut stream = match tls_stream.lock() {
                    Ok(lock) => lock,
                    Err(e) => {
                        eprintln!("Error al adquirir el lock del stream TLS: {:?}", e);
                        return;
                    }
                };

                // Procesar cada avión en el lote
                for avion in set {
                    avion.update_position(30.0);
                    let query = avion.generate_insert_query();
                    println!("Enviando consulta: {}", query);

                    if let Err(e) = handle_query(&mut stream, query) {
                        eprintln!("Error al enviar la consulta: {}", e);
                    }
                }
            }
        });

        thread::sleep(Duration::from_secs(10)); // Pausa entre lotes
    }
}
