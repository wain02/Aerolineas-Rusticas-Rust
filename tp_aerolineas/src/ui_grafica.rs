use eframe::{
    egui::{self, CentralPanel, SidePanel},
    run_native, App, NativeOptions,
};
use egui::{ComboBox, TextureHandle};
use image::GenericImageView;
use std::io::Error;
use std::io::ErrorKind;
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::aeropuerto::{Airport, AirportCodes};
use crate::avion::{AirFlights, AirportFlights, Direction, FlightType, Status};
use crate::cliente;
use rustls::{ClientConnection, StreamOwned};

struct Implementation {
    usuario: String,
    password: String,
    authenticated: bool,
    autenticacion_exitosa: bool,
    authenticacion_fallo: bool,
}

// Estructura principal de la aplicación
struct FlightTrackerApp {
    impl_features: Implementation,
    airports: Vec<Airport>,
    selected_airport: Option<usize>,
    selected_flight: Option<usize>,
    available_dates: Vec<String>,
    selected_date: Option<String>,
    selected_flight_type: Option<FlightType>,
    updated_date: Option<String>,
    updated_airport: Option<usize>,
    update_quantity: usize,
    updated_flight: Option<usize>,
    texture: Option<TextureHandle>,
    airplane_norte_texture: Option<TextureHandle>,
    airplane_sur_texture: Option<TextureHandle>,
    airplane_este_texture: Option<TextureHandle>,
    airplane_oeste_texture: Option<TextureHandle>,
    last_update: Instant,
    socket: Option<StreamOwned<ClientConnection, TcpStream>>,
}

impl FlightTrackerApp {
    fn new() -> Self {
        let airports = vec![
            Airport {
                name: AirportCodes::SCL,
                position: AirportCodes::SCL.get_coordinates(),
                ip: String::from("localhost:8080"),
                socket: None,
                upcoming_flights: vec![],
                incoming_flights: vec![],
                outgoing_flights: vec![],
            },
            Airport {
                name: AirportCodes::EZE,
                position: AirportCodes::EZE.get_coordinates(),
                ip: String::from("localhost:8081"),
                socket: None,
                upcoming_flights: vec![],
                incoming_flights: vec![],
                outgoing_flights: vec![],
            },
            Airport {
                name: AirportCodes::GRU,
                position: AirportCodes::GRU.get_coordinates(),
                ip: String::from("localhost:8082"),
                socket: None,
                upcoming_flights: vec![],
                incoming_flights: vec![],
                outgoing_flights: vec![],
            },
            Airport {
                name: AirportCodes::BOG,
                position: AirportCodes::BOG.get_coordinates(),
                ip: String::from("localhost:8083"),
                socket: None,
                upcoming_flights: vec![],
                incoming_flights: vec![],
                outgoing_flights: vec![],
            },
            Airport {
                name: AirportCodes::CCS,
                position: AirportCodes::CCS.get_coordinates(),
                ip: String::from("localhost:8084"),
                socket: None,
                upcoming_flights: vec![],
                incoming_flights: vec![],
                outgoing_flights: vec![],
            },
            Airport {
                name: AirportCodes::LIM,
                position: AirportCodes::LIM.get_coordinates(),
                ip: String::from("localhost:8085"),
                socket: None,
                upcoming_flights: vec![],
                incoming_flights: vec![],
                outgoing_flights: vec![],
            },
        ];

        FlightTrackerApp {
            impl_features: Implementation {
                usuario: String::new(),
                password: String::new(),
                authenticated: false,
                autenticacion_exitosa: false,
                authenticacion_fallo: false,
            },
            airports,
            selected_airport: None,
            selected_flight: None,
            selected_flight_type: None,
            updated_date: None,
            updated_airport: None,
            update_quantity: 0,
            updated_flight: None,
            available_dates: vec!["27-10-2024".to_string(), "28-10-2024".to_string()],
            selected_date: None,
            texture: None,
            airplane_sur_texture: None,
            airplane_norte_texture: None,
            airplane_este_texture: None,
            airplane_oeste_texture: None,
            last_update: Instant::now(),
            socket: None,
        }
    }

    fn load_image_from_file(
        &self,
        ctx: &egui::Context,
        path: &str,
    ) -> Result<egui::TextureHandle, String> {
        let img_path = Path::new(path);

        let img = image::open(img_path).map_err(|e| format!("Error al cargar la imagen: {}", e))?;

        let image_rgba = img.to_rgba8();
        let (width, height) = img.dimensions();
        let pixels: Vec<u8> = image_rgba.into_raw();

        Ok(ctx.load_texture(
            path,
            egui::ColorImage::from_rgba_unmultiplied([width as usize, height as usize], &pixels),
            egui::TextureOptions::default(),
        ))
    }

    fn geo_to_screen(&self, position: (f64, f64), map_size: (f32, f32)) -> (f32, f32) {
        let (lat, lon) = position;

        let map_width = map_size.0 as f64;
        let map_height = map_size.1 as f64;

        let x = ((lon + 180.0) / 360.0) * map_width;
        let y = ((90.0 - lat) / 180.0) * map_height;

        (x as f32, y as f32)
    }

    fn login(&mut self, ui: &mut egui::Ui) -> std::io::Result<()> {
        ui.vertical_centered(|ui| {
            ui.label("Login");
            ui.horizontal(|ui| {
                ui.label("Usuario:");
                ui.text_edit_singleline(&mut self.impl_features.usuario);
            });

            ui.horizontal(|ui| {
                ui.label("Contraseña:");
                ui.text_edit_singleline(&mut self.impl_features.password);
            });

            ui.add_space(20.0);

            let button_response = ui.add_sized([200.0, 40.0], egui::Button::new("Authenticate"));

            if button_response.clicked() {
                match self.inicializar_nodos() {
                    Ok(()) => {
                        self.impl_features.authenticated = true;
                        self.impl_features.autenticacion_exitosa = true;
                        self.impl_features.authenticacion_fallo = false;
                    }
                    Err(_) => {
                        self.impl_features.authenticacion_fallo = true;
                    }
                }
            }
            if self.impl_features.authenticacion_fallo {
                ui.colored_label(
                    egui::Color32::RED,
                    "Credenciales inválidas, intentelo de nuevo.",
                );
            }
        });

        Ok(())
    }

    fn mostrar_popup_exito(&mut self, ctx: &egui::Context) {
        if self.impl_features.autenticacion_exitosa {
            egui::Window::new("Autenticación exitosa")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(
                        egui::RichText::new("Autenticación correcta.").color(egui::Color32::GREEN),
                    );

                    if ui.button("Cerrar").clicked() {
                        self.impl_features.autenticacion_exitosa = false;
                    }
                });
        }
    }

    fn inicializar_nodos(&mut self) -> Result<(), Error> {
        println!("Cantidad de aeropuertos: {:?}", self.airports.len());

        let mut errores = vec![];
        for (_i, airport) in &mut self.airports.iter_mut().enumerate() {
            let ip = airport.ip.clone();
            let name = airport.name.clone();
            let usuario = self.impl_features.usuario.clone();
            let password = self.impl_features.password.clone();

            println!("Iniciando nodo {} para {}", ip, name);
            match cliente::ui_cliente(&ip, &usuario, &password) {
                Ok(socket) => {
                    println!("Nodo {} inicializado correctamente", name);
                    airport.socket = Some(socket);
                }
                Err(e) => {
                    println!("Error al inicializar nodo {}: {}", name, e);
                    errores.push(format!("Error en nodo {}: {:?}", name, e));
                }
            }
        }

        // Si hubo errores, retornarlos
        if errores.len() == self.airports.len() {
            return Err(Error::new(ErrorKind::Other, errores.join(", ")));
        }
        Ok(())
    }
    //vuelos estacionados en el aeropuerto
    fn consultar_vuelos_proximos(&mut self) -> Result<(), Error> {
        if let Some(selected_airport) = self.selected_airport {
            let airport = &mut self.airports[selected_airport];
            if let Some(ref mut socket) = airport.socket {
                if !issocket_active(socket) {
                    println!("Socket desconectado, cambiando conexión");
                    let usuario = self.impl_features.usuario.clone();
                    let password = self.impl_features.password.clone();

                    // Intentar reconectar al socket del aeropuerto seleccionado
                    match cliente::ui_cliente("localhost:8080", &usuario, &password) {
                        Ok(new_socket) => {
                            airport.socket = Some(new_socket);
                        }
                        Err(_) => {
                            match cliente::ui_cliente("localhost:8081", &usuario, &password) {
                                Ok(new_socket) => {
                                    airport.socket = Some(new_socket);
                                }
                                Err(_) => {
                                    match cliente::ui_cliente("localhost:8082", &usuario, &password)
                                    {
                                        Ok(new_socket) => {
                                            airport.socket = Some(new_socket);
                                        }
                                        Err(_) => {
                                            match cliente::ui_cliente(
                                                "localhost:8083",
                                                &usuario,
                                                &password,
                                            ) {
                                                Ok(new_socket) => {
                                                    airport.socket = Some(new_socket);
                                                }
                                                Err(_) => {
                                                    println!(
                                                        "Error al reconectar con el aeropuerto seleccionado: {}",
                                                        airport.name
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Some(ref mut socket) = airport.socket {
                let mut flight_data = vec![];
                let query_estacionados = if let Some(selected_date) = self.selected_date.clone() {
                    format!(
                        "SELECT * FROM keyspace2.aviones_en_aeropuerto USING CONSISTENCY QUORUM WHERE origin = '{}' AND fecha = '{}';",
                        airport.name, selected_date
                    )
                } else {
                    eprintln!("Error: selected_date no está presente.");
                    return Err(Error::new(
                        ErrorKind::Other,
                        "selected_date no está presente",
                    ));
                };
                println!("Query enviada: {}", query_estacionados);
                match cliente::handle_query_ui(socket, query_estacionados.to_string()) {
                    Ok(response) => {
                        for fila in response.iter() {
                            if fila.len() < 7 {
                                return Err(Error::new(ErrorKind::Other, "La fila no tiene suficientes columnas para llenar AirportFlights."));
                            }
                            let vuelo_estacionado = AirportFlights {
                                flight_number: fila[0].clone(),
                                origin: match fila[1].as_str() {
                                    "EZE" => AirportCodes::EZE,
                                    "SCL" => AirportCodes::SCL,
                                    "GRU" => AirportCodes::GRU,
                                    "BOG" => AirportCodes::BOG,
                                    "LIM" => AirportCodes::LIM,
                                    "CCS" => AirportCodes::CCS,
                                    _ => AirportCodes::EZE,
                                },
                                destination: match fila[2].as_str() {
                                    "EZE" => AirportCodes::EZE,
                                    "SCL" => AirportCodes::SCL,
                                    "GRU" => AirportCodes::GRU,
                                    "BOG" => AirportCodes::BOG,
                                    "LIM" => AirportCodes::LIM,
                                    "CCS" => AirportCodes::CCS,
                                    _ => AirportCodes::EZE,
                                },
                                airline: fila[3].clone(),
                                departure: fila[4].clone(),
                                status: match fila[5].as_str() {
                                    "Adelantado" => Status::Early,
                                    "Demorado" => Status::Delayed,
                                    "Cancelado" => Status::Cancelled,
                                    _ => Status::OnTime,
                                },
                                date: fila[6].clone(),
                            };
                            flight_data.push(vuelo_estacionado);
                        }
                    }
                    Err(e) => {
                        println!("Error al consultar aeropuerto {}: {}", airport.name, e);
                    }
                }
                airport.upcoming_flights = flight_data;
            }
        }
        Ok(())
    }

    fn consultar_vuelos_salientes(&mut self) -> Result<(), Error> {
        if let Some(selected_airport) = self.selected_airport {
            let airport = &mut self.airports[selected_airport];
            if let Some(ref mut socket) = airport.socket {
                if !issocket_active(socket) {
                    println!("Socket desconectado, cambiando conexión");
                    let usuario = self.impl_features.usuario.clone();
                    let password = self.impl_features.password.clone();

                    // Intentar reconectar al socket del aeropuerto seleccionado
                    match cliente::ui_cliente("localhost:8080", &usuario, &password) {
                        Ok(new_socket) => {
                            airport.socket = Some(new_socket);
                        }
                        Err(_) => {
                            match cliente::ui_cliente("localhost:8081", &usuario, &password) {
                                Ok(new_socket) => {
                                    airport.socket = Some(new_socket);
                                }
                                Err(_) => {
                                    match cliente::ui_cliente("localhost:8082", &usuario, &password)
                                    {
                                        Ok(new_socket) => {
                                            airport.socket = Some(new_socket);
                                        }
                                        Err(_) => {
                                            match cliente::ui_cliente(
                                                "localhost:8083",
                                                &usuario,
                                                &password,
                                            ) {
                                                Ok(new_socket) => {
                                                    airport.socket = Some(new_socket);
                                                }
                                                Err(_) => {
                                                    println!(
                                                        "Error al reconectar con el aeropuerto seleccionado: {}",
                                                        airport.name
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Some(ref mut socket) = airport.socket {
                let mut flight_data = vec![];
                let query_salientes = if let Some(selected_date) = self.selected_date.clone() {
                    format!(
                        "SELECT * FROM keyspace1.aviones_volando USING CONSISTENCY ONE WHERE origin = '{}' AND fecha = '{}'",
                        airport.name, selected_date
                    )
                } else {
                    eprintln!("Error: selected_date no está presente.");
                    return Err(Error::new(
                        ErrorKind::Other,
                        "selected_date no está presente",
                    ));
                };
                println!("Query enviada: {}", query_salientes);
                match cliente::handle_query_ui(socket, query_salientes.to_string()) {
                    Ok(response) => {
                        for fila in response.iter() {
                            if fila.len() < 12 {
                                return Err(Error::new(
                                    ErrorKind::Other,
                                    "La fila no tiene suficientes columnas para llenar AirFlights.",
                                ));
                            }
                            let vuelo_saliente = AirFlights {
                                flight_number: fila[0].clone(),
                                origin: match fila[1].as_str() {
                                    "EZE" => AirportCodes::EZE,
                                    "SCL" => AirportCodes::SCL,
                                    "GRU" => AirportCodes::GRU,
                                    "BOG" => AirportCodes::BOG,
                                    "LIM" => AirportCodes::LIM,
                                    "CCS" => AirportCodes::CCS,
                                    _ => AirportCodes::EZE,
                                },
                                destination: match fila[2].as_str() {
                                    "EZE" => AirportCodes::EZE,
                                    "SCL" => AirportCodes::SCL,
                                    "GRU" => AirportCodes::GRU,
                                    "BOG" => AirportCodes::BOG,
                                    "LIM" => AirportCodes::LIM,
                                    "CCS" => AirportCodes::CCS,
                                    _ => AirportCodes::EZE,
                                },
                                position: (
                                    match fila[3].parse::<f64>() {
                                        Ok(val) => val,
                                        Err(_) => {
                                            return Err(Error::new(
                                                ErrorKind::Other,
                                                "Error al analizar posición en fila[3]",
                                            ));
                                        }
                                    },
                                    match fila[4].parse::<f64>() {
                                        Ok(val) => val,
                                        Err(_) => {
                                            return Err(Error::new(
                                                ErrorKind::Other,
                                                "Error al analizar posición en fila[4]",
                                            ));
                                        }
                                    },
                                ),
                                altitude: fila[5].clone(),
                                speed: fila[6].clone(),
                                airline: fila[7].clone(),
                                direction: match fila[8].as_str() {
                                    "Norte" => Direction::North,
                                    "Sur" => Direction::South,
                                    "Este" => Direction::East,
                                    "Oeste" => Direction::West,
                                    _ => Direction::North,
                                },
                                fuel_percentage: match fila[9].parse::<f64>() {
                                    Ok(val) => val,
                                    Err(_) => {
                                        return Err(Error::new(
                                            ErrorKind::Other,
                                            "Error al analizar porcentaje de combustible en fila[9]",
                                        ));
                                    }
                                },
                                estado: match fila[10].as_str() {
                                    "Adelantado" => Status::Early,
                                    "Demorado" => Status::Delayed,
                                    "ATiempo" => Status::OnTime,
                                    _ => Status::Cancelled,
                                },
                                date: fila[11].clone(),
                            };
                            flight_data.push(vuelo_saliente);
                        }
                    }
                    Err(e) => {
                        println!("Error al consultar aeropuerto {}: {}", airport.name, e);
                    }
                }
                airport.outgoing_flights = flight_data;
            }
        }
        Ok(())
    }

    fn cambiar_conexion(&mut self) {
        if let Some(selected_airport) = self.selected_airport {
            let airport = &mut self.airports[selected_airport];
            let usuario = self.impl_features.usuario.clone();
            let password = self.impl_features.password.clone();

            // Intentar reconectar al socket del aeropuerto seleccionado
            match cliente::ui_cliente(&airport.ip, &usuario, &password) {
                Ok(socket) => {
                    airport.socket = Some(socket);
                    match &airport.socket {
                        Some(socket) => {
                            let _ = &socket;
                            return;
                        }
                        None => {
                            println!("No hay socket para clonar");
                            return;
                        }
                    }
                }
                Err(_) => {
                    println!(
                        "Error al reconectar con el aeropuerto seleccionado: {}",
                        airport.name
                    );
                }
            };

            // Buscar entre las conexiones de los aeropuertos y elegir una que esté activa
            for airport in &mut self.airports {
                if let Some(ref mut socket) = airport.socket {
                    if issocket_active(socket) {
                        //REVISAR QUE SI ESTA BIEN QUE SE VUELVA A REALIZAR LA CONEXIÓN Y TENGAS COMO DOS CONEXIONES CON UN MISMO NODO!
                        let tls_conn = match cliente::ui_cliente(
                            &airport.ip,
                            &self.impl_features.usuario,
                            &self.impl_features.password,
                        ) {
                            Ok(socket) => socket,
                            Err(e) => {
                                eprintln!(
                                    "Error al reconectar con el aeropuerto {}: {}",
                                    airport.name, e
                                );
                                return;
                            }
                        };
                        self.socket = Some(tls_conn);
                    }
                }
            }

            if let Err(e) = self.inicializar_nodos() {
                println!("Error al inicializar nodos: {}", e);
            } else {
                self.cambiar_conexion();
            }
        }
    }
    //volando, que entrara del aeropuerto seleccionado
    fn consultar_vuelos_entrantes(&mut self) -> Result<(), Error> {
        if let Some(selected_airport) = self.selected_airport {
            let airport = &mut self.airports[selected_airport];
            if let Some(ref mut socket) = airport.socket {
                if !issocket_active(socket) {
                    println!("Socket desconectado, cambiando conexión");
                    let usuario = self.impl_features.usuario.clone();
                    let password = self.impl_features.password.clone();

                    // Intentar reconectar al socket del aeropuerto seleccionado
                    match cliente::ui_cliente("localhost:8080", &usuario, &password) {
                        Ok(new_socket) => {
                            airport.socket = Some(new_socket);
                        }
                        Err(_) => {
                            match cliente::ui_cliente("localhost:8081", &usuario, &password) {
                                Ok(new_socket) => {
                                    airport.socket = Some(new_socket);
                                }
                                Err(_) => {
                                    match cliente::ui_cliente("localhost:8082", &usuario, &password)
                                    {
                                        Ok(new_socket) => {
                                            airport.socket = Some(new_socket);
                                        }
                                        Err(_) => {
                                            match cliente::ui_cliente(
                                                "localhost:8083",
                                                &usuario,
                                                &password,
                                            ) {
                                                Ok(new_socket) => {
                                                    airport.socket = Some(new_socket);
                                                }
                                                Err(_) => {
                                                    println!(
                                                        "Error al reconectar con el aeropuerto seleccionado: {}",
                                                        airport.name
                                                    );
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Some(ref mut socket) = airport.socket {
                let mut flight_data = vec![];
                let query_entrantes = if let Some(selected_date) = self.selected_date.clone() {
                    format!(
                        "SELECT * FROM keyspace1.aviones_volando USING CONSISTENCY ONE WHERE destination = '{}' AND fecha = '{}'",
                        airport.name.get_airport_code(), selected_date
                    )
                } else {
                    eprintln!("Error: selected_date no está presente.");
                    return Err(Error::new(
                        ErrorKind::Other,
                        "selected_date no está presente",
                    ));
                };
                println!("Query enviada: {}", query_entrantes);
                match cliente::handle_query_ui(socket, query_entrantes.to_string()) {
                    Ok(response) => {
                        for fila in response.iter() {
                            if fila.len() < 12 {
                                return Err(Error::new(
                                    ErrorKind::Other,
                                    "La fila no tiene suficientes columnas para llenar AirFlights.",
                                ));
                            }
                            let vuelo_entrante = AirFlights {
                                flight_number: fila[0].clone(),
                                origin: match fila[1].as_str() {
                                    "EZE" => AirportCodes::EZE,
                                    "SCL" => AirportCodes::SCL,
                                    "GRU" => AirportCodes::GRU,
                                    "BOG" => AirportCodes::BOG,
                                    "LIM" => AirportCodes::LIM,
                                    "CCS" => AirportCodes::CCS,
                                    _ => AirportCodes::EZE,
                                },
                                destination: match fila[2].as_str() {
                                    "EZE" => AirportCodes::EZE,
                                    "SCL" => AirportCodes::SCL,
                                    "GRU" => AirportCodes::GRU,
                                    "BOG" => AirportCodes::BOG,
                                    "LIM" => AirportCodes::LIM,
                                    "CCS" => AirportCodes::CCS,
                                    _ => AirportCodes::EZE,
                                },
                                position: (
                                    match fila[3].parse::<f64>() {
                                        Ok(val) => val,
                                        Err(_) => {
                                            return Err(Error::new(
                                                ErrorKind::Other,
                                                "Error al analizar posición en fila[3]",
                                            ));
                                        }
                                    },
                                    match fila[4].parse::<f64>() {
                                        Ok(val) => val,
                                        Err(_) => {
                                            return Err(Error::new(
                                                ErrorKind::Other,
                                                "Error al analizar posición en fila[4]",
                                            ));
                                        }
                                    },
                                ),
                                altitude: fila[5].clone(),
                                speed: fila[6].clone(),
                                airline: fila[7].clone(),
                                direction: match fila[8].as_str() {
                                    "Norte" => Direction::North,
                                    "Sur" => Direction::South,
                                    "Este" => Direction::East,
                                    "Oeste" => Direction::West,
                                    _ => Direction::North,
                                },
                                fuel_percentage: match fila[9].parse::<f64>() {
                                    Ok(val) => val,
                                    Err(_) => {
                                        return Err(Error::new(
                                            ErrorKind::Other,
                                            "Error al analizar porcentaje de combustible en fila[9]",
                                        ));
                                    }
                                },
                                estado: match fila[10].as_str() {
                                    "Adelantado" => Status::Early,
                                    "Demorado" => Status::Delayed,
                                    "ATiempo" => Status::OnTime,
                                    _ => Status::Cancelled,
                                },
                                date: fila[11].clone(),
                            };

                            flight_data.push(vuelo_entrante);
                        }
                    }
                    Err(e) => {
                        println!(":11::::::::::::::::::::::::::::::::::");
                        println!("Error al consultar aeropuerto {}: {}", airport.name, e);
                    }
                }
                airport.incoming_flights = flight_data;
            }
        }
        Ok(())
    }
    fn imprimir_valores_vuelo_volando(&mut self, ui: &mut egui::Ui, es_saliente: bool) {
        if let Some(selected_airport) = self.selected_airport {
            if let Some(selected_flight) = self.selected_flight {
                let flight = if es_saliente {
                    if selected_flight < self.airports[selected_airport].outgoing_flights.len() {
                        &self.airports[selected_airport].outgoing_flights[selected_flight]
                    } else {
                        self.selected_flight = None;
                        return;
                    }
                } else if selected_flight < self.airports[selected_airport].incoming_flights.len() {
                    &self.airports[selected_airport].incoming_flights[selected_flight]
                } else {
                    ui.label("Vuelo entrante seleccionado no válido");
                    return;
                };
                ui.heading(format!("Vuelo: {}", flight.flight_number));
                ui.heading(format!("Aerolínea: {}", flight.airline));
                ui.label(format!("Fecha: {}", flight.date));
                ui.label(format!("Origen: {}", flight.origin));
                ui.label(format!("Destino: {}", flight.destination));
                ui.label(format!(
                    "Ubicación actual: {}{}",
                    flight.position.0, flight.position.1
                ));
                ui.label(format!("Altitud: {} m", flight.altitude));
                ui.label(format!("Velocidad: {} km/h", flight.speed));
                ui.label(format!("Dirección: {}", flight.direction));
                ui.label(format!(
                    "Combustible restante: {} %",
                    flight.fuel_percentage
                ));
                ui.label(format!("Llegada al destino: {}", flight.estado));
            }
        }
    }
    fn imprimir_valores_vuelo_en_aeropuerto(&mut self, ui: &mut egui::Ui) {
        if let Some(selected_airport) = self.selected_airport {
            if let Some(selected_flight) = self.selected_flight {
                let flight =
                    if selected_flight < self.airports[selected_airport].upcoming_flights.len() {
                        &self.airports[selected_airport].upcoming_flights[selected_flight]
                    } else {
                        self.selected_flight = None;
                        return;
                    };
                ui.heading(format!("Vuelo: {}", flight.flight_number));
                ui.heading(format!("Aerolínea: {}", flight.airline));
                ui.label(format!("Fecha: {}", flight.date));
                ui.label(format!("Origen: {}", flight.origin));
                ui.label(format!("Destino: {}", flight.destination));
                ui.label(format!("Departure / Horario de Salida: {}", flight.date));
                ui.label(format!("Estado del vuelo: {}", flight.status));
            }
        }
    }

    fn load_texture(&mut self, ctx: &egui::Context) {
        // Si la textura ya está cargada, no hace nada
        if self.texture.is_none() {
            self.texture = self.load_image_from_file(ctx, "src/ui/mapa_latam.png").ok();
        }

        // Cargar texturas de los aviones solo si aún no están cargadas
        if self.airplane_norte_texture.is_none() {
            self.airplane_norte_texture = self
                .load_image_from_file(ctx, "src/ui/Icono_Avion_Norte.png")
                .ok();
        }
        if self.airplane_sur_texture.is_none() {
            self.airplane_sur_texture = self
                .load_image_from_file(ctx, "src/ui/Icono_Avion_Sur.png")
                .ok();
        }
        if self.airplane_este_texture.is_none() {
            self.airplane_este_texture = self
                .load_image_from_file(ctx, "src/ui/Icono_Avion_Este.png")
                .ok();
        }
        if self.airplane_oeste_texture.is_none() {
            self.airplane_oeste_texture = self
                .load_image_from_file(ctx, "src/ui/Icono_Avion_Oeste.png")
                .ok();
        }
    }
}

fn issocket_active(socket: &mut StreamOwned<ClientConnection, TcpStream>) -> bool {
    if let Err(e) = socket.sock.set_nonblocking(true) {
        eprintln!("Error al configurar socket como no bloqueante: {:?}", e);
        return false;
    }

    let mut buffer = [0; 1];
    let active = match socket.sock.peek(&mut buffer) {
        Ok(0) => false,
        Ok(_) => true,
        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => true,
        Err(e) => {
            eprintln!("Error al verificar el socket: {:?}", e);
            false
        }
    };

    if let Err(e) = socket.sock.set_nonblocking(false) {
        eprintln!("Error al restaurar el modo bloqueante del socket: {:?}", e);
    }

    active
}

impl App for FlightTrackerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.load_texture(ctx);

        if let Some(ref mut socket) = self.socket {
            println!("Entra a verificar la conexión");
            if !issocket_active(socket) {
                println!("Socket desconectado, cambiando conexión");
                self.cambiar_conexion();
            }
        }

        if !self.impl_features.authenticated {
            egui::CentralPanel::default().show(ctx, |_ui| {
                egui::Window::new("Iniciar sesión")
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                    .show(ctx, |ui| {
                        self.login(ui).unwrap_or_else(|e| {
                            ui.label(format!("Error al iniciar sesión: {:?}", e));
                        });
                    });
            });
        }

        self.mostrar_popup_exito(ctx);

        let now: Instant = Instant::now();
        self.last_update = now;
        self.update_quantity += 1;

        SidePanel::left("side_panel").show(ctx, |ui| {
            ui.heading("Aeropuertos disponibles");

            //Dropdown para seleccionar la fecha
            ui.label("Seleccionar fecha:");
            ComboBox::from_label(" ")
                .selected_text(
                    self.selected_date
                        .clone()
                        .unwrap_or_else(|| "Seleccionar".to_string()),
                )
                .show_ui(ui, |ui| {
                    for date in &self.available_dates {
                        ui.selectable_value(&mut self.selected_date, Some(date.clone()), date);
                    }
                });

            ui.separator();

            for (i, airport) in self.airports.iter().enumerate() {
                if ui.button(airport.name.get_airport_code()).clicked() {
                    self.selected_airport = Some(i);

                    self.selected_flight = None;
                }
            }
            if self.selected_date.is_some()
                && self.selected_airport.is_some()
                && (self.updated_date != self.selected_date
                    || self.updated_airport != self.selected_airport
                    || self.update_quantity > 500)
            {
                match self.consultar_vuelos_proximos() {
                    Ok(_) => (),
                    Err(e) => println!("Error al consultar vuelos próximos: {}", e),
                }
                match self.consultar_vuelos_entrantes() {
                    Ok(_) => (),
                    Err(e) => println!("Error al consultar vuelos entrantes: {}", e),
                }
                match self.consultar_vuelos_salientes() {
                    Ok(_) => (),
                    Err(e) => println!("Error al consultar vuelos salientes: {}", e),
                }
                self.updated_date = self.selected_date.clone();
                self.updated_airport = self.selected_airport;
                self.update_quantity = 0;
            }
            ui.separator();
            if self.selected_date.is_some() {
                if let Some(selected_airport) = self.selected_airport {
                    let airport = &self.airports[selected_airport];
                    ui.heading(format!("Vuelos en {}", airport.name));

                    ui.label("Vuelos próximos".to_string());
                    for (i, flight) in airport.upcoming_flights.iter().enumerate() {
                        if ui.button(&flight.flight_number).clicked() {
                            self.selected_flight = Some(i);
                            self.selected_flight_type = Some(FlightType::UpcomingFlight);
                        }
                    }
                    ui.label("Vuelos salientes".to_string());
                    for (i, flight) in airport.outgoing_flights.iter().enumerate() {
                        if ui.button(&flight.flight_number).clicked() {
                            self.selected_flight = Some(i);
                            self.selected_flight_type = Some(FlightType::OutgoingFlight);
                        }
                    }
                    ui.label("Vuelos entrantes".to_string());
                    for (i, flight) in airport.incoming_flights.iter().enumerate() {
                        if ui.button(&flight.flight_number).clicked() {
                            self.selected_flight = Some(i);
                            self.selected_flight_type = Some(FlightType::IncomingFlight);
                        }
                    }
                }
            }
        });

        CentralPanel::default().show(ctx, |ui| {
            ui.heading("Flight Tracker");

            if let Some(texture) = &self.texture {
                let image_size = egui::Vec2::new(1162.0 * 0.7, 1918.0 * 0.7);
                ui.image(texture.id(), image_size);
            } else {
                ui.label("Cargando imagen del mapa...");
            }

            if let Some(texture) = &self.texture {
                let map_size: egui::Vec2 = texture.size_vec2();

                ui.image(texture.id(), map_size);

                for (i, airport) in self.airports.iter().enumerate() {
                    let (x, y) = self.geo_to_screen(airport.position, map_size.into());

                    let button_rect = egui::Rect::from_min_size(
                        egui::Pos2::new(x, y),
                        egui::vec2(100.0, 30.0), // Tamaño del botón
                    );

                    if ui
                        .put(
                            button_rect,
                            egui::Button::new(airport.name.get_airport_code()),
                        )
                        .clicked()
                    {
                        self.selected_airport = Some(i);
                        self.selected_flight = None;
                    }
                }

                if let Some(selected_airport) = self.selected_airport {
                    let airport = &self.airports[selected_airport];

                    let icon_size = egui::vec2(40.0, 40.0);

                    for (i, flight) in airport.outgoing_flights.iter().enumerate() {
                        let (x, y) = self.geo_to_screen(flight.position, map_size.into());

                        let button_rect = egui::Rect::from_min_size(
                            egui::Pos2::new(x, y),
                            egui::vec2(40.0, 40.0),
                        );

                        let airplane_texture = match flight.direction {
                            Direction::North => &self.airplane_norte_texture,
                            Direction::South => &self.airplane_sur_texture,
                            Direction::East => &self.airplane_este_texture,
                            Direction::West => &self.airplane_oeste_texture,
                        };

                        if let Some(texture) = airplane_texture {
                            if ui
                                .put(button_rect, egui::ImageButton::new(texture.id(), icon_size))
                                .clicked()
                            {
                                self.selected_flight = Some(i);
                            }
                        } else {
                            ui.label("Cargando icono del avión...");
                        }
                    }

                    for (i, flight) in airport.incoming_flights.iter().enumerate() {
                        let (x, y) = self.geo_to_screen(flight.position, map_size.into());

                        let button_rect = egui::Rect::from_min_size(
                            egui::Pos2::new(x, y),
                            egui::vec2(40.0, 40.0),
                        );

                        let airplane_texture = match flight.direction {
                            Direction::North => &self.airplane_norte_texture,
                            Direction::South => &self.airplane_sur_texture,
                            Direction::East => &self.airplane_este_texture,
                            Direction::West => &self.airplane_oeste_texture,
                        };

                        if let Some(texture) = airplane_texture {
                            if ui
                                .put(button_rect, egui::ImageButton::new(texture.id(), icon_size))
                                .clicked()
                            {
                                self.selected_flight = Some(i);
                            }
                        } else {
                            ui.label("Cargando icono del avión...");
                        }
                    }
                }
            } else {
                ui.label("Cargando imagen del mapa...");
            }
        });

        SidePanel::right("right_panel")
            .resizable(true)
            .min_width(250.0)
            .default_width(300.0)
            .show(ctx, |ui| {
                ui.heading("Información de Vuelo");

                if let Some(_selected_airport) = self.selected_airport {
                    if let Some(_selected_flight) = self.selected_flight {
                        {
                            match self.selected_flight_type {
                                Some(FlightType::UpcomingFlight) => {
                                    self.imprimir_valores_vuelo_en_aeropuerto(ui);
                                }
                                Some(FlightType::OutgoingFlight) => {
                                    self.imprimir_valores_vuelo_volando(ui, true);
                                }
                                Some(FlightType::IncomingFlight) => {
                                    self.imprimir_valores_vuelo_volando(ui, false);
                                }
                                None => {
                                    ui.label("No hay vuelos seleccionados");
                                }
                            }
                            self.updated_flight = self.selected_flight;
                        }
                    }
                }
            });
        ctx.request_repaint_after(Duration::from_millis(16));
    }
}

// Esta función inicializa y ejecuta la aplicación "Flight Tracker" con opciones de ventana personalizadas.
pub fn grafica_run() {
    let app = FlightTrackerApp::new();

    let options = NativeOptions {
        initial_window_size: Some(egui::Vec2::new(1328.0, 1786.0)),
        centered: true,
        ..Default::default()
    };

    let _ = run_native("Flight Tracker", options, Box::new(|_| Box::new(app)));
}
