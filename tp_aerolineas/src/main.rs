pub mod aeropuerto;
pub mod auth_challenge;
pub mod avion;
pub mod cliente;
pub mod error_codes;
pub mod message;
pub mod servidor;
pub mod ui_grafica;
//CQL imports
use std::env;
pub mod ejecutor;
pub mod error;
pub mod message_functions;
pub mod nodo_cassandra;
pub mod nodo_cassandra_functions;
pub mod parser;
pub mod parser_functions;
pub mod postfija;
pub mod servidor_functions;
pub mod threadpool_functions;

use crate::nodo_cassandra::{change_token_range, Nodo};
use crate::ui_grafica::grafica_run;
use aeropuerto::airport_run;
use avion::avion_run;
use cliente::run_cliente;
use servidor::{adapt_cluster, server_run};
use std::sync::{Arc, Mutex};

fn main() {
    env::set_var("RUST_LOG", "debug");
    env::set_var("RUST_LOG", "info");
    env::set_var("RUST_LOG", "warn");
    //env_logger::init();
    let args: Vec<String> = env::args().collect();

    match env::current_dir() {
        Ok(path) => println!("Directorio actual: {}", path.display()),
        Err(e) => eprintln!("Error al obtener el directorio actual: {}", e),
    }

    if args.len() == 4 {
        let port = &args[1];
        let cantidad_nodos: u8 = args[2]
            .parse()
            .expect("Cantidad de nodos debe ser un número entero");
        if !(4..=8).contains(&cantidad_nodos) {
            eprintln!("Error: la cantidad de nodos debe ser mayor a 0");
            return;
        }
        let address = format!("nodo{}:{}", port, port);
        println!("Iniciando nodo en: {}", address);

        let adapt_cluster_arg = &args[3];

        if adapt_cluster_arg != "adapt" {
            eprintln!("Error: el cuarto argumento debe ser 'adapt'");
            return;
        }

        let mut nodo_actual = Arc::new(Mutex::new(Nodo::new(&address, port, cantidad_nodos)));

        if let Ok(nodo) = nodo_actual.lock() {
            println!("Iniciando servidor en: {}", nodo.address);
        } else {
            eprintln!(
                "Error: no se pudo obtener el bloqueo del nodo_actual para obtener la dirección."
            );
            return;
        }

        match nodo_actual.lock() {
            Ok(mut nodo) => match nodo.armar_keyspaces(Some(cantidad_nodos)) {
                Ok(_) => println!("Keyspaces creados correctamente"),
                Err(e) => {
                    println!("Error al leer el directorio keyspaces_info: {:?}", e);
                    let current_dir = match std::env::current_dir() {
                        Ok(current_dir) => {
                            println!("Directorio actual: {:?}", current_dir);
                            current_dir
                        }
                        Err(e) => {
                            println!("Error al obtener el directorio actual: {:?}", e);
                            return;
                        }
                    };
                    let paths = std::fs::read_dir(&current_dir).unwrap_or_else(|e| {
                        eprintln!("Error al leer el directorio actual: {:?}", e);
                        std::process::exit(1);
                    });
                    println!("Carpetas en el directorio actual:");
                    for path in paths {
                        let path = path
                            .unwrap_or_else(|e| {
                                eprintln!("Error al obtener la ruta del path: {:?}", e);
                                std::process::exit(1);
                            })
                            .path();
                        if path.is_dir() {
                            println!("{:?}", path);
                        }
                    }
                }
            },
            Err(e) => {
                eprintln!(
                    "Error: no se pudo obtener el bloqueo del nodo_actual para crear keyspaces. {}",
                    e
                );
                return;
            }
        }

        if let Ok(_nodo) = nodo_actual.lock() {
            if let Err(e) = change_token_range(cantidad_nodos) {
                eprintln!("Error al cambiar el rango de tokens en el archivo: {}", e);
                return;
            }
        } else {
            eprintln!("Error: no se pudo obtener el bloqueo del nodo_actual para cambiar el rango de tokens.");
            return;
        }

        if let Err(e) = adapt_cluster(&nodo_actual, cantidad_nodos) {
            eprintln!("Error al adaptar el cluster: {}", e);
            return;
        }

        match server_run(&mut nodo_actual, cantidad_nodos) {
            Ok(_) => println!("Servidor finalizado correctamente"),
            Err(e) => println!("Error en servidor: {}", e),
        }
    } else if args.len() == 3 {
        let port = &args[1];
        let cantidad_nodos: u8 = args[2]
            .parse()
            .expect("Cantidad de nodos debe ser un número entero");
        if !(4..=8).contains(&cantidad_nodos) {
            eprintln!("Error: la cantidad de nodos debe ser mayor a 0");
            return;
        }
        let address = format!("nodo{}:{}", port, port);
        println!("Iniciando nodo en: {}", address);

        let mut nodo_actual = Arc::new(Mutex::new(Nodo::new(&address, port, cantidad_nodos)));

        if let Ok(nodo) = nodo_actual.lock() {
            println!("Iniciando servidor en: {}", nodo.address);
        } else {
            eprintln!(
                "Error: no se pudo obtener el bloqueo del nodo_actual para obtener la dirección."
            );
            return;
        }

        match nodo_actual.lock() {
            Ok(mut nodo) => match nodo.armar_keyspaces(Some(cantidad_nodos)) {
                Ok(_) => println!("Keyspaces creados correctamente"),
                Err(e) => {
                    println!("Error al leer el directorio keyspaces_info: {:?}", e);
                    let current_dir = match std::env::current_dir() {
                        Ok(current_dir) => {
                            println!("Directorio actual: {:?}", current_dir);
                            current_dir
                        }
                        Err(e) => {
                            println!("Error al obtener el directorio actual: {:?}", e);
                            return;
                        }
                    };
                    let paths = std::fs::read_dir(&current_dir).unwrap_or_else(|e| {
                        eprintln!("Error al leer el directorio actual: {:?}", e);
                        std::process::exit(1);
                    });
                    println!("Carpetas en el directorio actual:");
                    for path in paths {
                        let path = path
                            .unwrap_or_else(|e| {
                                eprintln!("Error al obtener la ruta del path: {:?}", e);
                                std::process::exit(1);
                            })
                            .path();
                        if path.is_dir() {
                            println!("{:?}", path);
                        }
                    }
                }
            },
            Err(e) => {
                eprintln!(
                    "Error: no se pudo obtener el bloqueo del nodo_actual para crear keyspaces. {}",
                    e
                );
                return;
            }
        }

        match server_run(&mut nodo_actual, cantidad_nodos) {
            Ok(_) => println!("Servidor finalizado correctamente"),
            Err(e) => println!("Error en servidor: {}", e),
        }
    } else {
        let port = if args.len() > 1 { &args[1] } else { "nada" };
        if port == "grafica" {
            grafica_run();
        } else if port == "cliente" {
            match run_cliente() {
                Ok(_) => println!("Cliente finalizado correctamente"),
                Err(e) => println!("Error en cliente: {}", e),
            }
        } else if port == "avion" {
            match avion_run() {
                Ok(_) => println!("Avion finalizado correctamente"),
                Err(e) => println!("Error en avion: {}", e),
            }
        } else if port == "aeropuerto" {
            match airport_run() {
                Ok(_) => println!("Aeropuerto finalizado correctamente"),
                Err(e) => println!("Error en aeropuerto: {}", e),
            }
        }
    }
}
