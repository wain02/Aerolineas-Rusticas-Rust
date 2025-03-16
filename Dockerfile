# Usa la imagen oficial de Rust como base
FROM rust:latest

# Instala tmux y otras dependencias necesarias
RUN apt-get update && apt-get install -y tmux

# Establece el directorio de trabajo inicial dentro del contenedor
WORKDIR /app

# Copia el archivo Cargo.toml y Cargo.lock al contenedor
COPY Cargo.toml Cargo.lock ./

# Copia todo el proyecto al contenedor
COPY tp_aerolineas ./tp_aerolineas
COPY usuarios_database ./usuarios_database

# Copia el entrypoint al contenedor y le da permisos de ejecución
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Crea un archivo fuente temporal para compilar las dependencias
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Descarga las dependencias respetando el archivo Cargo.lock
RUN cargo fetch --locked

# Borra el archivo temporal después de descargar las dependencias
RUN rm -rf src

# Compila el binario en modo release
RUN cargo build --release --bin tp_aerolineas --locked

# Establece el script de entrada por defecto
ENTRYPOINT ["/app/entrypoint.sh"]