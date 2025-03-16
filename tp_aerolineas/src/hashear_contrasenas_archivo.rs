use bcrypt::{hash, DEFAULT_COST};
use std::fs;
use std::fs::File;
use std::io::Result;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

fn hashear_contrasena(contrasena: &str) -> Result<String, bcrypt::BcryptError> {
    hash(contrasena, DEFAULT_COST)
}

// HASHEA LAS CONTRASEÑAS
pub fn hashear_contrasenas_archivo() -> Result<()> {
    // Abrimos el archivo original para lectura
    let archivo = File::open("src/usuarios_database/usuarios.csv")?;
    let reader = BufReader::new(archivo);

    // Creamos un archivo temporal para escribir el contenido actualizado
    let ruta_archivo_temporal = Path::new("src/usuarios_database/usuarios_temp.csv");
    let archivo_temp = File::create(ruta_archivo_temporal)?;
    let mut writer = BufWriter::new(archivo_temp);

    for linea in reader.lines() {
        let linea = linea?;
        let mut partes = linea.split(';');

        // Si podemos obtener el usuario y la contraseña
        if let Some(usuario) = partes.next() {
            if let Some(contrasena) = partes.next() {
                // Hasheamos la contraseña
                let contrasena_hasheada = hashear_contrasena(contrasena);

                // Escribimos el usuario y la contraseña hasheada en el archivo temporal
                writeln!(writer, "{};{}", usuario, contrasena_hasheada)?;
            }
        }
    }

    // Renombramos el archivo temporal para reemplazar el original
    fs::rename(ruta_archivo_temporal, "src/usuarios.csv")?;

    Ok(())
}
