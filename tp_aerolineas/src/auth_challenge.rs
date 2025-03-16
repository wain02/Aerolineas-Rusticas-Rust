use sasl::client::mechanisms::Plain as ClientPlain;
use sasl::client::{Mechanism as ClientMechanism, MechanismError as ClientMechanismError};
use sasl::common::{Credentials, Identity};
use sasl::secret;
use sasl::server::mechanisms::Plain as ServerPlain;
use sasl::server::{Mechanism as ServerMechanism, Response, Validator};
use sasl::server::{MechanismError as ServerMechanismError, ValidatorError};

#[derive(Debug, PartialEq)]
enum MechanismError {
    Client(ClientMechanismError),
    Server(ServerMechanismError),
}

impl From<ClientMechanismError> for MechanismError {
    fn from(err: ClientMechanismError) -> MechanismError {
        MechanismError::Client(err)
    }
}

impl From<ServerMechanismError> for MechanismError {
    fn from(err: ServerMechanismError) -> MechanismError {
        MechanismError::Server(err)
    }
}

struct UserValidator {
    usuario: String,
    password: String,
}

impl UserValidator {
    // Constructor para inicializar el Validador con usuario y contraseña
    fn new(usuario: String, password: String) -> Self {
        UserValidator { usuario, password }
    }
}

impl Validator<secret::Plain> for UserValidator {
    fn validate(&self, identity: &Identity, value: &secret::Plain) -> Result<(), ValidatorError> {
        let secret::Plain(password) = value;
        if identity != &Identity::Username(self.usuario.clone()) || password != &self.password {
            Err(ValidatorError::AuthenticationFailed)
        } else {
            Ok(())
        }
    }
}

fn finish<CM, SM>(cm: &mut CM, sm: &mut SM) -> Result<Identity, MechanismError>
where
    CM: ClientMechanism,
    SM: ServerMechanism,
{
    let init = cm.initial();
    println!("C: {}", String::from_utf8_lossy(&init));

    let mut resp = sm.respond(&init)?;
    println!("Server response after initial: {:?}", resp);
    loop {
        let msg;
        match resp {
            Response::Proceed(ref data) => {
                println!("S: {}", String::from_utf8_lossy(data));
                msg = cm.response(data)?;
                println!("C: {}", String::from_utf8_lossy(&msg));
            }
            Response::Success(_, _) => {
                println!("S: Success received, breaking out of loop.");
                break;
            }
        }
        resp = sm.respond(&msg)?;
        println!("Server response after loop: {:?}", resp);
    }
    match resp {
        Response::Success(ret, fin) => {
            println!("S: {}", String::from_utf8_lossy(&fin));
            match cm.success(&fin) {
                Ok(()) => {
                    println!("Client processed success message");
                    Ok(ret)
                }
                Err(e) => {
                    println!("Client failed to process success message: {:?}", e);
                    Err(MechanismError::Client(e))
                }
            }
        }
        _ => {
            println!("Unexpected response: {:?}", resp);
            Err(MechanismError::Server(
                ServerMechanismError::AuthenticationFailed,
            ))
        }
    }
}

pub fn revisar_auth_challenge(
    token: Vec<u8>,
    username: String,
    password: String,
) -> std::io::Result<()> {
    let validador = UserValidator::new(username.clone(), password.clone());
    let mut mech: ServerPlain<UserValidator> = ServerPlain::new(validador);
    let expected_response = Response::Success(Identity::Username(username.clone()), Vec::new());

    match mech.respond(token.as_slice()) {
        Ok(response) => {
            if response != expected_response {
                eprintln!("La respuesta no coincide con la esperada");
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "La respuesta no coincide con la esperada",
                ));
            }
        }
        Err(e) => {
            eprintln!("Error al responder: {:?}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Error al responder",
            ));
        }
    }

    // Verificar el flujo de mensajes entre cliente y servidor
    let creds = Credentials::default()
        .with_username(username.clone())
        .with_password(password.clone());
    let mut client_mech = match ClientPlain::from_credentials(creds.clone()) {
        Ok(client) => client,
        Err(e) => {
            eprintln!("Error creando el cliente: {:?}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Error creando el cliente",
            ));
        }
    };
    let mut server_mech = ServerPlain::new(UserValidator::new(username.clone(), password.clone()));
    match finish(&mut client_mech, &mut server_mech) {
        Ok(Identity::Username(ref u)) if *u == username => (),
        Ok(_) => {
            eprintln!("Expected Username identity but got something else");
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Expected Username identity but got something else",
            ));
        }
        Err(e) => {
            eprintln!("Expected Ok but got Err: {:?}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("Expected Ok but got Err: {:?}", e),
            ));
        }
    }
    println!("Autenticación exitosa\n");
    Ok(())
}
