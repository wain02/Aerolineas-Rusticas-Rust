# Taller de Programación: Delfi-y-sus-umpalumpas

## Integrantes
- Borthaburu, Isidro Héctor
- Cano Ros Langrehr, María Delfina
- Di Nucci, Tomás Franco
- Wainwright, Martín

## Descripción

Este proyecto implementa un sistema de manejo de información para una aerolínea. Entre sus módulos se incluyen funcionalidades para manejar aviones, aeropuertos, una interfaz gráfica de usuario, y un sistema de nodos de Cassandra que interactúan con un protocolo de consulta tipo CQL. Los nodos del sistema pueden ejecutarse como servidores en distintos puertos y se comunican para procesar las operaciones.

## Estructura del Proyecto
El proyecto está organizado en varios módulos, entre ellos:

cliente: Implementa el cliente que interactúa con el sistema.
error_codes: Define códigos de error específicos.
message: Maneja la serialización y deserialización de mensajes entre nodos.
servidor: Ejecuta el servidor y maneja las conexiones de los nodos.
auth_challenge: Implementa los desafíos de autenticación.
ui_grafica: Contiene la implementación de la interfaz gráfica.
avion y aeropuerto: Módulos para gestionar entidades relacionadas con aviones y aeropuertos.
CQL:
ejecutor: Ejecuta consultas en los nodos de Cassandra.
error: Maneja errores en el procesamiento de consultas.
nodo_cassandra: Implementa la lógica para los nodos del sistema.
parser y postfija: Encargados de la interpretación de consultas tipo CQL.


## Cómo usar

### Compilación

Para compilar el programa, usa el comando:
```bash
cargo build --bin tp_aerolineas
```

### Ejecucion
Para ejecutar el programa, utiliza el siguiente formato en el directorio raíz del proyecto:
```bash
cargo run --bin tp_aerolineas [opción]
```

Donde [opción] puede ser:

grafica: Ejecuta la interfaz gráfica de usuario.
avion: Ejecuta el módulo de administración de aviones.
aeropuerto: Ejecuta el módulo de administración de aeropuertos.
cliente: Ejecuta el cliente para interactuar con los nodos de Cassandra.

Ejecutar nodos:
```bash
cargo run --bin tp_aerolineas [nodo] [cantidad]
```
[nodo]: Ejecuta un nodo de Cassandra, donde [nodo] es un puerto en el rango 8080 a 8087.
[cantidad]: Define cantidad de nodos de Cassandra.
Por ejemplo, para iniciar un nodo de Cassandra en el puerto 8080, usa:
```bash
cargo run --bin tp_aerolineas 8080 6
```
Cada nodo debe iniciarse en su propia carpeta dentro del directorio tp_aerolineas/nodos/, en una subcarpeta con el formato nodo808X, donde X corresponde al número del puerto.

Ejemplo para el nodo en el puerto 8080:
```bash
mkdir -p tp_aerolineas/nodos/nodo8080
cd tp_aerolineas/nodos/nodo8080
cargo run --bin tp_aerolineas 8080 6
```

### Requisitos

Asegúrate de tener Rust instalado y configurado en tu entorno. Para compilar y ejecutar correctamente, utiliza cargo, el gestor de paquetes de Rust.

## ENCRIPTACION
Comandos a ejecutar:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout server.key -out server.crt -nodes -days 36500 -config openssl.cnf
chequear que este bien:
openssl x509 -in server.crt -text -noout
openssl ec -in server.key -text -noout
```

# openssl.cnf
```bash
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = localhost

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = 127.0.0.1
IP.3 = 127.0.0.1
IP.4 = 127.0.0.1
IP.5 = 127.0.0.1
IP.6 = 127.0.0.1
IP.7 = 127.0.0.1
IP.8 = 127.0.0.1
IP.9 = 127.0.0.1
IP.10 = 127.0.0.1
```


# **Cómo Usar el Proyecto con Docker**

Esta seccion explica cómo compilar, ejecutar y utilizar el programa utilizando Docker y docker-compose. Los nodos se levantan en contenedores separados mediante Docker, mientras que los módulos principales se ejecutan directamente con cargo run.

---

## **Requisitos**

- **Docker**: Asegúrate de tener Docker instalado y configurado correctamente en tu sistema.
- **docker-compose**: Instala la versión correspondiente para trabajar con los archivos de configuración.
- **Rust**: Debes tener Rust instalado para ejecutar los módulos principales con cargo.

---

## **Compilación**

Para compilar las imágenes de Docker necesarias para los nodos, usa el siguiente comando desde el directorio raíz del proyecto:

docker-compose build

Este comando generará las imágenes requeridas para los nodos de Cassandra.

---

## **Ejecución**

### Inicialización y Precaución
Antes de levantar los nodos, siempre ejecutar el siguiente comando para asegurarse de que no haya contenedores o volúmenes previos que puedan generar conflictos:

docker compose down -v

### **Levantar los Nodos**
Los nodos de Cassandra deben levantarse en **terminales separadas** utilizando docker-compose. Cada nodo utiliza su propia subcarpeta en tp_aerolineas/nodos/nodo808X, donde **X** corresponde al número del puerto.

Además, es necesario configurar el número de nodos a levantar y definir si la opción de adaptación (adapt) estará activada. Esto se realiza mediante una serie de dos comandos, dependiendo del sistema operativo utilizado.

Configuraciones según el sistema operativo
#### Para MacOS:

Para definir 4 nodos y activar la adaptación, ejecutar:

export NODOS=4
export ADAPT=1

### Para Unix/Linux (para levantar 6 nodos y desactivar adaptación):
Para definir 6 nodos y desactivar la adaptación, ejecutar:

echo "NODOS=6" > .env
echo "ADAPT=0" >> .env


Ejemplo de comandos para iniciar los nodos despues:

- **Terminal 1**:
  docker-compose up nodo8080

- **Terminal 2**:
  docker-compose up nodo8081

- **Terminal 3**:
  docker-compose up nodo8082

- **Terminal 4**:
  docker-compose up nodo8083

Asi sucesivamente los nodos necesarios

Espera unos segundos para asegurarte de que los nodos estén completamente inicializados antes de proceder.

---

### **Ejecutar los Módulos Principales**

Una vez que los nodos estén activos, puedes ejecutar los módulos principales del programa utilizando cargo run dentro de la carpeta de ./tp_aerolineas/. Los módulos disponibles son:

#### **Avión**
Para ejecutar el módulo de administración de aviones:
cargo run --bin tp_aerolineas avion

#### **Aeropuerto**
Para ejecutar el módulo de administración de aeropuertos:
cargo run --bin tp_aerolineas aeropuerto

#### **Interfaz Gráfica**
Para ejecutar la interfaz gráfica de usuario:
cargo run --bin tp_aerolineas grafica

---

## Como testear

1. **Apagar y limpiar los contenedores activos** (si los hay):  
   Ejecuta el siguiente comando desde el directorio raíz del proyecto:  

   docker-compose down

2. **Compilar las imágenes de Docker**:  
    Desde el directorio raíz del proyecto, ejecuta:

    docker-compose build

3. **Levantar los Nodos de Prueba**:  
    El proyecto requiere levantar varios nodos de prueba, ubicados en tp_aerolineas/tests/nodos/nodo808X, donde X va de 0 a 3.
    Para esto, utiliza el siguiente comando en cuatro terminales diferentes:

    docker-compose up nodo808X

4. **Ejecución de los Tests**:  
    Una vez que los nodos están activos, abre una quinta terminal y 
    ejecuta el siguiente comando desde el directorio raíz del proyecto:

    cd tp_aerolineas
    cargo test


### Ejemplo con ui, se necesita ejecutar como cliente de anet mano antes de 
```bash
CREATE KEYSPACE keyspace1 WITH REPLICATION = {'class': 'SimpleStrategy', 'replication_factor': 3};
CREATE TABLE keyspace1.aviones_volando (    flight_number INT,    origin VARCHAR(100),    destination VARCHAR(100),    lat FLOAT,    lon VARCHAR(100),    altitude VARCHAR(100),    speed INT,     airline VARCHAR(100),    direction VARCHAR(50),    fuel_percentage FLOAT,   status VARCHAR(100),  fecha VARCHAR(100),   PRIMARY KEY ((flight_number, origin, destination), origin, fecha));
```

```bash
CREATE KEYSPACE keyspace2 WITH REPLICATION = {'class': 'SimpleStrategy', 'replication_factor': 3};
CREATE TABLE keyspace2.aviones_en_aeropuerto ( flight_number VARCHAR(100), origin VARCHAR(100), destination VARCHAR(100), airline VARCHAR(100), departure VARCHAR(100), state VARCHAR(100), fecha VARCHAR(100), PRIMARY KEY ((flight_number, origin), origin, fecha));
```
