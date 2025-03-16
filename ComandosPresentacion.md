# Comandos para la demostración

## Inicializar todos los containers
```bash
export NODOS=6 
export ADAPT=0
docker-compose up nodo808X
```

## Detener un container
```bash
control + c
```



## Levantar todos los nodos en un cluster de 6 
```bash
export NODOS=6
export ADAPT=0
docker-compose up nodo808X
```
Luego para demostrar que el adapt funciona correctamente se debe prender `aeropuerto` o `avión` y actualiza la información reconfigurar dinámicamente. 

```bash
cargo run --tp_aerolineas aeropuerto
```

### Desincorporar un nodo de la red 
Apago el nodo8083
````bash
export NODOS=4
export ADAPT=1
docker-compose up nodo8083
````

Observo que no le llegan más queries a los nodos 8084 y 8085.
También sus tablas están vacías y no tienen más registros 



### Incorporar un nodo a la red 
Levanto el container y nodo 8085, y el cluster es de 6 nodos nuevamente.
````bash
export NODOS=6
export ADAPT=1
docker-compose up nodo8085
````


## Logger
Al realizar el adapt se pueden visualizar los logs dentro de la carpeta de cada nodo

## Docker Logs
1. Ver logs de un contenedor en específico
````bash
    docker logs nombre_contenedor
````



## Tests
Mostrar tests ejecutados


## Demo Read-Repair

1. Levantar los 6 nodos y prender `aeropuerto`
2. Apagar el nodo 8081 y esperar a que se hagan las actualizaciones
3. Apagar `aeropuerto`
4. Prender cliente y enviar la consulta:
    ```bash
   SELECT * FROM keyspace1.aviones_volando USING CONSISTENCY ONE WHERE flight_number = 'EK333';
    ```
6. Prender nodo 8081 y enviar devuelta la query
7. Se actualizo! 

Ejemplo
Antes de actualizar:
``

Después de la consulta:
``







