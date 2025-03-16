#!/bin/sh
set -e

echo "Iniciando nodo en el puerto $NODE_ARG con NODOS=$NODOS y ADAPT=$ADAPT"

# Construir el comando base con NODE_ARG y NODOS
CMD="/app/target/release/tp_aerolineas $NODE_ARG $NODOS"

# Si ADAPT es 1, agregarlo al comando
if [ "$ADAPT" -eq 1 ]; then
    CMD="$CMD adapt"
fi

# Ejecutar el comando final
exec sh -c "$CMD"
