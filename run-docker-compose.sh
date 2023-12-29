#!/bin/sh

# Path to your Docker Compose YAML file
COMPOSE_FILE="compose.yaml"

# Check if the YAML file exists
if [ ! -f "$COMPOSE_FILE" ]; then
  echo "Error: The specified Docker Compose YAML file '$COMPOSE_FILE' does not exist."
  exit 1
fi

# Run Docker Compose
docker-compose -f "$COMPOSE_FILE" up --build
