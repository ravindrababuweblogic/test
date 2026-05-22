#!/bin/bash
set -e
echo "Building simple-java-app..."
mvn clean package
echo "Build complete! JAR: target/simple-java-app-1.0.0.jar"
