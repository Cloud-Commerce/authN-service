# Build stage
FROM eclipse-temurin:21-jdk-jammy AS builder

WORKDIR /app

# 1. Copy ALL Maven wrapper files first
COPY .mvn .mvn
COPY mvnw .

# 2. Fix permissions and line endings (works for both Windows/Linux)
RUN apt-get update && \
    apt-get install -y dos2unix && \
    dos2unix mvnw && \
    chmod +x mvnw && \
    ./mvnw --version

# 3. Copy remaining application files
COPY pom.xml .
COPY src src

# Install dependencies and build
RUN ./mvnw package -DskipTests

# Runtime stage
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY db db
COPY --from=builder /app/target/authN-service-*.jar ./authN-service.jar

EXPOSE 8501

ENTRYPOINT ["java", "-jar", "authN-service.jar"]