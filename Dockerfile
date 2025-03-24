FROM eclipse-temurin:21-jdk-jammy

WORKDIR /app

COPY .mvn/ .mvn
COPY mvnw pom.xml ./
COPY src ./src
COPY db ./db

RUN ./mvnw package -DskipTests

FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY --from=0 /app/target/authN-service-*.jar ./authN-service.jar

EXPOSE 8501

ENTRYPOINT ["java", "-jar", "authN-service.jar"]