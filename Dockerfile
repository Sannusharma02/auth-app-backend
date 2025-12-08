#FROM ubuntu:latest
#LABEL authors="sannu"
#
#ENTRYPOINT ["top", "-b"]

FROM eclipse-temurin:25-jdk
WORKDIR /app
COPY target/auth-app-backend-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8083
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
