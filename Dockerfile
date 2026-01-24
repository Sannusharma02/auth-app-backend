# Build stage
FROM maven:3.9.9-eclipse-temurin-21 AS build

#Set working directory
WORKDIR /app

#Copy pom.xml and download dependencies (cached layer)
COPY pom.xml .
RUN mvn dependency:go-offline

#copy source code
COPY src ./src

# Build the application
RUN mvn clean package -DskipTests

#Run stage
FROM eclipse-temurin:21-jdk

#Set working directory
WORKDIR /app

#Copy jar from buiil stage
COPY --from=build /app/target/*.jar app.jar

#Expose application port
EXPOSE 8080

#Run the spring Boot app
ENTRYPOINT ["java", "-jar", "app.jar"]



##FROM ubuntu:latest
##LABEL authors="sannu"
##
##ENTRYPOINT ["top", "-b"]
#
#FROM eclipse-temurin:25-jdk
#WORKDIR /app
#COPY target/auth-app-backend-0.0.1-SNAPSHOT.jar app.jar
#EXPOSE 8083
#ENTRYPOINT ["java", "-jar", "/app/app.jar"]
