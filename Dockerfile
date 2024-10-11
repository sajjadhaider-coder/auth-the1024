
# Use an official JDK as a base image
FROM openjdk:17-jdk-alpine

# Set the working directory inside the container
WORKDIR /app

# Copy the packaged jar file to the working directory
COPY target/lottery-app.jar /app/app.jar

# Expose the port the app runs on (adjust if necessary)
EXPOSE 8080

# Command to run the jar file
ENTRYPOINT ["java", "-jar", "app.jar"]
