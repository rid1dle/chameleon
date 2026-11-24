FROM maven:3-eclipse-temurin-25 AS build
WORKDIR /b
COPY pom.xml .
RUN mvn -q dependency:copy-dependencies -DoutputDirectory=/b/lib
COPY src ./src
RUN javac -cp "lib/*" -d out src/main/java/Main.java

# Suwayomi releases bundle Zulu JDK 25 (.github/workflows/publish.yml:98-102)
FROM azul/zulu-openjdk:25-jre
COPY --from=build /b/lib /app/lib
COPY --from=build /b/out /app/out
ENTRYPOINT ["java", "-cp", "/app/out:/app/lib/*", "Main"]
