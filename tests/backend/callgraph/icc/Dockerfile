FROM maven:3.8.2-openjdk-8 AS build
RUN git clone https://github.com/JordanSamhi/ic3.git
WORKDIR ic3
RUN mvn clean install:install-file -Dfile=libs/coal-all-0.1.7.jar -DgroupId=edu.psu.cse.siis -DartifactId=coal -Dversion=0.1.7 -Dpackaging=jar
RUN mvn clean package -P standalone
