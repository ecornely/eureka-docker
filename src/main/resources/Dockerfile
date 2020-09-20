FROM ecornely/java
#FROM debian
MAINTAINER Eric Cornely <ericcornely@gmail.com>
#RUN apt update -qq && apt install -qq -y openjdk-11-jdk-headless
WORKDIR /opt
EXPOSE 8761
ADD ./target/discovery.jar /opt
ENTRYPOINT ["java","-jar","/opt/discovery.jar"]