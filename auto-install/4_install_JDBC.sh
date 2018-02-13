#!/bin/sh

source ./control.sh

function getConnector() {
  cd /tmp
  wget --quiet http://dev.mysql.com/get/Downloads/Connector-J/mysql-connector-java-5.1.35.tar.gz
}

function extractJAR() {
  gunzip /tmp/mysql-connector-java-5.1.35.tar.gz
  tar xvf /tmp/mysql-connector-java-5.1.35.tar
}

function placeJAR() {
  cd /tmp/mysql-connector-java-5.1.35/
  mkdir -p /usr/share/java
  cp mysql-connector-java-5.1.35-bin.jar /usr/share/java
  cd /usr/share/java
  ln mysql-connector-java-5.1.35-bin.jar mysql-connector-java.jar
}

function integrateConnector() {
  # Assumes Cloudera Manager server package is installed
  cm_config=/etc/default/cloudera-scm-server
  jar_name=`grep CMF_JDBC_DRIVER_JAR ${cm_config}`
  echo "${cm_config}: ${jar_name}"
}

function installConnector() {
  say "Installing MySQL JDBC connector..."
  getConnector
  extractJAR
  placeJAR
  say "Configuring CM Server with MySQL JDBC..."
  integrateConnector
}

installConnector