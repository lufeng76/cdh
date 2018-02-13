#!/bin/sh

source ./control.sh

function install() {
  yum info $1
  yum -y install $1
}

function addJDK() {
  install oracle-j2sdk1.7.x86_64
}

function addCMServer() {
  install cloudera-manager-server
}

function addMySQL() {
  install mysql-community-server
}

function installPkgs() {
  say "Installing JDK 1.7..."
  addJDK
  say "Installing Cloudera Manager server"
  addCMServer
  say "Installing MySQL server"
  addMySQL
}

installPkgs