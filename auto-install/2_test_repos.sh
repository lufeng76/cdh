#!/bin/sh

source ./control.sh

function cleanYUM() {
  yum clean all
  rm -Rf /var/cache/yum/x86_64
  yum makecache
}

function verifyRepo() {
  yum repolist enabled | grep Cloudera
  yum repolist enabled | grep MySQL
}

function prepRepos() {
  say "Refreshing YUM metadata"
  cleanYUM
  say "Verifying utility repos"
  verifyRepo
}

prepRepos