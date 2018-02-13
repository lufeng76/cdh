#!/bin/sh

source ./control.sh

function getMySQLRepo() {
  cd /tmp
  wget --quiet —-no-check-certificate https://dev.mysql.com/get/mysql-community-release-el6-5.noarch.rpm
  yum -y localinstall mysql-community-release-el6-5.noarch.rpm
  cd -
}

function getClouderaManagerRepo() {
  cd /etc/yum.repos.d
  wget --quiet http://archive.cloudera.com/cm5/redhat/6/x86_64/cm/cloudera-manager.repo
  cd -
}

function getRepos() {
  say "Installing MySQL yum repo from dev.msql.com" 
  getMySQLRepo
  say "Installing latest Cloudera Manager repo"
  getClouderaManagerRepo
}

getRepos