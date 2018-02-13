#!/bin/sh

source ./control.sh

function startMySQL() {
  service mysqld start
}

function secureMySQL() {
  mysql_secure_installation
}

function noIPV6User() {
mysql -u root -p <<EOC
DELETE FROM mysql.user WHERE host='::1';
FLUSH PRIVILEGES;
EOC
}

function createDB() {
  db=$1
  user=$2
  node=$3
  pass=$4

  echo "Creating database ${db}"
  echo "Granting access to ${user} on ${node}"

mysql -u root -p <<EOC
CREATE DATABASE ${db};
GRANT ALL ON ${db}.\* TO \"${user}\"@\"${node}\" IDENTIFIED BY \"${pass}\";
EOC
}

function createDBs() {
  admin=`hostname -f`
  edge=${admin}
  createDB scm scm ${admin} cloudera
  createDB rman rman ${admin} cloudera
  createDB hive hive ${admin} cloudera
  createDB oozie oozie ${edge} cloudera
  createDB hue hue ${edge} cloudera
  createDB sentry sentry ${admin} cloudera
}

function integrateDB() {
  path=/usr/share/cmf/schema
  ${path}/scm_prepare_database.sh mysql -h $(hostname -f) --scm-host $(hostname -f) scm scm
}

function configureMySQL() {
  startMySQL
  say "Securing your MySQL server..."
  secureMySQL
  noIPV6User
  say "Creating databases for CM and CDH services..."
  createDBs
  say "Verifying and writing db connection string for CM..."
  integrateDB
}

configureMySQL