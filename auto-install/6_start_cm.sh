#!/bin/sh

source ./control.sh 

function initCM() {
  service cloudera-scm-server start
}

function testAPI() {
  AUTH="admin:admin"
  # JSON="Content-type: application/json"
  API_URL="http://$(hostname -f):7180/api"
  say "CM API URL Base: ${API_URL}"

  VER=`curl -u ${AUTH} "${API_URL}/version" --silent`
  say "Latest API version is ${VER}"
  echo

  greeting="Greetings!" 
  say "Testing API echo..."
  curl -X GET -u ${AUTH} --silent -i "${API_URL}/${VER}/tools/echo?message=$greeting"
}

function verifyCM() {
  say "Initializing Cloudera Manager service..."
  initCM
  say "Wait until the Jetty service is started to browse"
  say "Use tail -f /var/log/cloudera-scm-server/cloudera-scm-server.log | grep 'Started Jetty server'" 
  say "Sleeping for 45 seconds before testing REST API"
  sleep 45
  say "Verifying CM API version..."
  testAPI
}

verifyCM