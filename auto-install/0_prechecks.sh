#!/bin/sh

source ./control.sh

function no_hugepages() {
  echo never > /sys/kernel/mm/transparent_hugepage/enabled
  echo never > /sys/kernel/mm/transparent_hugepage/defrag
}

function verify_capacity() {

}

function verify_ntpd_on() {

}

function verify_nscd_on() {

}

function verify_dns_resolves() {

}

function verify_reverse_dns_resolves() {

}

function verify_iptables_off() {

}