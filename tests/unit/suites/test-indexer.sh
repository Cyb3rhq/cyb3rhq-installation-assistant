#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore common_logger
    e_certs_path="/etc/cyb3rhq-indexer/certs/"
}

function load-indexer_copyCertificates() {
    @load_function "${base_dir}/indexer.sh" indexer_copyCertificates
    indexer_cert_path="/etc/cyb3rhq-indexer/certs/"
}

test-ASSERT-FAIL-01-indexer_copyCertificates-no-tarfile() {
    load-indexer_copyCertificates
    tar_file=/tmp/tarfile.tar
    if [ -f ${tar_file} ]; then
        @rm ${tar_file}
    fi
    indexer_copyCertificates
}

test-02-indexer_copyCertificates() {
    load-indexer_copyCertificates
    tar_file=/tmp/tarfile.tar
    @touch ${tar_file}
    pos=0
    indexer_node_names=("elastic1" "elastic2")
    debug=
    indexer_copyCertificates
}

test-02-indexer_copyCertificates-assert() {
    rm -f /etc/cyb3rhq-indexer/certs/*
    tar -xf /tmp/tarfile.tar -C /etc/cyb3rhq-indexer/certs/ ./elastic1.pem && mv /etc/cyb3rhq-indexer/certs/elastic1.pem /etc/cyb3rhq-indexer/certs/indexer.pem
    tar -xf /tmp/tarfile.tar -C /etc/cyb3rhq-indexer/certs/ ./elastic1-key.pem && mv /etc/cyb3rhq-indexer/certs/elastic1-key.pem /etc/cyb3rhq-indexer/certs/indexer-key.pem
    tar -xf /tmp/tarfile.tar -C /etc/cyb3rhq-indexer/certs/ ./root-ca.pem
    tar -xf /tmp/tarfile.tar -C /etc/cyb3rhq-indexer/certs/ ./admin.pem
    tar -xf /tmp/tarfile.tar -C /etc/cyb3rhq-indexer/certs/ ./admin-key.pem
}

function load-indexer_install() {
    @load_function "${base_dir}/indexer.sh" indexer_install
}

test-03-indexer_install-yum() {
    load-indexer_install
    sys_type="yum"
    sep="-"
    cyb3rhq_version="4.10.0"
    cyb3rhq_revision="1"
    indexer_install
}

test-03-indexer_install-yum-assert() {
    yum install cyb3rhq-indexer-1.13.2-1 -y
    sysctl -q -w vm.max_map_count=262144
}

test-ASSERT-FAIL-04-indexer_install-yum-error() {
    load-indexer_install
    sys_type="yum"
    sep="-"
    cyb3rhq_version="4.10.0"
    cyb3rhq_revision="1"
    @mockfalse yum install cyb3rhq-indexer-1.13.2-1 -y
    indexer_install
}

test-05-indexer_install-apt() {
    load-indexer_install
    sys_type="apt-get"
    sep="="
    cyb3rhq_version="4.10.0"
    cyb3rhq_revision="1"
    indexer_install
}

test-05-indexer_install-apt-assert() {
    apt install cyb3rhq-indexer=1.13.2-1 -y
    sysctl -q -w vm.max_map_count=262144
}

test-ASSERT-FAIL-06-indexer_install-apt-error() {
    load-indexer_install
    sys_type="apt-get"
    sep="="
    cyb3rhq_version="4.10.0"
    cyb3rhq_revision="1"
    @mockfalse apt install cyb3rhq-indexer=1.13.2-1 -y
    indexer_install
}

function load-indexer_configure() {
    @load_function "${base_dir}/indexer.sh" indexer_configure
}

test-07-indexer_configure-dist-one-elastic-node() {
    load-indexer_configure
    indexer_node_names=("elastic1")
    indexer_node_ips=("1.1.1.1")
    @mocktrue free -g
    @mocktrue awk '/^Mem:/{print $2}'
    @mock java -version === @out
    @mock grep -o -m1 '1.8.0' === @out 1.8.0
    einame="elastic1"
    indexer_configure
}

test-07-indexer_configure-dist-one-elastic-node-assert() {

    sed -i "s/-Xms1g/-Xms1g/" /etc/cyb3rhq-indexer/jvm.options
    sed -i "s/-Xmx1g/-Xmx1g/" /etc/cyb3rhq-indexer/jvm.options

    installCommon_getConfig indexer/indexer_assistant_distributed.yml /etc/cyb3rhq-indexer/opensearch.yml

    indexer_copyCertificates
}

test-08-indexer_configure-dist-two-elastic-nodes() {
    load-indexer_configure
    indexer_node_names=("elastic1" "elastic2")
    indexer_node_ips=("1.1.1.1", "1.1.2.2")
    @mock free -g === @out "1"
    @mocktrue awk '/^Mem:/{print $2}'
    @mock java -version === @out
    @mock grep -o -m1 '1.8.0' === @out 1.8.0
    einame="elastic2"
    indexer_configure
}

test-08-indexer_configure-dist-two-elastic-nodes-assert() {
    sed -i "s/-Xms1g/-Xms1g/" /etc/cyb3rhq-indexer/jvm.options
    sed -i "s/-Xmx1g/-Xmx1g/" /etc/cyb3rhq-indexer/jvm.options

    installCommon_getConfig indexer/indexer_assistant_distributed.yml /etc/cyb3rhq-indexer/opensearch.yml

    indexer_copyCertificates
}

test-09-indexer_configure-AIO() {
    load-indexer_configure
    indexer_node_names=("elastic1")
    indexer_node_ips=("1.1.1.1")
    @mock free -g === @out "1"
    @mocktrue awk '/^Mem:/{print $2}'
    @mock java -version === @out
    @mock grep -o -m1 '1.8.0' === @out 1.8.0

    indexer_configure
}

test-09-indexer_configure-AIO-assert() {
    sed -i 's/-Xms1g/-Xms1g/' /etc/cyb3rhq-indexer/jvm.options
    sed -i 's/-Xmx1g/-Xmx1g/' /etc/cyb3rhq-indexer/jvm.options

    installCommon_getConfig indexer/indexer_assistant_distributed.yml /etc/cyb3rhq-indexer/opensearch.yml

    indexer_copyCertificates
}

function load-indexer_initialize() {
    @load_function "${base_dir}/indexer.sh" indexer_initialize
}

test-10-indexer_initialize-one-node() {
    load-indexer_initialize
    indexer_node_names=("elastic1")
    indexer_node_ips=("1.1.1.1")
    pos=0
    @mocktrue curl -XGET https://1.1.1.1:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null
    indexer_initialize
}

test-10-indexer_initialize-one-node-assert() {
    installCommon_changePasswords
}

test-11-indexer_initialize-two-nodes() {
    load-indexer_initialize
    indexer_node_names=("elastic1" "elastic2")
    indexer_node_ips=("1.1.1.1" "1.1.2.2")
    pos=1
    @mocktrue curl -XGET https://1.1.2.2:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null
    indexer_initialize
    @assert-success
}

test-ASSERT-FAIL-12-indexer_initialize-error-connecting() {
    load-indexer_initialize
    indexer_node_names=("elastic1")
    indexer_node_ips=("1.1.1.1")
    pos=0
    @mockfalse curl -XGET https://1.1.1.1:9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null
    indexer_initialize
}
