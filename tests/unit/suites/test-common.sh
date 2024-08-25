#!/usr/bin/env bash
set -euo pipefail
base_dir="$(cd "$(dirname "$BASH_SOURCE")"; pwd -P; cd - >/dev/null;)"
source "${base_dir}"/bach.sh

@setup-test {
    @ignore common_logger
}

function load-common_checkSystem() {
    @load_function "${base_dir}/common.sh" common_checkSystem
}

test-ASSERT-FAIL-01-common_checkSystem-empty() {
    load-common_checkSystem
    @mock command -v yum === @false
    @mock command -v apt-get === @false
    common_checkSystem
}

test-02-common_checkSystem-yum() {
    load-common_checkSystem
    @mock command -v yum === @echo /usr/bin/yum
    @mock command -v apt-get === @false
    common_checkSystem
    echo "$sys_type"
    echo "$sep"
}

test-02-common_checkSystem-yum-assert() {
    sys_type="yum"
    sep="-"
    echo "$sys_type"
    echo "$sep"
}


test-03-common_checkSystem-apt() {
    load-common_checkSystem
    @mock command -v yum === @false
    @mock command -v apt-get === @echo /usr/bin/apt-get
    common_checkSystem
    echo "$sys_type"
    echo "$sep"
}

test-03-common_checkSystem-apt-assert() {
    sys_type="apt-get"
    sep="="
    echo "$sys_type"
    echo "$sep"
}

function load-common_checkInstalled() {
    @load_function "${base_dir}/common.sh" common_checkInstalled
}

test-04-common_checkInstalled-all-installed-yum() {
    load-common_checkInstalled
    sys_type="yum"

    @mocktrue yum list installed

    @mock grep cyb3rhq-manager === @echo cyb3rhq-manager.x86_64 4.10.0-1 @cyb3rhq
    @mkdir /var/ossec

    @mock grep cyb3rhq-indexer === @echo cyb3rhq-indexer.x86_64 1.13.2-1 @cyb3rhq
    @mkdir /var/lib/cyb3rhq-indexer/
    @mkdir /usr/share/cyb3rhq-indexer
    @mkdir /etc/cyb3rhq-indexer

    @mock grep filebeat === @echo filebeat.x86_64 7.10.2-1 @cyb3rhq
    @mkdir /var/lib/filebeat/
    @mkdir /usr/share/filebeat
    @mkdir /etc/filebeat

    @mock grep cyb3rhq-dashboard === @echo cyb3rhq-dashboard.x86_64
    @mkdir /var/lib/cyb3rhq-dashboard/
    @mkdir /usr/share/cyb3rhq-dashboard/
    @mkdir /etc/cyb3rhq-dashboard

    common_checkInstalled
    @echo $cyb3rhq_installed
    @echo $cyb3rhq_remaining_files
    @rmdir /var/ossec

    @echo $indexer_installed
    @echo $indexer_remaining_files
    @rmdir /var/lib/cyb3rhq-indexer/
    @rmdir /usr/share/cyb3rhq-indexer
    @rmdir /etc/cyb3rhq-indexer

    @echo $filebeat_installed
    @echo $filebeat_remaining_files
    @rmdir /var/lib/filebeat/
    @rmdir /usr/share/filebeat
    @rmdir /etc/filebeat

    @echo $dashboard_installed
    @echo $dashboard_remaining_files
    @rmdir /var/lib/cyb3rhq-dashboard/
    @rmdir /usr/share/cyb3rhq-dashboard/
    @rmdir /etc/cyb3rhq-dashboard/

}

test-05-common_checkInstalled-all-installed-yum-assert() {
    @echo "cyb3rhq-manager.x86_64 4.10.0-1 @cyb3rhq"
    @echo 1

    @echo "cyb3rhq-indexer.x86_64 4.6.0-1 @cyb3rhq"
    @echo 1

    @echo "filebeat.x86_64 7.10.2-1 @cyb3rhq"
    @echo 1

    @echo "cyb3rhq-dashboard.x86_64"
    @echo 1
}


test-05-common_checkInstalled-all-installed-apt() {
    load-common_checkInstalled
    sys_type="apt-get"

    @mocktrue apt list --installed

    @mock grep cyb3rhq-manager === @echo cyb3rhq-manager/now 4.2.5-1 amd64 [installed,local]
    @mkdir /var/ossec

    @mock grep cyb3rhq-indexer === @echo cyb3rhq-indexer/stable,now 1.13.2-1 amd64 [installed]

    @mkdir /var/lib/cyb3rhq-indexer/
    @mkdir /usr/share/cyb3rhq-indexer
    @mkdir /etc/cyb3rhq-indexer

    @mock grep filebeat === @echo filebeat/now 7.10.2 amd64 [installed,local]
    @mkdir /var/lib/filebeat/
    @mkdir /usr/share/filebeat
    @mkdir /etc/filebeat

    @mock grep cyb3rhq-dashboard === @echo cyb3rhq-dashboard/now 1.13.2 amd64 [installed,local]
    @mkdir /var/lib/cyb3rhq-dashboard/
    @mkdir /usr/share/cyb3rhq-dashboard/
    @mkdir /etc/cyb3rhq-dashboard

    common_checkInstalled
    @echo $cyb3rhq_installed
    @echo $cyb3rhq_remaining_files
    @rmdir /var/ossec

    @echo $indexer_installed
    @echo $indexer_remaining_files
    @rmdir /var/lib/cyb3rhq-indexer/
    @rmdir /usr/share/cyb3rhq-indexer
    @rmdir /etc/cyb3rhq-indexer

    @echo $filebeat_installed
    @echo $filebeat_remaining_files
    @rmdir /var/lib/filebeat/
    @rmdir /usr/share/filebeat
    @rmdir /etc/filebeat

    @echo $dashboard_installed
    @echo $dashboard_remaining_files
    @rmdir /var/lib/cyb3rhq-dashboard/
    @rmdir /usr/share/cyb3rhq-dashboard/
    @rmdir /etc/cyb3rhq-dashboard/

}

test-05-common_checkInstalled-all-installed-apt-assert() {
    @echo "cyb3rhq-manager/now 4.2.5-1 amd64 [installed,local]"
    @echo 1

    @echo "cyb3rhq-indexer/stable,now 1.13.2-1 amd64 [installed]"
    @echo 1

    @echo "filebeat/now 7.10.2 amd64 [installed,local]"
    @echo 1

    @echo "cyb3rhq-dashboard/now 1.13.2 amd64 [installed,local]"
    @echo 1
}

test-06-common_checkInstalled-nothing-installed-apt() {
    load-common_checkInstalled
    sys_type="apt-get"

    @mocktrue apt list --installed

    @mock grep cyb3rhq-manager

    @mock grep cyb3rhq-indexer


    @mock grep filebeat

    @mock grep cyb3rhq-dashboard

    common_checkInstalled
    @echo $cyb3rhq_installed
    @echo $cyb3rhq_remaining_files

    @echo $indexer_installed
    @echo $indexer_remaining_files

    @echo $filebeat_installed
    @echo $filebeat_remaining_files

    @echo $dashboard_installed
    @echo $dashboard_remaining_files
}

test-06-common_checkInstalled-nothing-installed-apt-assert() {
    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""
}

test-07-common_checkInstalled-nothing-installed-yum() {
    load-common_checkInstalled
    sys_type="yum"

    @mocktrue yum list installed

    @mock grep cyb3rhq-manager

    @mock grep cyb3rhq-indexer


    @mock grep filebeat

    @mock grep cyb3rhq-dashboard

    common_checkInstalled
    @echo $cyb3rhq_installed
    @echo $cyb3rhq_remaining_files

    @echo $indexer_installed
    @echo $indexer_remaining_files

    @echo $filebeat_installed
    @echo $filebeat_remaining_files

    @echo $dashboard_installed
    @echo $dashboard_remaining_files
}

test-07-common_checkInstalled-nothing-installed-yum-assert() {
    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""

    @echo ""
    @echo ""
}
