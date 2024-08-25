# Cyb3rhq installer - variables
# Copyright (C) 2015, Cyb3rhq Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

## Package vars
readonly cyb3rhq_major="4.10"
readonly cyb3rhq_version="4.10.0"
readonly filebeat_version="7.10.2"
readonly cyb3rhq_install_vesion="0.1"
readonly source_branch="v${cyb3rhq_version}"

## Links and paths to resources
readonly resources="https://${bucket}/${cyb3rhq_major}"
readonly base_url="https://${bucket}/${repository}"
base_path="$(dirname "$(readlink -f "$0")")"
readonly base_path
config_file="${base_path}/config.yml"
readonly tar_file_name="cyb3rhq-install-files.tar"
tar_file="${base_path}/${tar_file_name}"

filebeat_cyb3rhq_template="https://raw.githubusercontent.com/cyb3rhq/cyb3rhq/${source_branch}/extensions/elasticsearch/7.x/cyb3rhq-template.json"

readonly dashboard_cert_path="/etc/cyb3rhq-dashboard/certs"
readonly filebeat_cert_path="/etc/filebeat/certs"
readonly indexer_cert_path="/etc/cyb3rhq-indexer/certs"

readonly logfile="/var/log/cyb3rhq-install.log"
debug=">> ${logfile} 2>&1"
readonly yum_lockfile="/var/run/yum.pid"
readonly apt_lockfile="/var/lib/dpkg/lock"

## Offline Installation vars
readonly base_dest_folder="cyb3rhq-offline"
readonly manager_deb_base_url="${base_url}/apt/pool/main/w/cyb3rhq-manager"
readonly filebeat_deb_base_url="${base_url}/apt/pool/main/f/filebeat"
readonly filebeat_deb_package="filebeat-oss-${filebeat_version}-amd64.deb"
readonly indexer_deb_base_url="${base_url}/apt/pool/main/w/cyb3rhq-indexer"
readonly dashboard_deb_base_url="${base_url}/apt/pool/main/w/cyb3rhq-dashboard"
readonly manager_rpm_base_url="${base_url}/yum"
readonly filebeat_rpm_base_url="${base_url}/yum"
readonly filebeat_rpm_package="filebeat-oss-${filebeat_version}-x86_64.rpm"
readonly indexer_rpm_base_url="${base_url}/yum"
readonly dashboard_rpm_base_url="${base_url}/yum"
readonly cyb3rhq_gpg_key="https://${bucket}/key/GPG-KEY-CYB3RHQ"
readonly filebeat_config_file="${resources}/tpl/cyb3rhq/filebeat/filebeat.yml"

adminUser="cyb3rhq"
adminPassword="cyb3rhq"

http_port=443
cyb3rhq_aio_ports=( 9200 9300 1514 1515 1516 55000 "${http_port}")
readonly cyb3rhq_indexer_ports=( 9200 9300 )
readonly cyb3rhq_manager_ports=( 1514 1515 1516 55000 )
cyb3rhq_dashboard_port="${http_port}"
# `lsof` and `openssl` are installed separately
wia_yum_dependencies=( systemd grep tar coreutils sed procps-ng gawk curl )
readonly wia_apt_dependencies=( systemd grep tar coreutils sed procps gawk curl )
readonly cyb3rhq_yum_dependencies=( libcap )
readonly cyb3rhq_apt_dependencies=( apt-transport-https libcap2-bin software-properties-common gnupg )
readonly indexer_yum_dependencies=( coreutils )
readonly indexer_apt_dependencies=( debconf adduser procps gnupg apt-transport-https )
readonly dashboard_yum_dependencies=( libcap )
readonly dashboard_apt_dependencies=( debhelper tar curl libcap2-bin gnupg apt-transport-https )
wia_dependencies_installed=()
