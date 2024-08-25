# Common functions for Cyb3rhq installation assistant,
# cyb3rhq-passwords-tool and cyb3rhq-cert-tool
# Copyright (C) 2015, Cyb3rhq Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function common_checkAptLock() {

    attempt=0
    seconds=30
    max_attempts=10

    while fuser "${apt_lockfile}" >/dev/null 2>&1 && [ "${attempt}" -lt "${max_attempts}" ]; do
        attempt=$((attempt+1))
        common_logger "Another process is using APT. Waiting for it to release the lock. Next retry in ${seconds} seconds (${attempt}/${max_attempts})"
        sleep "${seconds}"
    done

}

function common_logger() {

    now=$(date +'%d/%m/%Y %H:%M:%S')
    mtype="INFO:"
    debugLogger=
    nolog=
    if [ -n "${1}" ]; then
        while [ -n "${1}" ]; do
            case ${1} in
                "-e")
                    mtype="ERROR:"
                    shift 1
                    ;;
                "-w")
                    mtype="WARNING:"
                    shift 1
                    ;;
                "-d")
                    debugLogger=1
                    mtype="DEBUG:"
                    shift 1
                    ;;
                "-nl")
                    nolog=1
                    shift 1
                    ;;
                *)
                    message="${1}"
                    shift 1
                    ;;
            esac
        done
    fi

    if [ -z "${debugLogger}" ] || { [ -n "${debugLogger}" ] && [ -n "${debugEnabled}" ]; }; then
        if [ -z "${nolog}" ] && { [ "$EUID" -eq 0 ] || [[ "$(basename "$0")" =~ $cert_tool_script_name ]]; }; then
            printf "%s\n" "${now} ${mtype} ${message}" | tee -a ${logfile}
        else
            printf "%b\n" "${now} ${mtype} ${message}"
        fi
    fi

}

function common_checkRoot() {

    common_logger -d "Checking root permissions."
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root."
        exit 1;
    fi

    common_logger -d "Checking sudo package."
    if ! command -v sudo > /dev/null; then 
        common_logger -e "The sudo package is not installed and it is necessary for the installation."
        exit 1;
    fi
}

function common_checkInstalled() {

    common_logger -d "Checking Cyb3rhq installation."
    cyb3rhq_installed=""
    indexer_installed=""
    filebeat_installed=""
    dashboard_installed=""

    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q cyb3rhq-manager --quiet && cyb3rhq_installed=1"
    elif [ "${sys_type}" == "apt-get" ]; then
        cyb3rhq_installed=$(apt list --installed  2>/dev/null | grep cyb3rhq-manager)
    fi

    if [ -d "/var/ossec" ]; then
        common_logger -d "There are Cyb3rhq remaining files."
        cyb3rhq_remaining_files=1
    fi

    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q cyb3rhq-indexer --quiet && indexer_installed=1"

    elif [ "${sys_type}" == "apt-get" ]; then
        indexer_installed=$(apt list --installed 2>/dev/null | grep cyb3rhq-indexer)
    fi

    if [ -d "/var/lib/cyb3rhq-indexer/" ] || [ -d "/usr/share/cyb3rhq-indexer" ] || [ -d "/etc/cyb3rhq-indexer" ] || [ -f "${base_path}/search-guard-tlstool*" ]; then
        common_logger -d "There are Cyb3rhq indexer remaining files."
        indexer_remaining_files=1
    fi

    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q filebeat --quiet && filebeat_installed=1"
    elif [ "${sys_type}" == "apt-get" ]; then
        filebeat_installed=$(apt list --installed  2>/dev/null | grep filebeat)
    fi

    if [ -d "/var/lib/filebeat/" ] || [ -d "/usr/share/filebeat" ] || [ -d "/etc/filebeat" ]; then
        common_logger -d "There are Filebeat remaining files."
        filebeat_remaining_files=1
    fi

    if [ "${sys_type}" == "yum" ]; then
        eval "rpm -q cyb3rhq-dashboard --quiet && dashboard_installed=1"
    elif [ "${sys_type}" == "apt-get" ]; then
        dashboard_installed=$(apt list --installed  2>/dev/null | grep cyb3rhq-dashboard)
    fi

    if [ -d "/var/lib/cyb3rhq-dashboard/" ] || [ -d "/usr/share/cyb3rhq-dashboard" ] || [ -d "/etc/cyb3rhq-dashboard" ] || [ -d "/run/cyb3rhq-dashboard/" ]; then
        common_logger -d "There are Cyb3rhq dashboard remaining files."
        dashboard_remaining_files=1
    fi

}

function common_checkSystem() {

    if [ -n "$(command -v yum)" ]; then
        sys_type="yum"
        sep="-"
        common_logger -d "YUM package manager will be used."
    elif [ -n "$(command -v apt-get)" ]; then
        sys_type="apt-get"
        sep="="
        common_logger -d "APT package manager will be used."
    else
        common_logger -e "Couldn't find YUM or APT package manager. Try installing the one corresponding to your operating system and then, launch the installation assistant again."
        exit 1
    fi

}

function common_checkCyb3rhqConfigYaml() {

    common_logger -d "Checking Cyb3rhq YAML configuration file."
    filecorrect=$(cert_parseYaml "${config_file}" | grep -Ev '^#|^\s*$' | grep -Pzc "\A(\s*(nodes_indexer__name|nodes_indexer__ip|nodes_server__name|nodes_server__ip|nodes_server__node_type|nodes_dashboard__name|nodes_dashboard__ip)=.*?)+\Z")
    if [[ "${filecorrect}" -ne 1 ]]; then
        common_logger -e "The configuration file ${config_file} does not have a correct format."
        exit 1
    fi

}

# Retries even if the --retry-connrefused is not available
function common_curl() {

    if [ -n "${curl_has_connrefused}" ]; then
        eval "curl $@ --retry-connrefused"
        e_code="${PIPESTATUS[0]}"
    else
        retries=0
        eval "curl $@"
        e_code="${PIPESTATUS[0]}"
        while [ "${e_code}" -eq 7 ] && [ "${retries}" -ne 12 ]; do
            retries=$((retries+1))
            sleep 5
            eval "curl $@"
            e_code="${PIPESTATUS[0]}"
        done
    fi
    return "${e_code}"

}

function common_remove_gpg_key() {

    common_logger -d "Removing GPG key from system."
    if [ "${sys_type}" == "yum" ]; then
        if { rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\t%{SUMMARY}\n' | grep "Cyb3rhq"; } >/dev/null ; then
            key=$(rpm -q gpg-pubkey --qf '%{NAME}-%{VERSION}-%{RELEASE}\t%{SUMMARY}\n' | grep "Cyb3rhq Signing Key" | awk '{print $1}' )
            rpm -e "${key}"
        else
            common_logger "Cyb3rhq GPG key not found in the system"
            return 1
        fi
    elif [ "${sys_type}" == "apt-get" ]; then
        if [ -f "/usr/share/keyrings/cyb3rhq.gpg" ]; then
            rm -rf "/usr/share/keyrings/cyb3rhq.gpg" "${debug}"
        else
            common_logger "Cyb3rhq GPG key not found in the system"
            return 1
        fi
    fi

}

function common_checkYumLock() {

    attempt=0
    seconds=30
    max_attempts=10

    while [ -f "${yum_lockfile}" ] && [ "${attempt}" -lt "${max_attempts}" ]; do
        attempt=$((attempt+1))
        common_logger "Another process is using YUM. Waiting for it to release the lock. Next retry in ${seconds} seconds (${attempt}/${max_attempts})"
        sleep "${seconds}"
    done

}