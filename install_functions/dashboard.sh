# Cyb3rhq installer - dashboard.sh functions.
# Copyright (C) 2015, Cyb3rhq Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function dashboard_changePort() {

    chosen_port="$1"
    http_port="${chosen_port}" 
    cyb3rhq_dashboard_port=( "${http_port}" )
    cyb3rhq_aio_ports=(9200 9300 1514 1515 1516 55000 "${http_port}")

    sed -i 's/server\.port: [0-9]\+$/server.port: '"${chosen_port}"'/' "$0"
    common_logger "Cyb3rhq web interface port will be ${chosen_port}."
}

function dashboard_configure() {

    common_logger -d "Configuring Cyb3rhq dashboard."
    if [ -n "${AIO}" ]; then
        eval "installCommon_getConfig dashboard/dashboard_assistant.yml /etc/cyb3rhq-dashboard/opensearch_dashboards.yml ${debug}"
        dashboard_copyCertificates "${debug}"
    else
        eval "installCommon_getConfig dashboard/dashboard_assistant_distributed.yml /etc/cyb3rhq-dashboard/opensearch_dashboards.yml ${debug}"
        dashboard_copyCertificates "${debug}"
        if [ "${#dashboard_node_names[@]}" -eq 1 ]; then
            pos=0
            ip=${dashboard_node_ips[0]}
        else
            for i in "${!dashboard_node_names[@]}"; do
                if [[ "${dashboard_node_names[i]}" == "${dashname}" ]]; then
                    pos="${i}";
                fi
            done
            ip=${dashboard_node_ips[pos]}
        fi

        if [[ "${ip}" != "127.0.0.1" ]]; then
            echo "server.host: ${ip}" >> /etc/cyb3rhq-dashboard/opensearch_dashboards.yml
        else
            echo 'server.host: '0.0.0.0'' >> /etc/cyb3rhq-dashboard/opensearch_dashboards.yml
        fi

        if [ "${#indexer_node_names[@]}" -eq 1 ]; then
            echo "opensearch.hosts: https://${indexer_node_ips[0]}:9200" >> /etc/cyb3rhq-dashboard/opensearch_dashboards.yml
        else
            echo "opensearch.hosts:" >> /etc/cyb3rhq-dashboard/opensearch_dashboards.yml
            for i in "${indexer_node_ips[@]}"; do
                    echo "  - https://${i}:9200" >> /etc/cyb3rhq-dashboard/opensearch_dashboards.yml
            done
        fi
    fi

    sed -i 's/server\.port: [0-9]\+$/server.port: '"${chosen_port}"'/' /etc/cyb3rhq-dashboard/opensearch_dashboards.yml

    common_logger "Cyb3rhq dashboard post-install configuration finished."

}

function dashboard_copyCertificates() {

    common_logger -d "Copying Cyb3rhq dashboard certificates."
    eval "rm -f ${dashboard_cert_path}/* ${debug}"
    name=${dashboard_node_names[pos]}

    if [ -f "${tar_file}" ]; then
        if ! tar -tvf "${tar_file}" | grep -q "${name}" ; then
            common_logger -e "Tar file does not contain certificate for the node ${name}."
            installCommon_rollBack
            exit 1;
        fi
        eval "mkdir ${dashboard_cert_path} ${debug}"
        eval "sed -i s/dashboard.pem/${name}.pem/ /etc/cyb3rhq-dashboard/opensearch_dashboards.yml ${debug}"
        eval "sed -i s/dashboard-key.pem/${name}-key.pem/ /etc/cyb3rhq-dashboard/opensearch_dashboards.yml ${debug}"
        eval "tar -xf ${tar_file} -C ${dashboard_cert_path} cyb3rhq-install-files/${name}.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${dashboard_cert_path} cyb3rhq-install-files/${name}-key.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${dashboard_cert_path} cyb3rhq-install-files/root-ca.pem --strip-components 1 ${debug}"
        eval "chown -R cyb3rhq-dashboard:cyb3rhq-dashboard /etc/cyb3rhq-dashboard/ ${debug}"
        eval "chmod 500 ${dashboard_cert_path} ${debug}"
        eval "chmod 400 ${dashboard_cert_path}/* ${debug}"
        eval "chown cyb3rhq-dashboard:cyb3rhq-dashboard ${dashboard_cert_path}/* ${debug}"
        common_logger -d "Cyb3rhq dashboard certificate setup finished."
    else
        common_logger -e "No certificates found. Cyb3rhq dashboard  could not be initialized."
        installCommon_rollBack
        exit 1
    fi

}

function dashboard_initialize() {

    common_logger "Initializing Cyb3rhq dashboard web application."
    installCommon_getPass "admin"
    j=0

    if [ "${#dashboard_node_names[@]}" -eq 1 ]; then
        nodes_dashboard_ip=${dashboard_node_ips[0]}
    else
        for i in "${!dashboard_node_names[@]}"; do
            if [[ "${dashboard_node_names[i]}" == "${dashname}" ]]; then
                pos="${i}";
            fi
        done
        nodes_dashboard_ip=${dashboard_node_ips[pos]}
    fi

    if [ "${nodes_dashboard_ip}" == "localhost" ] || [[ "${nodes_dashboard_ip}" == 127.* ]]; then
        print_ip="<cyb3rhq-dashboard-ip>"
    else
        print_ip="${nodes_dashboard_ip}"
    fi

    until [ "$(curl -XGET https://"${nodes_dashboard_ip}":"${http_port}"/status -uadmin:"${u_pass}" -k -w %"{http_code}" -s -o /dev/null)" -eq "200" ] || [ "${j}" -eq "12" ]; do
        sleep 10
        j=$((j+1))
        common_logger -d "Retrying Cyb3rhq dashboard connection..."
    done

    if [ ${j} -lt 12 ]; then
        common_logger -d "Cyb3rhq dashboard connection was successful."
        if [ "${#server_node_names[@]}" -eq 1 ]; then
            cyb3rhq_api_address=${server_node_ips[0]}
        else
            for i in "${!server_node_types[@]}"; do
                if [[ "${server_node_types[i]}" == "master" ]]; then
                    cyb3rhq_api_address=${server_node_ips[i]}
                fi
            done
        fi
        if [ -f "/usr/share/cyb3rhq-dashboard/data/cyb3rhq/config/cyb3rhq.yml" ]; then
            eval "sed -i 's,url: https://localhost,url: https://${cyb3rhq_api_address},g' /usr/share/cyb3rhq-dashboard/data/cyb3rhq/config/cyb3rhq.yml ${debug}"
        fi

        common_logger "Cyb3rhq dashboard web application initialized."
        common_logger -nl "--- Summary ---"
        common_logger -nl "You can access the web interface https://${print_ip}:${http_port}\n    User: admin\n    Password: ${u_pass}"

    else
        flag="-w"
        if [ -z "${force}" ]; then
            flag="-e"
        fi
        failed_nodes=()
        common_logger "${flag}" "Cannot connect to Cyb3rhq dashboard."

        for i in "${!indexer_node_ips[@]}"; do
            curl=$(common_curl -XGET https://"${indexer_node_ips[i]}":9200/ -uadmin:"${u_pass}" -k -s --max-time 300 --retry 5 --retry-delay 5 --fail)
            exit_code=${PIPESTATUS[0]}
            if [[ "${exit_code}" -eq "7" ]]; then
                failed_connect=1
                failed_nodes+=("${indexer_node_names[i]}")
            elif [ "${exit_code}" -eq "22" ]; then
                sec_not_initialized=1
            fi
        done
        if [ -n "${failed_connect}" ]; then
            common_logger "${flag}" "Failed to connect with ${failed_nodes[*]}. Connection refused."
        fi

        if [ -n "${sec_not_initialized}" ]; then
            common_logger "${flag}" "Cyb3rhq indexer security settings not initialized. Please run the installation assistant using -s|--start-cluster in one of the cyb3rhq indexer nodes."
        fi

        if [ -z "${force}" ]; then
            common_logger "If you want to install Cyb3rhq dashboard without waiting for the Cyb3rhq indexer cluster, use the -fd option"
            installCommon_rollBack
            exit 1
        else
            common_logger -nl "--- Summary ---"
            common_logger -nl "When Cyb3rhq dashboard is able to connect to your Cyb3rhq indexer cluster, you can access the web interface https://${print_ip}\n    User: admin\n    Password: ${u_pass}"
        fi
    fi

}

function dashboard_initializeAIO() {

    cyb3rhq_api_address=${server_node_ips[0]}
    common_logger "Initializing Cyb3rhq dashboard web application."
    installCommon_getPass "admin"
    http_code=$(curl -XGET https://localhost:"${http_port}"/status -uadmin:"${u_pass}" -k -w %"{http_code}" -s -o /dev/null)
    retries=0
    max_dashboard_initialize_retries=20
    while [ "${http_code}" -ne "200" ] && [ "${retries}" -lt "${max_dashboard_initialize_retries}" ]
    do
        http_code=$(curl -XGET https://localhost:"${http_port}"/status -uadmin:"${u_pass}" -k -w %"{http_code}" -s -o /dev/null)
        common_logger "Cyb3rhq dashboard web application not yet initialized. Waiting..."
        retries=$((retries+1))
        sleep 15
    done
    if [ "${http_code}" -eq "200" ]; then
        if [ -f "/usr/share/cyb3rhq-dashboard/data/cyb3rhq/config/cyb3rhq.yml" ]; then
            eval "sed -i 's,url: https://localhost,url: https://${cyb3rhq_api_address},g' /usr/share/cyb3rhq-dashboard/data/cyb3rhq/config/cyb3rhq.yml ${debug}"
        fi
        common_logger "Cyb3rhq dashboard web application initialized."
        common_logger -nl "--- Summary ---"
        common_logger -nl "You can access the web interface https://<cyb3rhq-dashboard-ip>:${http_port}\n    User: admin\n    Password: ${u_pass}"
    else
        common_logger -e "Cyb3rhq dashboard installation failed."
        installCommon_rollBack
        exit 1
    fi
}

function dashboard_install() {

    common_logger "Starting Cyb3rhq dashboard installation."
    if [ "${sys_type}" == "yum" ]; then
        installCommon_yumInstall "cyb3rhq-dashboard" "${cyb3rhq_version}-*"
    elif [ "${sys_type}" == "apt-get" ]; then
        installCommon_aptInstall "cyb3rhq-dashboard" "${cyb3rhq_version}-*"
    fi
    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${dashboard_installed}" ]; then
        common_logger -e "Cyb3rhq dashboard installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Cyb3rhq dashboard installation finished."
    fi

}
