# Cyb3rhq installer - indexer.sh functions.
# Copyright (C) 2015, Cyb3rhq Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

function indexer_configure() {

    common_logger -d "Configuring Cyb3rhq indexer."
    eval "export JAVA_HOME=/usr/share/cyb3rhq-indexer/jdk/"

    # Configure JVM options for Cyb3rhq indexer
    ram_gb=$(free -m | awk 'FNR == 2 {print $2}')
    ram="$(( ram_mb / 2 ))"

    if [ "${ram}" -eq "0" ]; then
        ram=1024;
    fi
    eval "sed -i "s/-Xms1g/-Xms${ram}m/" /etc/cyb3rhq-indexer/jvm.options ${debug}"
    eval "sed -i "s/-Xmx1g/-Xmx${ram}m/" /etc/cyb3rhq-indexer/jvm.options ${debug}"

    if [ -n "${AIO}" ]; then
        eval "installCommon_getConfig indexer/indexer_all_in_one.yml /etc/cyb3rhq-indexer/opensearch.yml ${debug}"
    else
        eval "installCommon_getConfig indexer/indexer_assistant_distributed.yml /etc/cyb3rhq-indexer/opensearch.yml ${debug}"
        if [ "${#indexer_node_names[@]}" -eq 1 ]; then
            pos=0
            {
            echo "node.name: ${indxname}"
            echo "network.host: ${indexer_node_ips[0]}"
            echo "cluster.initial_master_nodes: ${indxname}"
            echo "plugins.security.nodes_dn:"
            echo '        - CN='"${indxname}"',OU=Cyb3rhq,O=Cyb3rhq,L=California,C=US'
            } >> /etc/cyb3rhq-indexer/opensearch.yml
        else
            echo "node.name: ${indxname}" >> /etc/cyb3rhq-indexer/opensearch.yml
            echo "cluster.initial_master_nodes:" >> /etc/cyb3rhq-indexer/opensearch.yml
            for i in "${indexer_node_names[@]}"; do
                echo "        - ${i}" >> /etc/cyb3rhq-indexer/opensearch.yml
            done

            echo "discovery.seed_hosts:" >> /etc/cyb3rhq-indexer/opensearch.yml
            for i in "${indexer_node_ips[@]}"; do
                echo "        - ${i}" >> /etc/cyb3rhq-indexer/opensearch.yml
            done

            for i in "${!indexer_node_names[@]}"; do
                if [[ "${indexer_node_names[i]}" == "${indxname}" ]]; then
                    pos="${i}";
                fi
            done

            echo "network.host: ${indexer_node_ips[pos]}" >> /etc/cyb3rhq-indexer/opensearch.yml

            echo "plugins.security.nodes_dn:" >> /etc/cyb3rhq-indexer/opensearch.yml
            for i in "${indexer_node_names[@]}"; do
                    echo "        - CN=${i},OU=Cyb3rhq,O=Cyb3rhq,L=California,C=US" >> /etc/cyb3rhq-indexer/opensearch.yml
            done
        fi
    fi

    indexer_copyCertificates

    jv=$(java -version 2>&1 | grep -o -m1 '1.8.0' )
    if [ "$jv" == "1.8.0" ]; then
        {
        echo "cyb3rhq-indexer hard nproc 4096"
        echo "cyb3rhq-indexer soft nproc 4096"
        echo "cyb3rhq-indexer hard nproc 4096"
        echo "cyb3rhq-indexer soft nproc 4096"
        } >> /etc/security/limits.conf
        echo -ne "\nbootstrap.system_call_filter: false" >> /etc/cyb3rhq-indexer/opensearch.yml
    fi

    common_logger "Cyb3rhq indexer post-install configuration finished."
}

function indexer_copyCertificates() {

    common_logger -d "Copying Cyb3rhq indexer certificates."
    eval "rm -f ${indexer_cert_path}/* ${debug}"
    name=${indexer_node_names[pos]}

    if [ -f "${tar_file}" ]; then
        if ! tar -tvf "${tar_file}" | grep -q "${name}" ; then
            common_logger -e "Tar file does not contain certificate for the node ${name}."
            installCommon_rollBack
            exit 1;
        fi
        eval "mkdir ${indexer_cert_path} ${debug}"
        eval "sed -i s/indexer.pem/${name}.pem/ /etc/cyb3rhq-indexer/opensearch.yml ${debug}"
        eval "sed -i s/indexer-key.pem/${name}-key.pem/ /etc/cyb3rhq-indexer/opensearch.yml ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} cyb3rhq-install-files/${name}.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} cyb3rhq-install-files/${name}-key.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} cyb3rhq-install-files/root-ca.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} cyb3rhq-install-files/admin.pem --strip-components 1 ${debug}"
        eval "tar -xf ${tar_file} -C ${indexer_cert_path} cyb3rhq-install-files/admin-key.pem --strip-components 1 ${debug}"
        eval "rm -rf ${indexer_cert_path}/cyb3rhq-install-files/ ${debug}"
        eval "chown -R cyb3rhq-indexer:cyb3rhq-indexer ${indexer_cert_path} ${debug}"
        eval "chmod 500 ${indexer_cert_path} ${debug}"
        eval "chmod 400 ${indexer_cert_path}/* ${debug}"
    else
        common_logger -e "No certificates found. Could not initialize Cyb3rhq indexer"
        installCommon_rollBack
        exit 1;
    fi

}

function indexer_initialize() {

    common_logger "Initializing Cyb3rhq indexer cluster security settings."
    eval "common_curl -XGET https://"${indexer_node_ips[pos]}":9200/ -uadmin:admin -k --max-time 120 --silent --output /dev/null"
    e_code="${PIPESTATUS[0]}"

    if [ "${e_code}" -ne "0" ]; then
        common_logger -e "Cannot initialize Cyb3rhq indexer cluster."
        installCommon_rollBack
        exit 1
    fi

    if [ -n "${AIO}" ]; then
        eval "sudo -u cyb3rhq-indexer JAVA_HOME=/usr/share/cyb3rhq-indexer/jdk/ OPENSEARCH_CONF_DIR=/etc/cyb3rhq-indexer /usr/share/cyb3rhq-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /etc/cyb3rhq-indexer/opensearch-security -icl -p 9200 -nhnv -cacert ${indexer_cert_path}/root-ca.pem -cert ${indexer_cert_path}/admin.pem -key ${indexer_cert_path}/admin-key.pem -h 127.0.0.1 ${debug}"
        if [  "${PIPESTATUS[0]}" != 0  ]; then
            common_logger -e "The Cyb3rhq indexer cluster security configuration could not be initialized."
            installCommon_rollBack
            exit 1
        else
            common_logger "Cyb3rhq indexer cluster security configuration initialized."
        fi
    fi

    if [ "${#indexer_node_names[@]}" -eq 1 ] && [ -z "${AIO}" ]; then
        installCommon_changePasswords
    fi

    common_logger "Cyb3rhq indexer cluster initialized."

}

function indexer_install() {

    common_logger "Starting Cyb3rhq indexer installation."

    if [ "${sys_type}" == "yum" ]; then
        installCommon_yumInstall "cyb3rhq-indexer" "${cyb3rhq_version}-*"
    elif [ "${sys_type}" == "apt-get" ]; then
        installCommon_aptInstall "cyb3rhq-indexer" "${cyb3rhq_version}-*"
    fi

    common_checkInstalled
    if [  "$install_result" != 0  ] || [ -z "${indexer_installed}" ]; then
        common_logger -e "Cyb3rhq indexer installation failed."
        installCommon_rollBack
        exit 1
    else
        common_logger "Cyb3rhq indexer installation finished."
    fi

    eval "sysctl -q -w vm.max_map_count=262144 ${debug}"

}

function indexer_startCluster() {

    common_logger -d "Starting Cyb3rhq indexer cluster."
    for ip_to_test in "${indexer_node_ips[@]}"; do
        eval "common_curl -XGET https://"${ip_to_test}":9200/ -k -s -o /dev/null"
        e_code="${PIPESTATUS[0]}"

        if [ "${e_code}" -eq "7" ]; then
            common_logger -e "Connectivity check failed on node ${ip_to_test} port 9200. Possible causes: Cyb3rhq indexer not installed on the node, the Cyb3rhq indexer service is not running or you have connectivity issues with that node. Please check this before trying again."
            exit 1
        fi
    done

    eval "cyb3rhq_indexer_ip=( $(cat /etc/cyb3rhq-indexer/opensearch.yml | grep network.host | sed 's/network.host:\s//') )"
    eval "sudo -u cyb3rhq-indexer JAVA_HOME=/usr/share/cyb3rhq-indexer/jdk/ OPENSEARCH_CONF_DIR=/etc/cyb3rhq-indexer /usr/share/cyb3rhq-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /etc/cyb3rhq-indexer/opensearch-security -icl -p 9200 -nhnv -cacert /etc/cyb3rhq-indexer/certs/root-ca.pem -cert /etc/cyb3rhq-indexer/certs/admin.pem -key /etc/cyb3rhq-indexer/certs/admin-key.pem -h ${cyb3rhq_indexer_ip} ${debug}"
    if [  "${PIPESTATUS[0]}" != 0  ]; then
        common_logger -e "The Cyb3rhq indexer cluster security configuration could not be initialized."
        installCommon_rollBack
        exit 1
    else
        common_logger "Cyb3rhq indexer cluster security configuration initialized."
    fi

    # Validate Cyb3rhq indexer security admin it is initialized
    indexer_security_admin_comm="common_curl -XGET https://"${indexer_node_ips[pos]}":9200/ -uadmin:admin -k --max-time 120 --silent -w \"%{http_code}\" --output /dev/null"
    http_status=$(eval "${indexer_security_admin_comm}")
    retries=0
    max_retries=5
    while [ "${http_status}" -ne 200 ]; do
        common_logger -d "Waiting for Cyb3rhq indexer to be ready. cyb3rhq-indexer status: ${http_status}"
        sleep 5
        retries=$((retries+1))
        if [ "${retries}" -eq "${max_retries}" ]; then
            common_logger -e "The Cyb3rhq indexer cluster security configuration could not be initialized."
            exit 1
        fi
        http_status=$(eval "${indexer_security_admin_comm}")
    done

    # Cyb3rhq alerts template injection
    if [ -n "${offline_install}" ]; then
        filebeat_cyb3rhq_template="file://${offline_files_path}/cyb3rhq-template.json"
    fi
    http_status=$(eval "common_curl --silent '${filebeat_cyb3rhq_template}' --max-time 300 --retry 5 --retry-delay 5" | eval "common_curl -X PUT 'https://${indexer_node_ips[pos]}:9200/_template/cyb3rhq' -H \'Content-Type: application/json\' -d @- -uadmin:admin -k --max-time 300 --silent --retry 5 --retry-delay 5 -w "%{http_code}" -o /dev/null")
    if [ "${http_status}" -ne 200 ]; then
        common_logger -e "The cyb3rhq-alerts template could not be inserted into the Cyb3rhq indexer cluster."
        exit 1
    else
        common_logger -d "Inserted cyb3rhq-alerts template into the Cyb3rhq indexer cluster."
    fi
}
