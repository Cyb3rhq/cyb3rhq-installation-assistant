# Certificate tool - Variables
# Copyright (C) 2015, Cyb3rhq Inc.
#
# This program is a free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License (version 2) as published by the FSF - Free Software
# Foundation.

readonly base_path="$(dirname "$(readlink -f "$0")")"
readonly config_file="${base_path}/config.yml"
readonly logfile="${base_path}/cyb3rhq-certificates-tool.log"
cert_tmp_path="/tmp/cyb3rhq-certificates"
debug=">> ${logfile} 2>&1"
readonly cert_tool_script_name=".*certs.*\.sh"