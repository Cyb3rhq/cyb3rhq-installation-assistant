# Cyb3rhq installation assistant

[![Slack](https://img.shields.io/badge/slack-join-blue.svg)](https://wazuh.com/community/join-us-on-slack/)
[![Email](https://img.shields.io/badge/email-join-blue.svg)](https://groups.google.com/forum/#!forum/cyb3rhq)
[![Documentation](https://img.shields.io/badge/docs-view-green.svg)](https://documentation.wazuh.com)
[![Documentation](https://img.shields.io/badge/web-view-green.svg)](https://wazuh.com)
[![Twitter](https://img.shields.io/twitter/follow/cyb3rhq?style=social)](https://twitter.com/cyb3rhq)
[![YouTube](https://img.shields.io/youtube/views/peTSzcAueEc?style=social)](https://www.youtube.com/watch?v=peTSzcAueEc)

## Table of Contents
1. [Overview](#overview)
2. [Tools](#tools)
3. [User Guide](#user-guide)
4. [Use Cases](#use-cases)
5. [Options Table](#options-table)
6. [Contribute](#contribute)
7. [Development Guide](#development-guide)
7. [More Information](#more-information)
9. [Authors](#authors)

## Overview

The Cyb3rhq installation Assistant is a tool designed to simplify the deployment of Cyb3rhq. It guides users through the process of installing Cyb3rhq components. Key features include:

- **Guided Installation**: Step-by-step instructions for easy setup.
- **Component Selection**: Install only the Cyb3rhq components you need.
- **System Requirements Check**: Automatically checks if your system meets the necessary requirements.
- **Automated Configuration**: Reduces errors by automating most of the setup.
- **Multi-Platform Support**: Compatible with various Linux distributions like Ubuntu, CentOS, and Debian.

## Tools

The Cyb3rhq installation assistant uses the following tools to enhance security during the installation process:

- **Cyb3rhq password tool**: Securely generate and manage passwords. [Learn more](https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html).
- **Cyb3rhq cert tool**: Manage SSL/TLS certificates for secure communications. [Learn more](https://documentation.wazuh.com/current/user-manual/cyb3rhq-dashboard/certificates.html).



## User Guide

### Downloads
- [Download the Cyb3rhq installation assistant.](https://packages.wazuh.com/4.10/cyb3rhq-install.sh)
- [Download the Cyb3rhq password tool.](https://packages.wazuh.com/4.10/cyb3rhq-passwords-tool.sh)
- [Download the Cyb3rhq cert tool.](https://packages.wazuh.com/4.10/cyb3rhq-certs-tool.sh)

### Build the scripts
As an alternative to downloading, use the `builder.sh` script to build the Cyb3rhq installation assistant and tools:


1. Build the Cyb3rhq installation assistant - `cyb3rhq-install.sh`:
   ```bash
   bash builder.sh -i
   ```

2. Build the Cyb3rhq password tool - `cyb3rhq-passwords-tool.sh`:
   ```bash
   bash builder.sh -p
   ```

3. Build the Cyb3rhq cert tool - `cyb3rhq-certs-tool.sh`:
   ```bash
   bash builder.sh -c
   ```

## Use Cases

Start by downloading the [configuration file](https://packages.wazuh.com/4.10/config.yml) and replace the node names and IP values with the corresponding ones.

> [!NOTE]
> It is not necessary to download the Cyb3rhq password tool and the Cyb3rhq cert tool to use the Cyb3rhq installation assistant. The Cyb3rhq installation assistant has embedded the previous tools.

### Common commands

1. Generate the passwords and certificates. Needs the [configuration file](https://packages.wazuh.com/4.10/config.yml).
   ```bash
   bash cyb3rhq-install.sh -g
   ```
2. Install all central components on the local machine:
   ```bash
   bash cyb3rhq-install.sh -a
   ```

3. Uninstall all central components:
   ```bash
   bash cyb3rhq-install.sh -u
   ```

4. Install the Cyb3rhq indexer specifying the same name as specified in the configuration file:
   ```bash
   bash cyb3rhq-install.sh --cyb3rhq-indexer <NODE_NAME>
   ```

5. Initialize the Cyb3rhq indexer cluster:
   ```bash
   bash cyb3rhq-install.sh --start-cluster
   ```

6. Install the Cyb3rhq server specifying the same name as specified in the configuration file:
   ```bash
   bash cyb3rhq-install.sh --cyb3rhq-server <NODE_NAME>
   ```

7. Install the Cyb3rhq dashboard specifying the same name as specified in the configuration file:
   ```bash
   bash cyb3rhq-install.sh --cyb3rhq-dashboard <NODE_NAME>
   ```

8. Display all options and help:
   ```bash
   bash cyb3rhq-install.sh -h
   ```

## Options Table

All the options for the Cyb3rhq installation assistant are listed in the following table:
| Option | Description |
|---------------------------------------|----------------------------------------|
| `-a`, `--all-in-one`                  | Install and configure Cyb3rhq server, Cyb3rhq indexer, Cyb3rhq dashboard.  |
| `-c`, `--config-file <path-to-config-yml>` | Path to the configuration file used to generate `cyb3rhq-install-files.tar` file containing the files needed for installation. By default, the Cyb3rhq installation assistant will search for a file named `config.yml` in the same path as the script.  |
| `-dw`, `--download-cyb3rhq <deb,rpm>`   | Download all the packages necessary for offline installation. Specify the type of packages to download for offline installation (`rpm`, `deb`).  |
| `-fd`, `--force-install-dashboard`    | Force Cyb3rhq dashboard installation to continue even when it is not capable of connecting to the Cyb3rhq indexer.  |
| `-g`, `--generate-config-files`       | Generate `cyb3rhq-install-files.tar` file containing the files needed for installation from `config.yml`. In distributed deployments, you will need to copy this file to all hosts.  |
| `-h`, `--help`                        | Display this help and exit.  |
| `-i`, `--ignore-check`                | Ignore the check for minimum hardware requirements.  |
| `-o`, `--overwrite`                   | Overwrite previously installed components. This will erase all the existing configuration and data.  |
| `-of`, `--offline-installation`       | Perform an offline installation. This option must be used with `-a`, `-ws`, `-s`, `-wi`, or `-wd`.  |
| `-p`, `--port`                        | Specify the Cyb3rhq web user interface port. Default is the `443` TCP port. Recommended ports are: `8443`, `8444`, `8080`, `8888`, `9000`.  |
| `-s`, `--start-cluster`               | Initialize Cyb3rhq indexer cluster security settings.  |
| `-t`, `--tar <path-to-certs-tar>`     | Path to tar file containing certificate files. By default, the Cyb3rhq installation assistant will search for a file named `cyb3rhq-install-files.tar` in the same path as the script.  |
| `-u`, `--uninstall`                   | Uninstall all Cyb3rhq components. This will erase all the existing configuration and data.  |
| `-v`, `--verbose`                     | Show the complete installation output.  |
| `-V`, `--version`                     | Show the version of the script and Cyb3rhq packages.  |
| `-wd`, `--cyb3rhq-dashboard <dashboard-node-name>`  | Install and configure Cyb3rhq dashboard, used for distributed deployments.  |
| `-wi`, `--cyb3rhq-indexer <indexer-node-name>`      | Install and configure Cyb3rhq indexer, used for distributed deployments.  |
| `-ws`, `--cyb3rhq-server <server-node-name>`        | Install and configure Cyb3rhq manager and Filebeat, used for distributed deployments.  |


## Contribute

If you want to contribute to our repository, please fork our GitHub repository and submit a pull request. Alternatively, you can share ideas through [our users' mailing list](https://groups.google.com/d/forum/cyb3rhq).

## Development Guide

To ensure consistency in development, please follow these guidelines:

- Write functions with a single objective and limited arguments.
- Use libraries selectively (e.g., `install_functions`).
- Main functions should not depend on specific implementations.
- Use descriptive names for variables and functions.
- Use `${var}` instead of `$(var)` and `$(command)` instead of backticks.
- Always quote variables: `"${var}"`.
- Use the `common_logger` function instead of `echo`.
- Check command results with `$?` or `PIPESTATUS`.
- Use timeouts for long commands.
- Ensure all necessary resources are available both online and offline.
- Check command existence with `command -v`.
- Parametrize all package versions.
- Use `| grep -q` instead of `| grep`.
- Use standard `$((..))` instead of old `$[]`.

> [!TIP]
> *Additional check*: Run unit [tests](/tests/unit/README) before preparing a pull request.

Some useful links and acknowledgment:
- [Bash meets solid](https://codewizardly.com/bash-meets-solid/)
- [Shellcheck](https://github.com/koalaman/shellcheck#gallery-of-bad-code)

## More Information

For more detailed instructions and advanced use cases, please refer to the [Cyb3rhq Quickstart Guide](https://documentation.wazuh.com/current/quickstart.html).


## Authors

Cyb3rhq Copyright (C) 2015-2023 Cyb3rhq Inc. (License GPLv2)