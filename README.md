# Sonatype IQ Waiver Extraction and Migration Scripts

This repository contains a pair of Python scripts to perform a two-step migration of policy waivers from a source Sonatype IQ Server to a new destination instance. The process involves first extracting all waivers from the source server into a JSON file, and then using that file to recreate the waivers on the destination server.

## NOTE: THESE SCRIPTS WILL MIGRATE LIFECYCLE WAIVERS ONLY - NOT REPOSITORY (FIREWALL) WAIVERS
## PLEASE TEST THOROUGHLY BEFORE APPLYING TO PRODUCTION - USE OF THESE SCRIPTS IS NOT SUPPORTED BY SONATYPE

## Overview

Migrating Sonatype IQ instances requires a manual process for transferring existing policy waivers. These scripts automate that workflow:

1.  **`get_waivers.py`**: Connects to your **source** IQ Server and fetches every policy waiver at the Root Organization, Organization, and Application levels. It compiles them into a single `all_policy_waivers.json` file.
2.  **`migrate_waivers.py`**: Reads the `all_policy_waivers.json` file and connects to your **destination** IQ Server. It intelligently maps the old waivers to new policy violations based on component and vulnerability data, and then creates the waivers on the new instance.

---

## Prerequisites

Before running the scripts, ensure you have the following:

* **Python 3.6+**
* **The `requests` library:** If not installed, you can add it via pip:
    ```shell
    pip install requests
    ```
* **Network access** to both your source and destination Sonatype IQ Server APIs.
* **User credentials** for both IQ Servers with appropriate permissions:
    * **Source Server User**: Permissions to read all organizations, applications, and policy waivers.
    * **Destination Server User**: Permissions to read applications/organizations and create policy waivers.

---

## Migration Process

The migration is a two-step process. You must run `get_waivers.py` first to generate the necessary data file for `migrate_waivers.py`.

### Step 1: Extract Waivers from Source IQ Server

This script connects to your source instance and exports all waivers.

**Script:** `get_waivers.py`

#### **Usage**

Run the script from your terminal, providing the URL and credentials for your **source** IQ Server.

```shell
python get_waivers.py --url <SOURCE_IQ_URL> --user <SOURCE_USERNAME> --password <SOURCE_PASSWORD>
```

* `--url`: The base URL of your **source** Sonatype IQ Server (e.g., `http://iq-source.example.com:8070`).
* `--user`: The username for authentication with the source server.
* `--password`: The password for the specified user.

This will create a file named **`all_policy_waivers.json`** in the same directory. This file is required for the next step.

#### **Example**

```shell
python get_waivers.py \
    --url "http://iq-prod-instance:8070" \
    --user "service-account" \
    --password "secret_password_1"
```

---

### Step 2: Migrate Waivers to Destination IQ Server

This script uses the `all_policy_waivers.json` file to apply the waivers to your new destination instance.

**Script:** `migrate_waivers.py`

#### **How it Works**

The script intelligently recreates waivers by:

1.  Fetching all applications, organizations, and current policy violations from the new destination server.
2.  Reading each waiver from the `all_policy_waivers.json` file.
3.  Matching the component, vulnerability, and scope of the old waiver to an active violation on the new server.
4.  If a match is found, it creates a new waiver on the destination server with the original comment.

#### **Usage**

Run the script from your terminal, providing the path to the waivers file and the credentials for your **destination** IQ Server.

```shell
python migrate_waivers.py --waivers-file all_policy_waivers.json --url <DESTINATION_IQ_URL> --user <DESTINATION_USERNAME> --password <DESTINATION_PASSWORD>
```

* `--waivers-file`: The path to the JSON file created in Step 1 (e.g., `all_policy_waivers.json`).
* `--url`: The base URL of your **destination** Sonatype IQ Server (e.g., `http://iq-new.example.com:8070`).
* `--user`: The username for authentication with the destination server.
* `--password`: The password for the specified user.

#### **Example**

```shell
python migrate_waivers.py \
    --waivers-file "./all_policy_waivers.json" \
    --url "http://localhost:8070" \
    --user "admin" \
    --password "admin123"
```

Upon completion, the script will print a summary of successful, failed, and skipped waivers.
