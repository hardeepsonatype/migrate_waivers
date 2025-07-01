# Sonatype IQ Waiver Extraction and Migration Scripts

This repository contains a pair of Python scripts to perform a two-step migration of policy waivers from a source Sonatype IQ Server to a new destination instance. The process involves first extracting all waivers from the source server into a JSON file, and then using that file to recreate the waivers on the destination server.

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
