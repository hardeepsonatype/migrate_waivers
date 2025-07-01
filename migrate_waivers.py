import requests
import argparse
import logging
import sys
import json
import re
from requests.auth import HTTPBasicAuth
from typing import Union, Dict, Any, Tuple

# --- Configuration ---
# Set up logging to provide feedback on the script's progress
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Helper Functions ---

def make_comp_key(component_identifier: dict) -> tuple:
    """Creates a stable, hashable tuple from a component identifier dictionary."""
    if not component_identifier or 'coordinates' not in component_identifier:
        return tuple()
    coords = component_identifier.get('coordinates', {})
    # Create a stable tuple of coordinate items that are actually present
    stable_coords = {
        'artifactId': coords.get('artifactId'),
        'classifier': coords.get('classifier', ''),
        'extension': coords.get('extension'),
        'groupId': coords.get('groupId'),
        'version': coords.get('version')
    }
    coords_tuple = tuple(sorted(stable_coords.items()))
    return (
        ('format', component_identifier.get('format')),
        ('coordinates', coords_tuple)
    )

def extract_vuln_id_from_reason(reason: str) -> Union[str, None]:
    """Extracts a CVE or Sonatype ID from a policy violation condition reason string."""
    if not reason:
        return None
    cve_match = re.search(r'(CVE-\d{4}-\d{4,})', reason)
    if cve_match:
        return cve_match.group(1)
    sonatype_match = re.search(r'(sonatype-\d{4}-\d{4,})', reason)
    if sonatype_match:
        return sonatype_match.group(1)
    return None

def get_all_applications(iq_url: str, auth: HTTPBasicAuth) -> list:
    """Fetches all applications and returns the full list of application objects."""
    api_path = "/api/v2/applications"
    try:
        response = requests.get(f"{iq_url}{api_path}", auth=auth)
        response.raise_for_status()
        apps = response.json().get('applications', [])
        logging.info(f"Successfully fetched {len(apps)} applications.")
        return apps
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch applications: {e}")
        return []

def get_all_organizations(iq_url: str, auth: HTTPBasicAuth) -> dict:
    """Fetches all organizations and returns a map of {name: internalId}."""
    api_path = "/api/v2/organizations"
    try:
        response = requests.get(f"{iq_url}{api_path}", auth=auth)
        response.raise_for_status()
        orgs = response.json().get('organizations', [])
        logging.info(f"Successfully fetched {len(orgs)} organizations.")
        return {org['name']: org['id'] for org in orgs}
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch organizations: {e}")
        return {}

def get_all_violations(iq_url: str, auth: HTTPBasicAuth, applications: list) -> Dict[Tuple, str]:
    """
    Fetches all policy violations by iterating through every report for every application.
    The map key is a tuple: (app_public_id, component_key, vulnerability_id)
    """
    violation_map = {}
    logging.info("Starting to fetch all policy violations from the new server by checking ALL scans. This may take a moment...")

    for app in applications:
        app_public_id = app.get('publicId')
        app_internal_id = app.get('id')
        if not all([app_public_id, app_internal_id]):
            continue
        try:
            reports_path = f"/api/v2/reports/applications/{app_internal_id}"
            reports_response = requests.get(f"{iq_url}{reports_path}", auth=auth)
            if reports_response.status_code == 404: continue
            reports_response.raise_for_status()
            reports = reports_response.json()

            if not reports:
                logging.warning(f"No reports found for application '{app_public_id}'.")
                continue

            for report in reports:
                report_html_url = report.get('reportHtmlUrl')
                if not report_html_url: continue
                
                try:
                    report_id = report_html_url.split('/')[-1]
                except IndexError:
                    continue

                policy_violations_path = f"/api/v2/applications/{app_public_id}/reports/{report_id}/policy"
                violations_response = requests.get(f"{iq_url}{policy_violations_path}", auth=auth)
                
                if violations_response.status_code != 200:
                    continue

                policy_report_data = violations_response.json()
                
                for component in policy_report_data.get('components', []):
                    comp_id = component.get('componentIdentifier')
                    if not comp_id: continue

                    if comp_id.get('format') == 'maven' and 'classifier' not in comp_id.get('coordinates', {}):
                        comp_id['coordinates']['classifier'] = ''
                    
                    comp_key = make_comp_key(comp_id)
                    if not comp_key: continue

                    for policy_violation in component.get('violations', []):
                        violation_id = policy_violation.get('policyViolationId')
                        for constraint in policy_violation.get('constraints', []):
                            for condition in constraint.get('conditions', []):
                                reason = condition.get('conditionReason')
                                vuln_id = extract_vuln_id_from_reason(reason)
                                if vuln_id:
                                    key = (app_public_id, comp_key, vuln_id)
                                    violation_map[key] = violation_id

        except requests.exceptions.RequestException as e:
            logging.warning(f"Could not process reports for application '{app_public_id}': {e}")
            if e.response: logging.error(f"Response Body: {e.response.text}")
    
    logging.info(f"Finished fetching violations. Found {len(violation_map)} total violations to map against.")
    return violation_map

def create_waiver(iq_url: str, auth: HTTPBasicAuth, owner_type: str, owner_id: str, violation_id: str, source_waiver: dict) -> bool:
    """
    Creates a waiver for a specific, existing policy violation, using data from the source waiver.
    """
    api_path = f"/api/v2/policyWaivers/{owner_type}/{owner_id}/{violation_id}"
    
    waiver_payload = {
        "comment": source_waiver.get("comment", "Waiver migrated from previous IQ Server."),
        "matcherStrategy": source_waiver.get("matcherStrategy", "EXACT_COMPONENT")
    }
    
    logging.info(f"Attempting to create waiver at endpoint: {iq_url}{api_path}")
    logging.info("Using payload:")
    logging.info(json.dumps(waiver_payload, indent=4))

    try:
        response = requests.post(f"{iq_url}{api_path}", auth=auth, json=waiver_payload)
        response.raise_for_status()
        
        if response.status_code in [200, 204]:
            logging.info(f"Successfully created waiver for violation ID: {violation_id}")
            return True
        else:
            logging.warning(f"Received unexpected status code {response.status_code} for violation ID {violation_id}.")
            return False
            
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to create waiver for violation ID {violation_id}. Error: {e}")
        if e.response:
            logging.error(f"Response body: {e.response.text}")
        return False

# --- Main Logic ---

def migrate_waivers(waivers_path: str, iq_url: str, auth: HTTPBasicAuth):
    """
    Main function to process a JSON file of waivers and recreate them on a new server.
    """
    logging.info("--- Starting Waiver Migration Process ---")
    
    applications = get_all_applications(iq_url, auth)
    app_map = {app['publicId']: app for app in applications} # Map publicId to full app object
    org_map = get_all_organizations(iq_url, auth)
    violation_map = get_all_violations(iq_url, auth, applications)

    if not violation_map:
        logging.warning("No applicable policy violations found on the new server. Cannot migrate any waivers.")

    success_count = 0
    failure_count = 0
    skipped_count = 0
    
    try:
        with open(waivers_path, 'r', encoding='utf-8-sig') as f:
            source_waivers = json.load(f)
        
        logging.info(f"Loaded {len(source_waivers)} waivers to migrate from '{waivers_path}'.")

        for i, waiver in enumerate(source_waivers):
            row_num = i + 1
            
            scope_name = waiver.get('scopeOwnerName')
            owner_type = waiver.get('scopeOwnerType')
            comp_identifier = waiver.get('componentIdentifier')
            vuln_id = waiver.get('vulnerabilityId')

            if not all([scope_name, owner_type, comp_identifier, vuln_id]):
                failure_count += 1
                continue

            if comp_identifier.get('format') == 'maven' and 'classifier' not in comp_identifier.get('coordinates', {}):
                comp_identifier['coordinates']['classifier'] = ''
            
            comp_key = make_comp_key(comp_identifier)
            
            violation_id_to_waive = None
            api_owner_type = None
            api_owner_id = None

            if owner_type == 'application':
                lookup_key = (scope_name, comp_key, vuln_id)
                violation_id_to_waive = violation_map.get(lookup_key)
                if violation_id_to_waive:
                    api_owner_type = 'application'
                    api_owner_id = scope_name
            
            elif owner_type == 'organization':
                logging.info(f"Row {row_num}: This is an Organization waiver for '{scope_name}'. Searching for a match in any of its applications...")
                org_internal_id = org_map.get(scope_name)
                if not org_internal_id:
                    logging.error(f"Row {row_num}: Could not find organization '{scope_name}' on the new server.")
                    skipped_count += 1
                    continue
                
                apps_in_org = [app['publicId'] for app in applications if app.get('organizationId') == org_internal_id]
                for app_in_org in apps_in_org:
                    lookup_key = (app_in_org, comp_key, vuln_id)
                    violation_id_to_waive = violation_map.get(lookup_key)
                    if violation_id_to_waive:
                        api_owner_type = 'organization'
                        api_owner_id = org_internal_id
                        logging.info(f"  --> Found a match in application '{app_in_org}' with violation ID '{violation_id_to_waive}'. Will waive at Organization level.")
                        break

            elif owner_type == 'root_organization':
                logging.info(f"Row {row_num}: This is a Root Organization waiver. Searching for a match in any application...")
                for (dest_app_id, dest_comp_key, dest_vuln_id), dest_violation_id in violation_map.items():
                    if comp_key == dest_comp_key and vuln_id == dest_vuln_id:
                        violation_id_to_waive = dest_violation_id
                        api_owner_type = 'organization'
                        api_owner_id = 'ROOT_ORGANIZATION_ID'
                        logging.info(f"  --> Found a match in application '{dest_app_id}' with violation ID '{violation_id_to_waive}'. Will waive at Root Organization level.")
                        break 
            
            if not violation_id_to_waive:
                logging.warning(f"Row {row_num}: --> No matching violation found in map for waiver on {scope_name}. Skipping.")
                skipped_count += 1
                continue
            
            if not api_owner_id:
                logging.error(f"Row {row_num}: Could not determine API owner ID for scope '{scope_name}'. Skipping.")
                failure_count += 1
                continue

            if create_waiver(iq_url, auth, api_owner_type, api_owner_id, violation_id_to_waive, waiver):
                success_count += 1
            else:
                failure_count += 1

    except FileNotFoundError:
        logging.critical(f"The file '{waivers_path}' was not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        logging.critical(f"The file '{waivers_path}' is not a valid JSON file.")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"An unexpected error occurred: {e}", exc_info=True)
        sys.exit(1)

    logging.info("--- Waiver Migration Process Finished ---")
    logging.info(f"Successfully created: {success_count}")
    logging.info(f"Failed to create:   {failure_count}")
    logging.info(f"Skipped:              {skipped_count}")


# --- Script Execution ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate Sonatype IQ policy waivers from a JSON export to a new IQ Server instance.")
    parser.add_argument("--waivers-file", required=True, help="Path to the source waivers JSON file (e.g., instance1_waivers.json).")
    parser.add_argument("-u", "--url", required=True, help="Base URL of the new Sonatype IQ Server (e.g., http://iq-server:8070).")
    parser.add_argument("-a", "--user", required=True, help="Username for authentication with the IQ Server.")
    parser.add_argument("-p", "--password", required=True, help="Password for authentication with the IQ Server.")
    
    args = parser.parse_args()
    iq_auth = HTTPBasicAuth(args.user, args.password)
    migrate_waivers(args.waivers_file, args.url, iq_auth)
