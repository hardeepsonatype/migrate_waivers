import requests
import argparse
import logging
import sys
import json
import re
import csv
import os
from urllib.parse import urljoin
from requests.auth import HTTPBasicAuth
from typing import Union, Dict, Any, Tuple, Optional, List

# --- Helper Functions ---

def setup_logging(verbose: bool, log_file: Optional[str] = None):
    """
    Configures logging to console and optionally to a file.
    """
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    formatter = logging.Formatter(log_format)
    
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    if logger.hasHandlers():
        logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        try:
            file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
            file_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
            logging.info(f"Logging to file enabled. Output will be saved to: {log_file}")
        except IOError as e:
            logging.error(f"Could not open log file '{log_file}' for writing. Error: {e}")

def make_comp_key(component_identifier: dict) -> tuple:
    """Creates a stable, hashable tuple from a component identifier dictionary."""
    if not component_identifier or 'coordinates' not in component_identifier:
        return tuple()
    
    coords = component_identifier.get('coordinates', {})
    coords_tuple = tuple(sorted(coords.items()))
    
    return (
        ('format', component_identifier.get('format')),
        ('coordinates', coords_tuple)
    )

def extract_vuln_id_from_reason(reason: str) -> Optional[str]:
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

def load_waiver_details_from_csv(csv_path: str) -> Dict[str, str]:
    """
    Loads waiver details from the results-waivers.csv file.
    Returns a dictionary mapping policyWaiverId to policyName.
    """
    waiver_details = {}
    logging.info(f"Loading waiver details from '{csv_path}'...")
    try:
        with open(csv_path, mode='r', encoding='utf-8-sig') as infile:
            reader = csv.reader(infile)
            
            header_row = next(reader)
            cleaned_header = [h.strip() for h in header_row]
            logging.debug(f"Cleaned CSV Header: {cleaned_header}")
            
            try:
                waiver_id_idx = cleaned_header.index('Waiver Id')
                policy_name_idx = cleaned_header.index('Policy Name')
            except ValueError as e:
                logging.critical(f"CSV file is missing required columns 'Waiver Id' or 'Policy Name'. Error: {e}")
                sys.exit(1)

            for row in reader:
                if len(row) > max(waiver_id_idx, policy_name_idx):
                    policy_waiver_id = row[waiver_id_idx]
                    policy_name = row[policy_name_idx]
                    if policy_waiver_id and policy_name:
                        waiver_details[policy_waiver_id] = policy_name
        logging.info(f"Successfully loaded details for {len(waiver_details)} waivers from CSV.")
        return waiver_details
    except FileNotFoundError:
        logging.critical(f"Error: The waiver details CSV file '{csv_path}' was not found.")
        sys.exit(1)
    except Exception as e:
        logging.critical(f"An unexpected error occurred while reading the CSV file: {e}", exc_info=True)
        sys.exit(1)

def get_all_descendant_org_ids(start_org_id: str, all_orgs_by_id: Dict[str, Any]) -> List[str]:
    """
    Recursively finds all descendant organization IDs for a given starting organization.
    """
    descendant_ids = {start_org_id}
    children_to_process = [start_org_id]

    while children_to_process:
        current_org_id = children_to_process.pop(0)
        for org_id, org_data in all_orgs_by_id.items():
            if org_data.get('parentOrganizationId') == current_org_id:
                if org_id not in descendant_ids:
                    descendant_ids.add(org_id)
                    children_to_process.append(org_id)
    return list(descendant_ids)

# --- Caching Functions ---
def save_to_cache(data: Any, path: str):
    """Saves data to a JSON file, handling tuple keys for dictionaries."""
    logging.info(f"Saving data to cache file: {path}")
    try:
        with open(path, 'w', encoding='utf-8') as f:
            if isinstance(data, dict) and any(isinstance(k, tuple) for k in data.keys()):
                string_keyed_data = {str(k): v for k, v in data.items()}
                json.dump(string_keyed_data, f, indent=4)
            else:
                json.dump(data, f, indent=4)
    except IOError as e:
        logging.error(f"Could not write to cache file {path}. Error: {e}")

def load_from_cache(path: str, is_violations_map: bool = False) -> Any:
    """Loads data from a JSON file, handling string keys back to tuples."""
    logging.info(f"Loading data from cache file: {path}")
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if is_violations_map:
                # Using eval is generally unsafe, but acceptable here as we control the input format.
                # A safer alternative would be a more robust serialization/deserialization method.
                return {eval(k): v for k, v in data.items()}
            return data
    except (IOError, json.JSONDecodeError) as e:
        logging.error(f"Could not read or parse cache file {path}. Error: {e}")
        return None

# --- API Fetching Functions ---
def get_all_applications(iq_url: str, auth: HTTPBasicAuth) -> list:
    """Fetches all applications and returns the full list of application objects."""
    api_path = "/api/v2/applications"
    full_url = urljoin(iq_url, api_path)
    logging.debug(f"Fetching all applications from {full_url}")
    try:
        response = requests.get(full_url, auth=auth)
        response.raise_for_status()
        apps = response.json().get('applications', [])
        logging.info(f"Successfully fetched {len(apps)} applications.")
        return apps
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch applications: {e}")
        return []

def get_all_organizations(iq_url: str, auth: HTTPBasicAuth) -> Tuple[Dict[str, Any], Dict[str, str]]:
    """Fetches all organizations and returns two maps: {id: org_object} and {name: id}."""
    api_path = "/api/v2/organizations"
    full_url = urljoin(iq_url, api_path)
    logging.debug(f"Fetching all organizations from {full_url}")
    try:
        response = requests.get(full_url, auth=auth)
        response.raise_for_status()
        orgs = response.json().get('organizations', [])
        logging.info(f"Successfully fetched {len(orgs)} organizations.")
        orgs_by_id = {org['id']: org for org in orgs}
        org_name_to_id_map = {org['name']: org['id'] for org in orgs}
        return orgs_by_id, org_name_to_id_map
    except requests.exceptions.RequestException as e:
        logging.error(f"Failed to fetch organizations: {e}")
        return {}, {}

def get_all_violations(iq_url: str, auth: HTTPBasicAuth, applications: list) -> Dict[Tuple, str]:
    """
    Fetches all policy violations by iterating through every report for every application.
    The map key is a tuple that includes the policy name to differentiate violations of the same CVE.
    """
    violation_map = {}
    total_apps = len(applications)
    logging.info(f"Starting to fetch all policy violations for {total_apps} applications. This may take a moment...")

    for i, app in enumerate(applications):
        if (i > 0) and (i + 1) % 10 == 0:
            logging.info(f"  ...processed {i + 1} of {total_apps} applications.")

        app_public_id = app.get('publicId')
        app_internal_id = app.get('id')
        if not all([app_public_id, app_internal_id]):
            continue
        
        logging.debug(f"Checking reports for application: {app.get('name')} ({app_public_id})")
        try:
            reports_path = f"/api/v2/reports/applications/{app_internal_id}"
            reports_response = requests.get(urljoin(iq_url, reports_path), auth=auth)
            if reports_response.status_code == 404:
                logging.debug(f"No reports endpoint found for application '{app_public_id}', skipping.")
                continue
            reports_response.raise_for_status()
            reports = reports_response.json()

            if not reports:
                logging.debug(f"No reports found for application '{app_public_id}'.")
                continue

            for report in reports:
                report_html_url = report.get('reportHtmlUrl')
                if not report_html_url: continue
                
                try:
                    report_id = report_html_url.split('/')[-1]
                except IndexError:
                    continue

                policy_violations_path = f"/api/v2/applications/{app_public_id}/reports/{report_id}/policy"
                violations_response = requests.get(urljoin(iq_url, policy_violations_path), auth=auth)
                
                if violations_response.status_code != 200:
                    continue

                policy_report_data = violations_response.json()
                
                for component in policy_report_data.get('components', []):
                    comp_id = component.get('componentIdentifier')
                    if not comp_id: continue
                    
                    comp_key = make_comp_key(comp_id)
                    if not comp_key: continue

                    for policy_violation in component.get('violations', []):
                        violation_id = policy_violation.get('policyViolationId')
                        policy_name = policy_violation.get('policyName')

                        vuln_id = None
                        for constraint in policy_violation.get('constraints', []):
                            for condition in constraint.get('conditions', []):
                                reason = condition.get('conditionReason')
                                vuln_id = extract_vuln_id_from_reason(reason)
                                if vuln_id: break
                            if vuln_id: break
                        
                        if vuln_id and policy_name:
                            key = ('security', app_public_id, comp_key, policy_name, vuln_id)
                            violation_map[key] = violation_id
                            logging.debug(f"Mapped SECURITY violation: App='{app_public_id}', Policy='{policy_name}', Vuln='{vuln_id}', ViolationID='{violation_id}'")
                        elif policy_name:
                            key = ('policy', app_public_id, comp_key, policy_name)
                            violation_map[key] = violation_id
                            logging.debug(f"Mapped POLICY violation: App='{app_public_id}', Policy='{policy_name}', ViolationID='{violation_id}'")

        except requests.exceptions.RequestException as e:
            logging.warning(f"Could not process reports for application '{app_public_id}': {e}")
            if e.response: logging.error(f"Response Body: {e.response.text}")
    
    logging.info(f"Finished fetching violations. Found {len(violation_map)} total violations to map against.")
    return violation_map

def create_waiver(iq_url: str, auth: HTTPBasicAuth, owner_type: str, owner_id: str, violation_id: str, source_waiver: dict) -> bool:
    """
    Creates a waiver for a specific, existing policy violation.
    """
    api_path = f"/api/v2/policyWaivers/{owner_type}/{owner_id}/{violation_id}"
    full_url = urljoin(iq_url, api_path)
    
    waiver_payload = {
        "matcherStrategy": source_waiver.get("matcherStrategy", "EXACT_COMPONENT")
    }

    creator_name = source_waiver.get("creatorName")
    source_comment = source_waiver.get("comment")
    
    final_comment_parts = []
    if creator_name and creator_name.strip():
        final_comment_parts.append(creator_name.strip())
    
    if source_comment and source_comment.strip():
        final_comment_parts.append(source_comment.strip())

    if final_comment_parts:
        waiver_payload["comment"] = " - ".join(final_comment_parts)
    else:
        waiver_payload["comment"] = "Waiver migrated from previous IQ Server."

    source_reason_id = source_waiver.get("policyWaiverReasonId")
    if source_reason_id:
        waiver_payload["waiverReasonId"] = source_reason_id

    expiry_time = source_waiver.get("expiryTime")
    if expiry_time:
        waiver_payload["expiryTime"] = expiry_time
    
    logging.info(f"Attempting to create waiver for violation '{violation_id}' at {owner_type} '{owner_id}'.")
    logging.debug(f"Waiver request endpoint: {full_url}")
    logging.debug(f"Waiver request payload: {json.dumps(waiver_payload, indent=2)}")

    try:
        response = requests.post(full_url, auth=auth, json=waiver_payload)
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

def migrate_waivers(waivers_path: str, iq_url: str, auth: HTTPBasicAuth, waiver_details_map: Dict[str, str], cache_dir: str, force_fetch: bool):
    """
    Main function to process a JSON file of waivers and recreate them on a new server.
    """
    logging.info("--- Starting Waiver Migration Process ---")

    # --- Caching and Data Loading ---
    apps_cache_path = os.path.join(cache_dir, 'applications.json')
    orgs_cache_path = os.path.join(cache_dir, 'organizations.json')
    violations_cache_path = os.path.join(cache_dir, 'violations.json')

    if not force_fetch and os.path.exists(apps_cache_path):
        applications = load_from_cache(apps_cache_path)
    else:
        applications = get_all_applications(iq_url, auth)
        save_to_cache(applications, apps_cache_path)

    app_name_to_public_id = {app['name']: app['publicId'] for app in applications}

    if not force_fetch and os.path.exists(orgs_cache_path):
        cached_org_data = load_from_cache(orgs_cache_path)
        all_orgs_by_id, org_name_to_id_map = cached_org_data[0], cached_org_data[1]
    else:
        all_orgs_by_id, org_name_to_id_map = get_all_organizations(iq_url, auth)
        save_to_cache([all_orgs_by_id, org_name_to_id_map], orgs_cache_path)

    if not force_fetch and os.path.exists(violations_cache_path):
        violation_map = load_from_cache(violations_cache_path, is_violations_map=True)
    else:
        violation_map = get_all_violations(iq_url, auth, applications)
        save_to_cache(violation_map, violations_cache_path)

    if not violation_map:
        logging.warning("No applicable policy violations found on the new server or in cache. Cannot migrate any waivers.")
        return

    success_count = 0
    failure_count = 0
    skipped_count = 0
    
    try:
        with open(waivers_path, 'r', encoding='utf-8-sig') as f:
            source_waivers = json.load(f)
        
        logging.info(f"Loaded {len(source_waivers)} waivers to migrate from '{waivers_path}'.")

        # --- Main Processing Loop ---
        for i, waiver in enumerate(source_waivers):
            row_num = i + 1
            logging.debug(f"--- Processing source waiver #{row_num} ---")
            
            # --- 1. Extract and Validate Waiver Data ---
            scope_name = waiver.get('scopeOwnerName')
            owner_type = waiver.get('scopeOwnerType')
            comp_identifier = waiver.get('componentIdentifier')
            vuln_id = waiver.get('vulnerabilityId')
            policy_waiver_id = waiver.get('policyWaiverId')
            matcher_strategy = waiver.get('matcherStrategy')

            if not all([scope_name, owner_type, policy_waiver_id, matcher_strategy]):
                logging.error(f"Row {row_num}: Skipping waiver due to missing essential data (scope, type, policyWaiverId, or matcherStrategy).")
                failure_count += 1
                continue
            
            # A component identifier is only required if the waiver is not for ALL_COMPONENTS
            if matcher_strategy != 'ALL_COMPONENTS' and not comp_identifier:
                logging.error(f"Row {row_num}: Skipping waiver as it is component-specific but is missing a component identifier.")
                failure_count += 1
                continue

            policy_name = waiver_details_map.get(policy_waiver_id)
            if not policy_name:
                logging.warning(f"Row {row_num}: Could not find policy name for waiver ID '{policy_waiver_id}' in the provided CSV. Skipping.")
                skipped_count += 1
                continue

            # --- 2. Determine Search Scope ---
            apps_in_scope = set()
            target_owner_id = None
            target_owner_type = None

            if owner_type == 'application':
                app_public_id = app_name_to_public_id.get(scope_name)
                if app_public_id:
                    apps_in_scope.add(app_public_id)
                    target_owner_id = app_public_id
                    target_owner_type = 'application'
                else:
                    logging.warning(f"Row {row_num}: Could not find application named '{scope_name}' on the new server. Skipping.")
                    skipped_count += 1
                    continue
            elif owner_type == 'organization':
                org_internal_id = org_name_to_id_map.get(scope_name)
                if org_internal_id:
                    all_relevant_org_ids = get_all_descendant_org_ids(org_internal_id, all_orgs_by_id)
                    apps_in_scope.update(app['publicId'] for app in applications if app.get('organizationId') in all_relevant_org_ids)
                    target_owner_id = org_internal_id
                    target_owner_type = 'organization'
                else:
                    logging.warning(f"Row {row_num}: Could not find organization '{scope_name}' on the new server. Skipping.")
                    skipped_count += 1
                    continue
            elif owner_type == 'root_organization':
                apps_in_scope.update(app['publicId'] for app in applications)
                target_owner_id = 'ROOT_ORGANIZATION_ID'
                target_owner_type = 'organization'

            # --- 3. Find a Matching Violation to Anchor the Waiver ---
            violation_id_to_waive = None
            comp_key_to_match = make_comp_key(comp_identifier)

            for v_key, v_id in violation_map.items():
                v_type, v_app_id, v_comp_key, v_policy_name, *v_rest = v_key
                
                if v_app_id not in apps_in_scope:
                    continue
                
                if v_policy_name != policy_name:
                    continue
                
                # For component-specific waivers, the component key must match
                if matcher_strategy != 'ALL_COMPONENTS' and v_comp_key != comp_key_to_match:
                    continue
                
                is_match = False
                if vuln_id and v_type == 'security' and v_rest:
                    if vuln_id == v_rest[0]:
                        is_match = True
                elif not vuln_id and v_type == 'policy':
                    is_match = True

                if is_match:
                    violation_id_to_waive = v_id
                    logging.info(f"  --> Row {row_num}: Found anchor violation '{v_id}' in app '{v_app_id}' for policy '{policy_name}'.")
                    break # Found a suitable anchor, no need to search further

            # --- 4. Create the Waiver ---
            if not violation_id_to_waive:
                waiver_type = f"vuln '{vuln_id}'" if vuln_id else "a policy violation"
                logging.warning(f"Row {row_num}: No matching violation found for waiver on '{scope_name}' with policy '{policy_name}' and {waiver_type}. Skipping.")
                skipped_count += 1
                continue
            
            if not target_owner_id:
                logging.error(f"Row {row_num}: Could not determine API owner ID for scope '{scope_name}'. This should not happen. Skipping.")
                failure_count += 1
                continue

            if create_waiver(iq_url, auth, target_owner_type, target_owner_id, violation_id_to_waive, waiver):
                success_count += 1
            else:
                failure_count += 1

    except FileNotFoundError:
        logging.critical(f"Error: The file '{waivers_path}' was not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        logging.critical(f"Error: The file '{waivers_path}' is not a valid JSON file.")
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
    parser = argparse.ArgumentParser(
        description="Migrate Sonatype IQ policy waivers from a JSON export to a new IQ Server instance.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--waivers-file", required=True, help="Path to the source waivers JSON file (e.g., all_policy_waivers.json).")
    parser.add_argument("--waiver-details-csv", required=True, help="Path to the CSV file containing waiver details (e.g., results-waivers.csv).")
    parser.add_argument("-u", "--url", required=True, help="Base URL of the new Sonatype IQ Server (e.g., http://iq-server:8070).")
    parser.add_argument("-a", "--user", required=True, help="Username for authentication with the IQ Server.")
    parser.add_argument("-p", "--password", required=True, help="Password for authentication with the IQ Server.")
    
    parser.add_argument(
        "--cache-dir",
        default=".waiver_cache",
        help="Directory to store cache files (default: ./.waiver_cache)."
    )
    parser.add_argument(
        "--force-fetch",
        action="store_true",
        help="Force fetching data from APIs, ignoring existing cache."
    )
    
    parser.add_argument(
        "--log-file",
        help="Optional. Path to a file to store all log output (e.g., migration.log).\n"
             "The file will be overwritten on each run."
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Optional. Enable verbose console output to show detailed debug messages."
    )

    args = parser.parse_args()

    setup_logging(args.verbose, args.log_file)
    
    if not os.path.exists(args.cache_dir):
        logging.info(f"Cache directory '{args.cache_dir}' not found. Creating it.")
        os.makedirs(args.cache_dir)
        
    waiver_details = load_waiver_details_from_csv(args.waiver_details_csv)
    
    iq_auth = HTTPBasicAuth(args.user, args.password)
    migrate_waivers(args.waivers_file, args.url, iq_auth, waiver_details, args.cache_dir, args.force_fetch)
