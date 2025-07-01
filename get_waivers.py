import requests
import json
import os
import getpass
import argparse

def get_all_organizations(session, base_url):
    """
    Fetches all organizations from the Sonatype IQ Server.
    
    Args:
        session (requests.Session): The authenticated session object.
        base_url (str): The base URL of the Sonatype IQ Server.
        
    Returns:
        list: A list of organization dictionaries, or an empty list if an error occurs.
    """
    print("Fetching all organizations...")
    api_url = f"{base_url}/api/v2/organizations"
    try:
        response = session.get(api_url)
        response.raise_for_status()  # Raises an HTTPError for bad responses (4xx or 5xx)
        organizations = response.json().get('organizations', [])
        print(f"Successfully found {len(organizations)} organizations.")
        return organizations
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred while fetching organizations: {http_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"A request error occurred: {req_err}")
    except json.JSONDecodeError:
        print("Failed to decode JSON response from server.")
    return []

def get_all_applications(session, base_url):
    """
    Fetches all applications from the Sonatype IQ Server.
    
    Args:
        session (requests.Session): The authenticated session object.
        base_url (str): The base URL of the Sonatype IQ Server.
        
    Returns:
        list: A list of application dictionaries, or an empty list if an error occurs.
    """
    print("\nFetching all applications...")
    api_url = f"{base_url}/api/v2/applications"
    try:
        response = session.get(api_url)
        response.raise_for_status()
        applications = response.json().get('applications', [])
        print(f"Successfully found {len(applications)} applications.")
        return applications
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred while fetching applications: {http_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"A request error occurred: {req_err}")
    except json.JSONDecodeError:
        print("Failed to decode JSON response from server.")
    return []

def get_policy_waivers(session, base_url, owner_type, owner_id):
    """
    Fetches policy waivers for a specific owner (application or organization).
    
    Args:
        session (requests.Session): The authenticated session object.
        base_url (str): The base URL of the Sonatype IQ Server.
        owner_type (str): The type of owner ('application' or 'organization').
        owner_id (str): The ID of the owner.
        
    Returns:
        list: A list of policy waiver dictionaries, or an empty list if none are found or an error occurs.
    """
    # Corrected URL path - removed the extra '/owner' segment.
    api_url = f"{base_url}/api/v2/policyWaivers/{owner_type}/{owner_id}"
    try:
        response = session.get(api_url)
        
        # A 404 Not Found is expected if no waivers exist for the owner.
        if response.status_code == 404:
            return []
        
        response.raise_for_status()
        return response.json()

    except requests.exceptions.HTTPError as http_err:
        print(f"    <-- HTTP error occurred fetching waivers for {owner_type} '{owner_id}': {http_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"    <-- A request error occurred: {req_err}")
    except json.JSONDecodeError:
        print(f"    <-- ERROR: Failed to decode JSON response for {owner_type} '{owner_id}'.")
    
    return []

def main():
    """
    Main function to orchestrate fetching all policy waivers and saving them to a file.
    Accepts command-line arguments for credentials and URL.
    """
    # --- Configuration via Command-Line Arguments ---
    parser = argparse.ArgumentParser(description="Fetch all policy waivers from a Sonatype IQ Server.")
    parser.add_argument("-u", "--url", required=True, help="The base URL of the Sonatype IQ Server (e.g., http://localhost:8070)")
    parser.add_argument("-a", "--user", required=True, help="Username for authentication.")
    parser.add_argument("-p", "--password", required=True, help="Password for authentication.")
    
    args = parser.parse_args()

    base_url = args.url.strip()
    username = args.user.strip()
    password = args.password
    
    # The special ID for the root organization in Sonatype IQ
    ROOT_ORGANIZATION_ID = "ROOT_ORGANIZATION_ID"
    
    output_filename = "all_policy_waivers.json"
    
    # --- Create an authenticated session ---
    session = requests.Session()
    session.auth = (username, password)
    
    all_waivers = []
    
    # --- Fetch Organization Waivers ---
    organizations = get_all_organizations(session, base_url)
    org_ids = [org['id'] for org in organizations]
    
    # Ensure the Root Organization is included for checking waivers
    if ROOT_ORGANIZATION_ID not in org_ids:
        org_ids.insert(0, ROOT_ORGANIZATION_ID)
        
    print(f"\nChecking waivers for {len(org_ids)} organizations (including Root)...")
    for org_id in org_ids:
        print(f"  - Checking organization ID: {org_id}")
        waivers = get_policy_waivers(session, base_url, "organization", org_id)
        if waivers:
            print(f"    > Found {len(waivers)} waiver(s).")
            all_waivers.extend(waivers)
            
    # --- Fetch Application Waivers ---
    applications = get_all_applications(session, base_url)
    
    if applications:
        print(f"\nChecking waivers for {len(applications)} applications...")
        for app in applications:
            app_public_id = app.get('publicId')
            app_name = app.get('name', 'N/A')
            if app_public_id:
                print(f"  - Checking application: '{app_name}' (ID: {app_public_id})")
                waivers = get_policy_waivers(session, base_url, "application", app_public_id)
                if waivers:
                    print(f"    > Found {len(waivers)} waiver(s).")
                    all_waivers.extend(waivers)
            else:
                print(f"  - Skipping application '{app_name}' due to missing publicId.")

    # --- Save results to JSON file ---
    print(f"\nTotal waivers collected: {len(all_waivers)}")
    try:
        with open(output_filename, 'w') as f:
            json.dump(all_waivers, f, indent=4)
        print(f"Successfully saved all waivers to '{output_filename}'")
    except IOError as e:
        print(f"Error writing to file '{output_filename}': {e}")

if __name__ == "__main__":
    main()
