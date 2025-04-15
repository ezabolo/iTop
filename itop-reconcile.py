import requests
import json
from requests.packages.urllib3.contrib.socks import SOCKSProxyManager
import os
import subprocess
import csv
import sys
import time
import zipfile

ITOP_URL = 'url'
ITOP_USER = 'user'
ITOP_PWD = 'itop_password'
PROXY = None

expected_header = [
        "FQDN",
        "IP_Address",
        "AO_Branch",
        "AO_Application",
        "OS_Name",
        "OS_Version",
        "CPU",
        "Memory",
        "Provisioned_Storage",
        "Used_Storage"
 ]

def check_csv_header(file_path):
    with open(file_path, mode='r') as file:
         reader = csv.reader(file)
         header = next(reader)
         if header != expected_header :
            raise ValueError("Header mismatch: Expected %s, but got %s"%(expected_header,header))

def process_zips(directory):

    target_dir = os.path.abspath(directory)

    zip_files = [ f for f in os.listdir(directory) if f.endswith('.zip') ]
    if len(zip_files) > 2 :
       print("found more than 2 Zip files- Aborting")
       sys.exit(1)
    elif len(zip_files) == 1:
       zip_path = os.path.join(target_dir,zip_files[0])
       print ("The zip file : %s"%zip_path)
       with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(target_dir)
       os.remove(zip_path)
       print("Extracted %s to current directory and removed archive"%{zip_files[0]})

   # Define the directory and filenames
    old_filename = 'iTop Consolidation Report.csv'
    new_filename = 'iTop_Consolidation_Report.csv'
   # Construct full paths
    old_filepath = os.path.join(directory, old_filename)
    new_filepath = os.path.join(directory, new_filename)

    # Check if the file exists
    if os.path.exists(old_filepath):
      try:
        # Rename the file
        os.rename(old_filepath, new_filepath)
        #subprocess.run(['sudo', 'mv', old_filepath, new_filepath], check=True)
        print("File renamed successfully: {} -> {}".format(old_filename, new_filename))
      except PermissionError:
        print("Error: Permission denied while renaming '{}'.".format(old_filename))
      except Exception as e:
        print("An unexpected error occurred: {}".format(e))
    else:
        print("File '{}' not found in directory '{}'. Exiting.".format(old_filename, directory))



def create_itop_machine(fqdn, project, envir, cmsofct, descript, os, os_version, cpu, ram, diskspace, ip, org="CMSO"):
    virtual_host = "CMSO-PPS-E"
    machine_data = {
        "name": fqdn,
        "org_id": "SELECT Organization WHERE name = '%s'" % org,
        "project": project,
        "osfamily_id": "SELECT OSFamily WHERE name = '%s'" % os,
        "osversion_id": "SELECT OSVersion WHERE name = '%s'" % os_version,
         "virtualhost_id":"SELECT VirtualHost WHERE name = '%s'" % virtual_host,
        "cpu": cpu,
        "ram": ram,
        "managementip": ip,
        "diskspace": diskspace,
        "status": "production",
        "currentstatus": "on"
    }

    payload = {
        "operation": "core/create",
        "class": "VirtualMachine",
        "fields": machine_data,
        "comment": "Created via Python API",
        "output_fields": "id, name, status"
    }

    try:
        session = requests.Session()
        if PROXY:
            session.proxies = {'https': PROXY}
            session.verify = False

        # Print request details for debugging
        print "Sending request to:", ITOP_URL
        print "Payload:", json.dumps(payload, indent=2)

        response = session.post(
            ITOP_URL,
            data={
                'version': '1.3',
                'auth_user': ITOP_USER,
                'auth_pwd': ITOP_PWD,
                'json_data': json.dumps(payload)
            },
            timeout=15
        )

        # Force show raw response before parsing
        print "\nRaw response content:"
        print "Status Code:", response.status_code
        print "Headers:", response.headers
        print "Body:", response.text[:1000]  # Show first 1000 characters

        response.raise_for_status()
        result = response.json()

        # Validate iTop-specific response structure
        if not isinstance(result, dict):
            raise ValueError("Response is not a JSON object")

        if 'objects' not in result and 'code' not in result:
            raise ValueError("Invalid iTop response structure. Received: %s" % result)

        return result

    except requests.exceptions.RequestException as e:
        print "Request failed:", str(e)
        if hasattr(e, 'response') and e.response:
            print "Error response content:", e.response.text[:1000]
        raise
    except ValueError as e:
        print "JSON decode error:", str(e)
        raise

def main():
    # Run Ansible playbook
    subprocess.call(["/bin/ansible-playbook", "get_list_servers_itop.yml", "-i", "itop.example.com,"])

    # Check and process VM list
    if not os.path.exists("/tmp/list_vms_itop.csv"):
        print("The List of iTop VMs is missing...aborting")
        sys.exit(1)

    # Remove duplicate headers
    with open("/tmp/list_vms_itop.csv", "r+") as f:
        lines = f.readlines()
        headers = [i for i, line in enumerate(lines) if "Name" in line]
        if len(headers) > 1:
            del lines[headers[-1]]
        f.seek(0)
        f.writelines(lines)
        f.truncate()

    # Check and process Server list
    if not os.path.exists("/tmp/list_servers_itop.csv"):
        print("The List of iTop Servers is missing... Aborting")
        sys.exit(1)

    # Remove duplicate headers
    with open("/tmp/list_servers_itop.csv", "r+") as f:
        lines = f.readlines()
        headers = [i for i, line in enumerate(lines) if "Name" in line]
        if len(headers) > 1:
            del lines[headers[-1]]
        f.seek(0)
        f.writelines(lines)
        f.truncate()

    # Merge CSV files
    with open("/tmp/list_itop_machines.csv", "w") as out:
        out.write("FQDN,IP ADDRESSS,OS_FAMILY\n")
        for fname in ["/tmp/list_vms_itop.csv", "/tmp/list_servers_itop.csv"]:
            with open(fname) as f:
                next(f)  # Skip header
                for line in f:
                    out.write(line.replace('"', ''))

    #Extract the external consolidate inventory file
    target_dir = '/itop/inventory'
    process_zips(target_dir)
    if not os.path.exists("/itop/inventory/iTop_Consolidation_Report.csv"):
       print("The consolidated list of machines is missing ... Aborting")
       sys.exit(1)



    # Compare files
    a_file = "/tmp/list_itop_machines.csv"
    b_file = "/itop/inventory/iTop_Consolidation_Report.csv"

    #Remove blank line at the end of the file
    subprocess.call(["sed", "-i", r"/^\s*$/d", b_file])
    subprocess.call(["sed", "-i",r"/^\s*$/d", b_file])
    #Renaming Linux OS name to RHEL
    subprocess.call(["sed", "-i", r"s/Linux/RHEL/", b_file])
    #Rename OS Version from Red Hat ES x.y to x,y
    subprocess.call(["sed", "-i", r"s/Red Hat ES //", b_file])
    output_file = "missing_in_itop.csv"

    #Validating the consolidated inventory file
    check_csv_header(b_file)

    a_ips = set()
    a_names = set()

    with open(a_file) as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        for row in reader:
            a_ips.add(row[1].strip('"').lower())
            a_names.add(row[0].strip('"').lower())

    with open(output_file, "w") as out:
        out.write("FQDN,IP_Address,AO_Branch,AO_Application,OS_Name,OS_Version,CPU,Memory,Provisioned_Storage,Used_Storage\n")

        with open(b_file) as f:
            reader = csv.reader(f)
            next(reader)  # Skip header
            for row in reader:
                ip = row[1].strip('"').lower()
                fqdn = row[0].strip('"').lower()

                if ip not in a_ips and fqdn not in a_names:
                    out.write(','.join(row) + '\n')

    print("Processing complete. Results in", output_file)
    print("Print the list of missing Servers in iTop....")
    with open(output_file) as f:
        print(f.read())

    #resp = input("\n\nDo you want to import the missing machines to iTop? (Y/N)? ")
    #if resp != "Y":
    #    print("Quitting...")
    #    sys.exit(0)

    # Process import
    with open(output_file) as f:
        next(f)  # Skip header
        for line in f:
            fields = line.strip().split(',')
            fqdn = fields[0]
            ip = fields[1]
            project = fields[3]
            os_name = fields[4]
            os_version = fields[5]
            cpu = fields[6]
            memory = fields[7]
            storage = fields[8]
            environment = ""
            cmso_fct = ""
            description = ""
            create_itop_machine (
                fqdn=fqdn,
                project=project,
                envir=environment,
                cmsofct=cmso_fct,
                descript=description,
                os=os_name,
                os_version=os_version,
                cpu=cpu,
                ram=memory,
                diskspace=storage,
                ip=ip
            )
            print('\n....')
            time.sleep(2)

if __name__ == "__main__":
    main()

