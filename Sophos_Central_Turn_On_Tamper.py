# Copyright 2019-2020 Sophos Limited
#
# Licensed under the GNU General Public License v3.0(the "License"); you may
# not use this file except in compliance with the License.
#
# You may obtain a copy of the License at:
# https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied. See the License for the specific language governing permissions and
# limitations under the License.
#
#
# Sophos_Central_Turn_On_Tamper.py
#
# Turns Tamper on for all machines in every Sophos Central sub estate
#
#
# By: Michael Curtis and Robert Prechtel
# Date: 29/5/2020
# Version 2.04
# README: This script is an unsupported solution provided by
#           Sophos Professional Services
import requests
import csv
import configparser
import json
# Import getpass for Client Secret
import getpass
# Import datetime modules
from datetime import date
from datetime import datetime
# Import OS to allow to check which OS the script is being run on
import os
today = date.today()
now = datetime.now()
timestamp = str(now.strftime("%d%m%Y_%H-%M-%S"))
# This list will hold all the sub estates
sub_estate_list = []
# This list will hold all the computers
computer_list = []

# Get Access Token - JWT in the documentation
def get_bearer_token(client, secret, url):
    d = {
                'grant_type': 'client_credentials',
                'client_id': client,
                'client_secret': secret,
                'scope': 'token'
            }
    request_token = requests.post(url, auth=(client, secret), data=d)
    json_token = request_token.json()
    #headers is used to get data from Central
    #headers = {'Authorization': str('Bearer ' + json_token['access_token'])}
    headers = {'Authorization': f"Bearer {json_token['access_token']}"}
    # post headers is used to post to Central
    post_headers = {'Authorization': f"Bearer {json_token['access_token']}",
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }
    return headers, post_headers

def get_whoami():
    # We now have our JWT Access Token. We now need to find out if we are a Partner or Organization
    # Partner = MSP
    # Organization = Sophos Central Enterprise Dashboard
    # The whoami URL
    whoami_url = 'https://api.central.sophos.com/whoami/v1'
    request_whoami = requests.get(whoami_url, headers=headers)
    whoami = request_whoami.json()
    # MSP or Sophos Central Enterprise Dashboard
    # We don't use this variable in this script. It returns the organization type
    organization_type = whoami["idType"]
    if whoami["idType"] == "partner":
        organization_header= "X-Partner-ID"
    elif whoami["idType"] == "organization":
        organization_header = "X-Organization-ID"
    else:
        organization_header = "X-Tenant-ID"
    organization_id = whoami["id"]
    # The region_url is used if Sophos Central is a tenant
    region_url = whoami['apiHosts']["dataRegion"]
    return organization_id, organization_header, organization_type, region_url

def get_all_sub_estates():
    # Add X-Organization-ID to the headers dictionary
    headers[organization_header] = organization_id
    # URL to get the list of tenants
    # Request all tenants
    request_sub_estates = requests.get(f"{'https://api.central.sophos.com/'}{organization_type}{'/v1/tenants?pageTotal=True'}", headers=headers)
    # Convert to JSON
    sub_estate_json = request_sub_estates.json()
    # Find the number of pages we will need to search to get all the sub estates
    total_pages = sub_estate_json["pages"]["total"]
    # Set the keys you want in the list
    sub_estate_keys = ('id', 'name', 'dataRegion')
    while (total_pages != 0):
    #Paged URL https://api.central.sophos.com/organization/v1/tenants?page=2 add total pages in a loop
        request_sub_estates = requests.get(f"{'https://api.central.sophos.com/'}{organization_type}{'/v1/tenants?page='}{total_pages}", headers=headers)
        sub_estate_json = request_sub_estates.json()
        #Add the tenants to the sub estate list
        for all_sub_estates in sub_estate_json["items"]:
            #Make a temporary Dictionary to be added to the sub estate list
            sub_estate_dictionary = {key:value for key, value in all_sub_estates.items() if key in sub_estate_keys}
            sub_estate_list.append(sub_estate_dictionary)
            print(f"Sub Estate - {sub_estate_dictionary['name']}. Sub Estate ID - {sub_estate_dictionary['id']}")
        total_pages -= 1
    # Remove X-Organization-ID from headers dictionary. We don't need this anymore
    del headers[organization_header]
    # Debug code
    print(f"Sub Estates Found: {(len(sub_estate_list))}")

def get_all_computers(sub_estate_token, url, sub_estate_name):
    # Get all Computers from sub estates
    print(f'Checking tamper for machines in - {sub_estate_name}')
    # Add pageSize to url and the view of full
    pagesize = 500
    tamper_url = url
    url = (f"{url}{'/endpoints?pageSize='}{pagesize}")
    computers_url = url
    # Loop while the page_count is not equal to 0. We have more computers to query
    page_count = 1
    while page_count != 0:
        # Sub estate to be searched
        sub_estate_id = sub_estate_token
        # Add X-Tenant-ID to the headers dictionary
        headers['X-Tenant-ID'] = sub_estate_id
        # Add X-Tenant-ID to the post_headers dictionary
        post_headers['X-Tenant-ID'] = sub_estate_id
        # Request all Computers
        request_computers = requests.get(computers_url, headers=headers)
        if request_computers.status_code == 403:
            print(f"No access to sub estate - {sub_estate_name}. Status Code - {request_computers.status_code}")
            break
        if request_computers.status_code != 200:
            return
        # Convert to JSON
        computers_json = request_computers.json()
        # Set the keys you want in the list
        computer_keys = ('id', 'hostname', 'lastSeenAt', 'tamperProtectionEnabled', 'Sub Estate', 'type')
        for all_computers in computers_json["items"]:
            # Make a temporary Dictionary to be added to the sub estate list
            computer_dictionary = {key: value for key, value in all_computers.items() if key in computer_keys}
            if 'lastSeenAt' in computer_dictionary.keys():
                # This line allows you to debug on a certain computer. Add computer name
                if 'machinename' == computer_dictionary['hostname']:
                    print('Add breakpoint here', computer_dictionary['hostname'])
                # Sends the last seen date to get_days_since_last_seen and converts this to days
                computer_dictionary['Last_Seen'] = get_days_since_last_seen(computer_dictionary['lastSeenAt'])
                # Checks if Health have been returned
                if 'tamperProtectionEnabled' in computer_dictionary.keys():
                    # Checks if Tamper is enabled
                    if computer_dictionary['tamperProtectionEnabled'] == False:
                        if organization_type == "tenant":
                            # Provides direct link to the machines. Not working well with sub estate at the moment
                            computer_dictionary['Machine_URL'] = make_valid_client_id(computer_dictionary['type'],
                                                                                      computer_dictionary['id'])
                        else:
                            computer_dictionary['Machine_URL'] = 'N/A'
                        if organization_type != "tenant":
                            # Adds the sub estate name to the computer dictionary only if the console is Sophos Central Enterprise Dashboard or MSP
                            computer_dictionary['Sub Estate'] = sub_estate_name
                        # Add the computers to the computers list
                        computer_list.append(computer_dictionary)
                        # Turn on Tamper and return status code. 201 successful
                        result_code = turn_on_tamper(computer_dictionary['id'], tamper_url, post_headers)
                        if result_code.status_code == 201:
                            computer_dictionary['tamperProtectionEnabled'] = 'Successful'
                            print(f"Tamper was turned on for machine: {computer_dictionary['hostname']} - {computer_dictionary['id']}")
                        else:
                            computer_dictionary['tamperProtectionEnabled'] = 'Failed'
        # Check to see if you have more than 500 machines by checking if nextKey exists
        # We need to check if we need to page through lots of computers
        if 'nextKey' in computers_json['pages']:
            next_page = computers_json['pages']['nextKey']
            # Change URL to get the next page of computers
            # Example https://api-us01.central.sophos.com/endpoint/v1/endpoints?pageFromKey=<next-key>
            computers_url = f"{url}{'&pageFromKey='}{next_page}"
            # print(computers_url)
        else:
            # If we don't get another nextKey set page_count to 0 to stop looping
            page_count = 0

def turn_on_tamper(machine_id, endpoint_url, post_header):
    # full_endpoint_url = f"{endpoint_url}{'/endpoints/'}{machine_id}{'/'}{'tamper-protection'}"
    tamper_status = {'enabled': 'true'}
    result = requests.post(f"{endpoint_url}{'/endpoints/'}{machine_id}{'/'}{'tamper-protection'}",data=json.dumps(tamper_status), headers=post_header)
    return result

def get_days_since_last_seen(report_date):
    # https://www.programiz.com/python-programming/datetime/strptime
    # Converts report_date from a string into a DataTime
    convert_last_seen_to_a_date = datetime.strptime(report_date, "%Y-%m-%dT%H:%M:%S.%f%z")
    # Remove the time from convert_last_seen_to_a_date
    convert_last_seen_to_a_date = datetime.date(convert_last_seen_to_a_date)
    # Converts date to days
    days = (today - convert_last_seen_to_a_date).days
    return days

def make_valid_client_id(os, machine_id):
    Server_URL = 'https://central.sophos.com/manage/server/devices/servers/'
    Endpoint_URL = 'https://central.sophos.com/manage/endpoint/devices/computers/'
    # Characters to be removed
    # Remove the - from the id
    remove_characters_from_id = ['-']
    for remove_each_character in remove_characters_from_id:
        machine_id = machine_id.replace(remove_each_character, '')
    new_machine_id = list(machine_id)
    # Rotates the characters
    new_machine_id[::2], new_machine_id[1::2] = new_machine_id[1::2], new_machine_id[::2]
    for i in range(8, 28, 5):
        new_machine_id.insert(i, '-')
    new_machine_id = ''.join(new_machine_id)
    if os == 'computer':
        machine_url = Endpoint_URL + new_machine_id
    else:
        machine_url = Server_URL + new_machine_id
    return (machine_url)

def read_config():
    config = configparser.ConfigParser()
    config.read('Sophos_Central_Turn_On_Tamper.config')
    config.sections()
    client_id = config['DEFAULT']['ClientID']
    client_secret = config['DEFAULT']['ClientSecret']
    if client_secret == '':
        client_secret = getpass.getpass(prompt='Enter Client Secret: ', stream=None)
    report_name = config['REPORT']['ReportName']
    report_file_path = config['REPORT']['ReportFilePath']
    # Checks if the last character of the file path contains a \ or / if not add one
    if report_file_path[-1].isalpha():
        if os.name != "posix":
            report_file_path = report_file_path + "\\"
        else:
            report_file_path = report_file_path + "/"
    return(client_id, client_secret, report_name, report_file_path)

def report_field_names():
    # Customise the column headers
    field_names = ['Machine URL',
                  'Sub Estate',
                  'Hostname',
                  'Type',
                  'Last Seen Date',
                  'Days Since Last Seen',
                  'Tamper Enabled',
                  'ID',
                  ]
    #Sets the column order
    order = ['Machine_URL',
             'Sub Estate',
             'hostname',
             'type',
             'lastSeenAt',
             'Last_Seen',
             'tamperProtectionEnabled',
             'id',
            ]
    return (field_names, order)

def print_report():
    full_report_path = f"{report_file_path}{report_name}{timestamp}{'.csv'}"
    with open(full_report_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(field_names)
    with open(full_report_path, 'a+', encoding='utf-8', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, order)
        dict_writer.writerows(computer_list)

client_id, client_secret, report_name, report_file_path = read_config()
field_names, order = report_field_names()
token_url = 'https://id.sophos.com/api/v2/oauth2/token'
headers, post_headers = get_bearer_token(client_id, client_secret, token_url)
organization_id, organization_header, organization_type, region_url = get_whoami()
if organization_type != "tenant":
    print(f"Sophos Central is a {organization_type}")
    get_all_sub_estates()
    for sub_etates_in_list in range(len(sub_estate_list)):
        sub_estate = sub_estate_list[sub_etates_in_list]
        get_all_computers(sub_estate['id'], f"{'https://api-'}{sub_estate['dataRegion']}{'.central.sophos.com/endpoint/v1'}", sub_estate['name'])
else:
    print(f"Sophos Central is a {organization_type}")
    # Removes sub estate name from report if the console is a single tenant
    field_names.remove('Sub Estate')
    order.remove('Sub Estate')
    get_all_computers(organization_id,f"{region_url}{'/endpoint/v1'}", organization_type)
print_report()