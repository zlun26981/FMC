      	
#
# Generated FMC REST API sample script
#
 
import json
import sys
import requests
 
server = "https://fmcrestapisandbox.cisco.com"
 
username = "zlun"
if len(sys.argv) > 1:
    username = sys.argv[1]
password = "36UbTd9K"
if len(sys.argv) > 2:
    password = sys.argv[2]
               
r = None
headers = {'Content-Type': 'application/json'}
api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
auth_url = server + api_auth_path
try:
    # 2 ways of making a REST call are provided:
    # One with "SSL verification turned off" and the other with "SSL verification turned on".
    # The one with "SSL verification turned off" is commented out. If you like to use that then 
    # uncomment the line where verify=False and comment the line with =verify='/path/to/ssl_certificate'
    # REST call with SSL verification turned off: 
    r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify=False)
    # REST call with SSL verification turned on: Download SSL certificates from your FMC first and provide its path for verification.
    #r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(username,password), verify='/path/to/ssl_certificate')
    auth_headers = r.headers
    auth_token = auth_headers.get('X-auth-access-token', default=None)
    if auth_token == None:
        print("auth_token not found. Exiting...")
        sys.exit()
except Exception as err:
    print ("Error in generating auth token --> "+str(err))
    sys.exit()
 
headers['X-auth-access-token']=auth_token
 
api_path = "/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/securityzones"    # param
url = server + api_path
if (url[-1] == '/'):
    url = url[:-1]
 
# GET OPERATION
 

try:
    # REST call with SSL verification turned off: 
    r = requests.get(url, headers=headers, verify=False)
    # REST call with SSL verification turned on:
    #r = requests.get(url, headers=headers, verify='/path/to/ssl_certificate')
    status_code = r.status_code
    resp = r.text
    if (status_code == 200):
        print("GET successful. Response data --> ")
        Object_name = input('Which object do you want to delete: ')
        json_resp = json.loads(resp)
        Object_count = json_resp['paging']['count']
        print(str(Object_count) + ' objects have been found. \n')
        for i in range (Object_count):
            item = json_resp['items'][i]
            if item['name'] == Object_name:
                Object_ID = item['id']
                print(Object_name + ' Object found!')
                break
				#print('Name: ' + item['name'] + '\nID: ' + item['id'] + '\n')
            else:
                print('Name: ' + item['name'] + '\nID: ' + item['id'] + '\n')
        #print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
    else:
        r.raise_for_status()
        print("Error occurred in GET --> "+resp)
except requests.exceptions.HTTPError as err:
    print ("Error in connection --> "+str(err)) 
finally:
    if r : r.close()
