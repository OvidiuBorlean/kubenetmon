import json
import requests
import datetime
import hashlib
import hmac
import base64
import subprocess
import os
import socket
from socket import gaierror
import time


settings = {}
settings['timeout']         = 3
settings['sleep']           = 1000
settings['limit']           = 5
settings['ip']              = "google.ro"
settings['port']            = "80"

def tcping(host):
    try:
        connected = False
        tsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tsock.settimeout(settings['timeout'])
        tsock.connect(host, int(settings['port']))
        connected = True
        tsock.shutdown(socket.SHUT_RDWR)
        tsock.close()
        return connected
    except Exception as ErrMs:
        return connected

def dnstest(host):
    try:
        data = socket.gethostbyname(host)
        ip = repr(data)
        #print(ip)
        return ip
    except Exception:
        # fail gracefully!
        return False

### Reserved for future deployments
#def httptest(url):
#  try:
#    initial_time = time.time() #Store the time when request is sent
#    request = requests.get(url)
#    ending_time = time.time() #Time when acknowledged the request
#    elapsed_time = str(ending_time - initial_time)
#    return elapsed_time
#  except:
#    return False    

def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print('Accepted')
    else:
        print("Response code: {}".format(response.status_code))


if __name__ == "__main__":
    
    # For test purpose, will set in program the ENV vars
    os.environ["HOSTTARGET"] = "google.ro"
    os.environ["FQDN"] = "microsoft.com"
    os.environ["PINGTEST"] = "False"
    os.environ["HTTPTEST"] = "True"
    os.environ["DNSTEST"] = "True"
    
    #Getting the Environment Variables to check for the tests that needs to be run. The tests are boolean values, with pingTest configured to True by default
    pingTest = True
    hostTarget = os.environ['HOSTTARGET']
    pingTest = os.environ['PINGTEST']
    httpTest = os.environ['HTTPTEST']
    dnsTest = os.environ['DNSTEST']
    fqdn = os.environ['FQDN']

    
     # Update the customer ID to your Log Analytics workspace ID
    customer_id = ''

    # For the shared key, use either the primary or the secondary Connected Sources client authentication key
    shared_key = ""

    # The log type is the name of the event that is being submitted
    log_type = 'KubeNetMonitor'
    
    if len(hostTarget) == 0:
        print ("Please provide the env for HOSTTARGET")
    else:
        values = []
        for count in range(5):
            pSTime = datetime.datetime.now()
            pStat = tcping(hostTarget)
            pETime = datetime.datetime.now()
            pingTime = pETime - pSTime
            #pingTime = pETime - pSTime
            #pSTime = str(pSTime.strftime("%Y-%m-%dT%H:%M:%S"))
            pSTime = str(pSTime.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])
            pingTime = pingTime.total_seconds()
            pingTime = "{:.4f}".format(pingTime)
            pingTimeMS = float(pingTime)*1000
            values.append(pingTimeMS)
            time.sleep(1)
        os.environ["min_latency"] = str(min(values))
        os.environ["avg_latency"] = str(sum(values)/5)
        os.environ["max_latency"] = str(max(values))
        os.environ["dnsresponder"] = "Down"
        
    if dnsTest == "True":
        DNSTestResult =  dnstest(fqdn)
        #print(type(DNSTestResult))
        if DNSTestResult == False:
            os.environ["dnsquery"] = "False" 
        else:
            os.environ["dnsquery"] = DNSTestResult

    commands = '''
        
   
    UTCScriptRunTime=`date "+%F %T"`

    # Get Linux Distribution

    distro=`lsb_release -d | awk '{print $2 $3}'`

    # Get VM private IP Address


    IPAddress=`ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'` 2> /dev/null

    dnsresponder=$(dig $FQDN | grep SERVER)

    # Get VM Public IP Address

    PublicIP=`wget http://ipecho.net/plain -O - -q ; echo` 2> /dev/null


    
    printf '{"UTCScriptRunTime":"%s","IPAddress":"%s","PublicIP":"%s","MinLatency":"%s","AvgLatency":"%s","MaxLatency":"%s","DNSQuery":"%s", "DNSResponder":"%s"}\n' "$UTCScriptRunTime" "$IPAddress" "$PublicIP" "$min_latency" "$avg_latency" "$max_latency" "$dnsquery" "$dnsresponder"
    '''

    process = subprocess.Popen('/bin/bash', stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    body, err = process.communicate(commands.encode('utf-8'))
 
    #print(str(body) + "\n")    
    post_data(customer_id, shared_key, body, log_type)
