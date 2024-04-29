import os
import uuid
import time
import datetime
import io

import urllib3
import requests
import pyzipper

def get_val(data, keys):
    result = data
    keys = keys.split(".")
    for key in keys:
        if type(key) == int:
            if key+1 > len(result):
                result = None
            else:
                result = result[key]
        else:
            if type(result) == type([]):
                # if no offset into array is specified, grab the first entry
                if len(result) == 0:
                    return None
                result = result[0]
            result = result.get(key)
        
        if result == None:
            break
    return result
    
class Session:
    def __init__(self, kibana_url):
        if "://" not in kibana_url:
            kibana_url = "https://" + kibana_url

        kibana_url = kibana_url.rstrip("/")
        self.kibana_url = kibana_url
    def url(self, uri):
        return self.kibana_url + "/" + uri.lstrip("/")
        
    def login(self, user, password, cloud, no_verify):
        # login to kibana with the provided creds
        def response_hook(r, *args, **kwargs):
            try:
                r.raise_for_status()
            except Exception:
                if r.content and r.content.startswith(b"{"):
                    print(r.json())
                else:
                    print(r)
                raise
                
        session = requests.session()
        session.hooks['response'] = response_hook
        session.headers.update({'Content-Type': "application/json", "kbn-xsrf": str(uuid.uuid4())})
        
        if cloud:
            payload = {"username": user, "password": password}
            payload = {'params': payload, 'currentURL': '', 'providerType': 'basic', 'providerName': 'cloud-basic'}
            session.post(self.url("/internal/security/login"), json=payload)
        else:
            session.auth = (user, password)

        if no_verify:
            session.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self.session = session

    def get_hosts(self):
        # https://www.elastic.co/guide/en/security/current/list-endpoints-api.html
        response = self.session.get(self.url("/api/endpoint/metadata"), params={"hostStatuses": '["healthy"]'})
        hosts = []
        for host in response.json().get("data"):
            hosts.append((get_val(host, "metadata.agent.id"), get_val(host, "metadata.host.hostname"), get_val(host, "metadata.host.os.full")))
        return hosts

    def display_hosts(self):
        hosts = self.get_hosts()
        print(f"Active hosts: {len(hosts)}")
        for host in hosts:
            agent_id, hostname, os_full = host
            print(f"  {hostname} - {os_full} - {agent_id}")
    
    def get_action(self, action_id):
        # https://www.elastic.co/guide/en/security/current/get-action-api.html
        response = self.session.get(self.url(f"/api/endpoint/action/{action_id}")).json()
        return get_val(response, "data")

    def execute(self, endpoint_ids, command):
        # https://www.elastic.co/guide/en/security/current/execute-api.html
        params = {
            "endpoint_ids": endpoint_ids,
            "parameters": {
                "command": command,
                "timeout": 60,
            }
        }
        response = self.session.post(self.url("/api/endpoint/action/execute"), json=params).json()
        action_id = get_val(response, "data.id")
        return action_id
        
    def execute_wait(self, endpoint_ids, command):
        action_id = self.execute(endpoint_ids, command)
        while True:
            result = self.get_action(action_id)
            #print(json.dumps(result, indent=4))
            if result.get("status") != "pending":
                if result.get("status") != "successful":
                    print(f"Status: {result.get('status')}")
                    return
                outputs = {}
                for agent_id in result.get("outputs", {}):
                    outputs[agent_id] = {
                        "stdout": result["outputs"][agent_id]["content"]["stdout"],
                        "stderr": result["outputs"][agent_id]["content"]["stderr"],
                        "output": (result["outputs"][agent_id]["content"]["stdout"] + 
                                  result["outputs"][agent_id]["content"]["stderr"])
                    }
                return outputs
            time.sleep(1)

    def get_file(self, endpoint_ids, file_path):
        # https://www.elastic.co/guide/en/security/current/get-file-api.html
        params = {
            "endpoint_ids": endpoint_ids,
            "parameters": {
                "path": file_path,
            }
        }
        response = self.session.post(self.url("/api/endpoint/action/get_file"), json=params).json()
        action_id = get_val(response, "data.id")
        return action_id

    def download_file(self, action_id, endpoint_id):
        response = self.session.get(self.url(f"/api/endpoint/action/{action_id}/file/{action_id}.{endpoint_id}/download?apiVersion=2023-10-31"))
        zip_buffer = io.BytesIO()
        zip_buffer.write(response.content)
        with pyzipper.AESZipFile(zip_buffer) as zf:
            zf.setpassword(b"elastic")
            for file_name in zf.namelist():
                if file_name == "upload.info":
                    continue
                out_file = os.path.join("downloads", file_name)
                data = zf.read(file_name)
                if not os.path.exists("downloads"):
                    os.mkdir("downloads")
                with open(out_file, "wb") as f:
                    f.write(data)
                print(f"File saved to: {out_file}")

    
    def get_file_wait(self, endpoint_id, file_path):
        action_id = self.get_file([endpoint_id], file_path)
        while True:
            result = self.get_action(action_id)
            #print(json.dumps(result, indent=4))
            if result.get("status") != "pending":
                if result.get("status") != "successful":
                    print(f"Status: {result.get('status')}")
                    return
                self.download_file(action_id, endpoint_id)
                return
            time.sleep(1)
    
    def upload_file(self, endpoint_ids, file_name, content):
        files = {
            "file": (file_name, open("hello.txt","rb"), "form-data"),
            "endpoint_ids": (None, '["'+endpoint_ids[0]+'"]'),
        }
        response = self.session.post(self.url("/api/endpoint/action/upload"), files=files).json()
        action_id = get_val(response, "data.id")
        return action_id

    def upload_file_wait(self, endpoint_id, file_name, content):
        action_id = self.upload_file([endpoint_id], file_name, content)
        while True:
            result = self.get_action(action_id)
            if result.get("status") != "pending":
                if result.get("status") != "successful":
                    print(f"Status: {result.get('status')}")
                    return          
                print(f"Uploaded to: {result['outputs'][endpoint_id]['content']['path']}")
                return
            time.sleep(1)
    
    def esql_query(self, query, start_date=None, end_date=None):
        if not start_date:
            start_date = datetime.datetime.utcfromtimestamp(0)
        if not end_date:
            end_date = datetime.datetime.utcnow()
        body = {
            "query": query,
             "locale": "en",
              "filter": {
                "bool": {
                  "filter": [
                    {
                      "range": {
                        "@timestamp": {
                          "format": "strict_date_optional_time",
                          "gte": start_date.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                          "lte": end_date.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                        }
                      }
                    }
                  ]
                }
            }
        }
        response = self.session.post(self.url("/api/console/proxy?path=/_query/&method=POST"), json=body).json()
        return response.get("values", [])

    def search(self, index, body):
        response = self.session.post(self.url(f"/api/console/proxy?path=/{index}/_search?&method=POST"), json=body).json()
        return response
