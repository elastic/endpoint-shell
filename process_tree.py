import os
import json
import traceback
import fnmatch
import re
import uuid
import datetime

import endpoint_api

filterlist = []
ignored_ips = set()
ignored_domains = set()
tracked_ips = {}

def track_dns(event):
    if get_val(event, "event.action") == "lookup_requested":
        query_name = get_val(event, "dns.question.name")
        for domain in ignored_domains:
            if fnmatch.fnmatch(query_name, domain):
                return True
    if not get_val(event, "event.action") == "lookup_result":
        return
    query_name = get_val(event, "dns.question.name")
    message = get_val(event, "message")
    ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", message)
    for ip in ips:
        if ip not in tracked_ips:
            tracked_ips[ip] = query_name
    found = False
    for domain in ignored_domains:
        if fnmatch.fnmatch(query_name, domain):
            found = True
            break
    if not found:
        return
    for ip in ips:
        ignored_ips.add(ip)
    return True
    
def get_val(alert, keys):
    """
    Function for safely retrieving a value from the alert
    """
    result = alert
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
                if len(result):
                    result = result[0]
                else:
                    result = {}
            result = result.get(key)
        
        if result == None:
            break
    return result

def dump(event):
    print("New event observed..")
    print(json.dumps(event, indent=4, sort_keys=True))
    print("Exiting..")
    quit()
       
analyzed_process = set()
def uniq_add(array, entry):
    if entry not in array:
        array.append(entry)

def process_activity(process_event, events, entity, indent=None):
    if entity in analyzed_process:
        return
    else:
        analyzed_process.add(entity)
        
    activity = []
    children = []
    if not indent:
        indent = 3

    # start with the process event
    process_str = f"{' '*(indent-3)}* {get_val(process_event, 'process.executable') or get_val(process_event, 'process.name')}: {get_val(process_event, 'process.command_line')}"
    effective_parent = get_val(process_event, "process.Ext.effective_parent.name")
    if effective_parent and effective_parent != get_val(process_event, "process.parent.name"):
        process_str += f" [effective parent: {effective_parent}]"
    uniq_add(activity, process_str)
    
    for event in events.get(entity, []):
        if track_dns(event):
            continue
        executable = get_val(event, "process.executable") or get_val(event, "process.name")
        category = get_val(event, "event.category")
        if not category:
            continue
        category = category[0]
        action = get_val(event, "event.action")
        if category == "process" and action != "end":
            if entity == get_val(event, "process.parent.entity_id"):
                # This is a child, so recurse
                child = process_activity(event, events, get_val(event, "process.entity_id"), indent=(indent+3))
                if child:
                    children.append(child)
        if entity != get_val(event, "process.entity_id"):
            continue
        elif category == "network":
            protocol = get_val(event, "network.protocol")
            transport = get_val(event, "network.transport")
            if protocol == "dns":
                if action in ("lookup_requested", "lookup_result"):
                    action = "lookup_requested"
                    query_name = get_val(event, "dns.question.name")
                    uniq_add(activity, f"{' '*indent}{category} - {action}: {query_name}")
            elif transport == "tcp":
                if action == "disconnect_received":
                    continue
                elif action == "connection_attempted":
                    dest_ip = get_val(event, "destination.ip")
                    dest_port = get_val(event, "destination.port")
                    msg = f"{' '*indent}{category} - {action}: {dest_ip}:{dest_port}"
                    if dest_ip in tracked_ips:
                        msg += f" [{tracked_ips[dest_ip]}]"                    
                    uniq_add(activity, msg)
                elif action == "connection_accepted":
                    src_ip = get_val(event, "source.ip")
                    src_port = get_val(event, "source.port")
                    dest_port = get_val(event, "destination.port")
                    uniq_add(activity, f"{' '*indent}{category} - {action}: {src_ip}:{src_port} -> {dest_port}")
        elif category == "file":
            file_path = get_val(event, "file.path")
            file_summary = f"{' '*indent}{category} - {action}: {file_path}"
            header = get_val(event, "file.Ext.header_bytes")
            if header:
                file_summary += f" [{bytes.fromhex(header)}]"
            effective_proc = get_val(event, "Effective_process.name")
            if effective_proc:
                file_summary += f" [effective: {effective_proc}]"
            uniq_add(activity, file_summary)
        elif category == "registry":
            if action in ("modification"):
                key_path = get_val(event, "registry.path")
                key_data = get_val(event, "registry.data.strings")
                uniq_add(activity, f"{' '*indent}{category} - {action}: {key_path} -> {key_data}")
            elif action == "query":
                key_path = get_val(event, "registry.path")
                uniq_add(activity, f"{' '*indent}{category} - {action}: {key_path}")
        elif get_val(event, "event.kind") == "alert":
            message = alert_oneline_summary(event)
            uniq_add(activity, f"{' '*indent}{message}")
        elif category == "process":
            pass
        elif category == "library":
            trusted = get_val(event, "dll.code_signature.trusted")
            if trusted: continue
            path = get_val(event, "dll.path")
            if path.endswith(".exe") : continue
            uniq_add(activity, f"{' '*indent}{category} - {action}: {get_val(event, 'dll.path')}")
        elif category == "driver":
            dll_path = get_val(event, "dll.path")
            subject = get_val(event, "dll.code_signature.subject_name")
            status = get_val(event, "dll.code_signature.status")
            uniq_add(activity, f"{' '*indent}{category} - {action}: {dll_path} ({subject}:{status})")
        elif category == "authentication":
            pass
        elif category == "api":
            summary = get_val(event, "process.Ext.api.summary")
            api_name = get_val(event, "process.Ext.api.name")
            stack = get_val(event, "process.thread.Ext.call_stack_summary")
            a = f"{' '*indent}{category} - {summary}, {stack}"
            if api_name == "WriteProcessMemory":
                size = get_val(event, "process.Ext.api.parameters.size") or 0
                if size < 5000:
                    continue
            if get_val(event, "event.action") == "diagnostic-only":
                a += " [Diag]"
            uniq_add(activity, a)
        else:
            print(f"Unknown category: {category}")
    
    for child in children:
        activity.extend(child)

    return activity

def alert_oneline_summary(event):
    # Generate a one line summary of an alert_coverage
    message = "error"
    try:
        message = get_val(event, "message")
        if get_val(event, "event.code") == "behavior":
            message = "Behavior Detection Alert"
        feature = None
        for k in event:
            if type(k) == str and k[0:1].isupper():
                feature = get_val(event, k + ".feature")
                if feature:
                    break
        code = get_val(event, "event.code")
        if feature:
            message += f" - {feature}"
        elif code:
            message += f" - {code}"
        rule_name = get_val(event, "rule.name")
        if rule_name:
            message += f" - {rule_name}"
        if code == "malicious_file":
            message += f" - {get_val(event, 'file.hash.sha256')}"
        if get_val(event, "data_stream.dataset") == "endpoint.diagnostic.collection":
            message += " [Diag]"
    except:
        print(traceback.format_exc())
    return message

def tree(events):
    output = ""

    events_by_process = {}
    for event in events:
        track_dns(event)
        category = get_val(event, "event.category")
        if not category:
            continue
        category = category[0]
        action = get_val(event, "event.action")
        if category == "process" and action != "end":
            entity_id = get_val(event, "process.parent.entity_id")
        else:
            entity_id = get_val(event, "process.entity_id")
        if entity_id not in events_by_process:
            events_by_process[entity_id] = []
        events_by_process[entity_id].append(event)
    for event in events:
        try:
            executable = get_val(event, "process.executable")
            category = get_val(event, "event.category")
            action = get_val(event, "event.action")
            if not category:
                continue
            category = category[0]
            if category == "process" and action != "end":
                activity = process_activity(event, events_by_process, get_val(event, "process.entity_id"))
                if activity:
                    #print("\n".join(activity))
                    output += "\n".join(activity) + "\n"
        except:
            print(traceback.format_exc())
            
    if output == "":
        output = "No activity"
    return output

def get_alert(session, alert_id, age):
    date_str = (datetime.datetime.utcnow()+datetime.timedelta(days=age*-1)).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    body = {
    "_source": True,
    "query": {
    "bool": {
      "filter": [
        {
          "bool": {
            "should": [
              {
                "term": {
                  "event.id": {
                    "value": alert_id
                  }
                }
              }
            ],
            "minimum_should_match": 1
          }
        },
        {
          "range": {
            "@timestamp": {
              "gte": date_str,
              "lte": "now/m"
            }
          }
        }
      ]
    }
    }
    }

    response = session.search(index="logs-*", body=body)
    if response["hits"]["hits"]:
        alert = response["hits"]["hits"][0]["_source"]
        
        return alert


def get_events_by_entity(session, entity_id, start_date, end_date, ancestors=None, children=None):
    body = {
    "size": 5000,
    "sort": [
        {
          "@timestamp": {
            "order": "asc",
            "format": "strict_date_optional_time",
          }
        }
    ],
    "query": {
    "bool": {
      "filter": [
        {
          "bool": {
            "should": [],
            "minimum_should_match": 1
          }
        },
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

    if ancestors:
        body["query"]["bool"]["filter"][0]["bool"]["should"].append({"term":{"process.entity_id":{"value":entity_id}}})
        body["query"]["bool"]["filter"][0]["bool"]["should"].append({"term":{"event.dataset":{"value":"endpoint.events.process"}}})
        body["query"]["bool"]["filter"][0]["bool"]["minimum_should_match"] = 2
    elif children:
        body["query"]["bool"]["filter"][0]["bool"]["should"].append({"term":{"process.Ext.ancestry":{"value":entity_id}}})
        body["query"]["bool"]["filter"][0]["bool"]["should"].append({"term":{"event.dataset":{"value":"endpoint.events.process"}}})
        body["query"]["bool"]["filter"][0]["bool"]["minimum_should_match"] = 2
    else:
        body["query"]["bool"]["filter"][0]["bool"]["should"].append({"term":{"process.entity_id":{"value":entity_id}}})

    response = session.search(index="logs-*", body=body)
    if response["hits"]["hits"]:
        events = []
        for hit in response["hits"]["hits"]:
            events.append(hit["_source"])
        return events  
    return []
    
def tree_from_alert(session, alert_id, age=None):
    if not age:
        age = 30

    alert = get_alert(session, alert_id, age)
    if not alert:
        print("Alert not found")
        return
    
    timestamp = alert["@timestamp"]
    base_date = datetime.datetime.strptime(timestamp[:26].strip('Z'), "%Y-%m-%dT%H:%M:%S.%f")
    start_date = base_date+datetime.timedelta(hours=-24)
    end_date = base_date+datetime.timedelta(hours=24)
    
    events = []
    
    ancestors = get_val(alert, "process.Ext.ancestry") or []
    ancestors.reverse()

    for entity_id in ancestors:
        events.extend(get_events_by_entity(session, entity_id, start_date, end_date, ancestors=True))
    
    entity_id = get_val(alert, "process.entity_id")
    events.extend(get_events_by_entity(session, entity_id,  start_date, end_date))
    
    children = get_events_by_entity(session, entity_id,  start_date, end_date, children=True)
    events.extend(children)
    for child in children:
         events.extend(get_events_by_entity(session, get_val(child, "process.entity_id"), start_date, end_date))

    return tree(events)
