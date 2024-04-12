import os
import yaml
import datetime
import base64

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(ROOT_DIR, "etc", "remediation_config.yml")
with open(CONFIG_PATH) as f:
    CONFIG = yaml.safe_load(f)

def generate_registry_esql(agent_id, user_name):
    query = f'from logs-*| where event.category == "registry" and agent.id == "{agent_id}" and user.name == "{user_name}"| eval registry.key_lower = to_lower(registry.key) | where '
    for regkey in CONFIG["registry"]:
        key = regkey["key"]
        if key.startswith("HKLM"):
            hive = "HKLM"
        else:
            hive = "HKEY_USERS"
        key = key.replace("HKLM\\","")
        key = key.replace("HKEY_USERS\\","")
        key = key.replace("\\", "\\\\\\\\")
        key = key.lower()
        if "values" in regkey:
            # todo
            continue
        else:
            query += f'( registry.key_lower like "{key}" and registry.hive == "{hive}") or \n'
        
    # strip trailing or
    query = query.rstrip("or \n")
    query += '| keep registry.hive, registry.key, registry.value, registry.path, registry.data.strings'
    print(query)
    
    return query

def generate_file_esql(agent_id, user_name):
    query = f'from logs-*| where event.category == "file" and agent.id == "{agent_id}" and user.name == "{user_name}" '
    query += '| where (file.Ext.header_bytes like "4d5a*") '
    query += '| keep process.executable, file.path'
    #print(query)
    
    return query

def generate_process_esql(agent_id, user_name):
    query = f'from logs-*| where event.category == "process" and event.action == "start" and agent.id == "{agent_id}" and user.name == "{user_name}"'
    query += '| where not (process.code_signature.trusted == true and process.code_signature.subject_name like "*Microsoft*")' # todo or lolbin
    query += '| keep process.executable, process.entity_id, process.pid'
    #print(query)
    
    return query
    
def remediate_alert(session, alert_id):
    start_date = datetime.datetime.utcnow()+datetime.timedelta(hours=24*-1)
    rows = session.esql_query(f'from logs-*| where event.kind == "alert" and event.module == "endpoint" and event.id == "{alert_id}"|keep @timestamp, agent.id, user.name', start_date)
    if not rows:
        print("Alert not found")
        return
    row = rows[0]
    timestamp, agent_id, user_name = row
    print(f"Agent id: {agent_id}, User: {user_name}")
    base_date = datetime.datetime.strptime(timestamp[:26].strip('Z'), "%Y-%m-%dT%H:%M:%S.%f")
    start_date = base_date+datetime.timedelta(minutes=-5)
    end_date = base_date+datetime.timedelta(minutes=5)
    
    process_terminate_commands = []
    process_query = generate_process_esql(agent_id, user_name)
    rows = session.esql_query(process_query, start_date, end_date)
    if rows:
        print("Launched processes:")
        for row in rows:
            process, entity_id, pid = row
            print(f"  Process: {process}, Entity: {entity_id}, Pid: {pid}" )
            cmd = f'Stop-Process -Id {pid} -Force'
            process_terminate_commands.append(cmd)

    registry_cleanup_commands = []
    reg_query = generate_registry_esql(agent_id, user_name)
    rows = session.esql_query(reg_query, start_date, end_date)
    if rows:
        print("Registry persistence:")
        for row in rows:
            hive, key, value, path, strings = row
            print(f"  Path: {path}, Data: {strings}" )
            cmd = f'Remove-ItemProperty -Path "Registry::{hive}\\{key}" -Name "{value}" -Force'
            registry_cleanup_commands.append(cmd)

    files_to_collect = []
    file_cleanup_commands = []
    file_query = generate_file_esql(agent_id, user_name)
    rows = session.esql_query(file_query, start_date, end_date)
    if rows:
        print("Dropped files:")
        for row in rows:
            process, file_path = row
            print(f"  Process: {process}, Path: {file_path}" )
            files_to_collect.append(file_path)
            cmd = f'Remove-Item -Path "{file_path}" -Force'
            file_cleanup_commands.append(cmd)

    r = input("Execute remediation [y/n]: ")
    if r != "y":
        return
    
    if process_terminate_commands:
        print("Terminating processes..")
        cmd = ";".join(process_terminate_commands)
        cmd_enc = base64.b64encode(cmd.encode('UTF-16LE')).decode()
        session.execute_wait([agent_id], f"powershell -enc {cmd_enc}")

    if files_to_collect:
        print("Collecting dropped files..")
        for file_path in files_to_collect:
            session.get_file_wait(agent_id, file_path)
    
    if file_cleanup_commands or registry_cleanup_commands:
        print("Cleaning up files/registry..")
        cmd = ";".join(file_cleanup_commands + registry_cleanup_commands)
        cmd_enc = base64.b64encode(cmd.encode('UTF-16LE')).decode()
        session.execute_wait([agent_id], f"powershell -enc {cmd_enc}")
    
    print("Remediation complete!")

def main():
    return
    
if __name__ == "__main__":
    main()
