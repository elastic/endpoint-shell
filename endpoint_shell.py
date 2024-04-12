import shlex
import argparse
import datetime

from prettytable import PrettyTable

import endpoint_api
import remediate

def shell(session, active_host):
    agent_id, hostname, os_full = active_host
    while True:
        prompt = active_host[1]
        cmd = input(f"[{active_host[1]}] shell > ")
        if cmd in ("!exit","exit","!quit","quit"):
            break
        if not cmd:
            continue
        outputs = session.execute_wait([agent_id], cmd)
        if not outputs:
            continue
        print(outputs.get(agent_id, {}).get("output"))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--kibana-url', help='Kibana URL', required=True)
    parser.add_argument('--user', dest='user', help='Kibana username', default="elastic")
    parser.add_argument('--password', dest='password', help='Kibana password')
    args = parser.parse_args()
    
    if not args.password:
        args.password = input("Enter password: ")
    
    session = endpoint_api.Session(args.kibana_url)
    session.login(args.user, args.password)
    
    active_host = None
    while True:
        if active_host:
            prompt = active_host[1]
        else:
            prompt = "endpoint shell"
        cmd = input(f"[{prompt}] > ")
        
        if cmd.startswith("!help"):
            print(" = Endpoint Response Shell =")
            print("Available commands:")
            print("!list                             List active endpoints")
            print("!interact <host name>             Interact with a host")
            print("!shell                            Launch a pseudo shell on host")
            print("!download <path>                  Download a file from a host")
            print("!upload <local path> <file name>  Upload a file to a host")
            print("!alerts                           Display recent endpoint alerts")
            print("!remediate <alert id>             Malware remediaton for an alert")
            
        elif cmd.startswith("!list"):
            session.display_hosts()

        elif cmd.startswith("!interact"):
            active_host = None
            args = cmd.split(" ")
            if len(args) != 2:
                print("Usage: !interact <hostname>")
                continue
            hosts = session.get_hosts()
            for host in hosts:
                agent_id, hostname, os_full = host
                if args[1] in hostname:
                    active_host = host
                    break
            if not active_host:
                print("Host not found")
        
        elif cmd.startswith("!shell"):
            if not active_host:
                print("Use !interact first")
                continue
            shell(session, active_host)

        elif cmd.startswith("!download") or cmd.startswith("!dl"):
            if not active_host:
                print("Use !interact first")
                continue
            args = cmd.split(" ")
            if len(args) != 2:
                print("Usage: !download <path>")
                continue
            session.get_file_wait(active_host[0], args[1])

        elif cmd.startswith("!upload") or cmd.startswith("!ul"):
            if not active_host:
                print("Use !interact first")
                continue
            args = shlex.split(cmd, posix=False)
            if len(args) != 3:
                print("Usage: !upload <local path> <file name>")
                continue
            with open(args[1], "rb") as f:
                content = f.read()
            session.upload_file_wait(active_host[0], args[2], content)
        
        elif cmd.startswith("!alerts"):
            start_date = datetime.datetime.utcnow()+datetime.timedelta(hours=24*-1)
            rows = session.esql_query('from logs-*| where event.kind == "alert" and event.module == "endpoint"|keep process.executable, message, event.id', start_date)
            if not rows:
                print("No alerts found")
                continue
            pt = PrettyTable(["executable","message","alert id"])
            for row in rows:
                pt.add_row(row)
            pt.align = "l"
            print(pt)

        elif cmd.startswith("!remediate"):
            args = cmd.split(" ")
            if len(args) != 2:
                print("Usage: !remediate <alert id>")
                continue
            remediate.remediate_alert(session, args[1])
        elif cmd in ("!exit", "exit", "!quit", "quit"):
            break

if __name__ == "__main__":
    main()

