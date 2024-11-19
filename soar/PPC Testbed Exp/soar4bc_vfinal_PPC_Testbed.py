from flask import Flask, request, jsonify
import requests
import json
import threading
import time
import subprocess
import os
import pytz
import logging
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# WAZUH API access
HEADERS = {
    'Content-Type': 'application/json',
    'Authorization': 'Basic YWRtaW46U2VjcmV0UGFzc3dvcmQ='
}
uri = "https://wazuh.trsc.net:9200/wazuh-alerts*/_search"
controller_uri = "http://127.0.0.1:8080/firewall/rules/00004665efb56049"
HONEYPOT_IP = "10.250.100.50"  # Honeypot's IP address

# Clean up old data from Neo4J database
def cleanup_neo4j_dashboard():
    try:
        url = "http://localhost:7474/db/neo4j/tx/commit"
        data = {
            "statements": [
                {
                    "statement": "MATCH (s:SOAR)-[r:RESPONSE]->(resp:RESPONSE) DELETE s, r, resp"
                },
                {
                    "statement": "MATCH (a:Attacker) DELETE a"
                }
            ]
        }
        response = requests.post(url, auth=('neo4j', 'sindit-neo4j'), json=data)
    except (KeyboardInterrupt, requests.exceptions.RequestException) as e:
            print(e)
            print("[ERROR] No Connection to Neo4j database")

def update_attacker_node_do_nothing(attacker_ip):
    #cleanup_neo4j_dashboard()
    try:
        # Define Neo4j URL
        url = "http://localhost:7474/db/neo4j/tx/commit"
        
        # Current timestamp (use CEST time)
        cest_tz = pytz.timezone('Europe/Berlin')
        timestamp = datetime.now(cest_tz).strftime("%Y-%m-%d %H:%M:%S")
        
        # Query to create or update the Attacker node with status 'blocked'
        query = """
        MERGE (a:Attacker {ip: $attacker_ip})
        ON CREATE SET a.status = 'Not Blocked', a.timestamp = $timestamp
        ON MATCH SET a.status = 'Not Blocked', a.timestamp = $timestamp
        """
        
        # Data for creating/updating attacker node
        data = {
            "statements": [
                {
                    "statement": query,
                    "parameters": {
                        "attacker_ip": attacker_ip,
                        "timestamp": timestamp
                    }
                }
            ]
        }
        
        response = requests.post(url, auth=('neo4j', 'sindit-neo4j'), json=data)
    except Exception as e:
        print(f"Error creating/updating attacker node: {e}")


def update_attacker_node(attacker_ip):
    #cleanup_neo4j_dashboard()
    try:
        # Define Neo4j URL
        url = "http://localhost:7474/db/neo4j/tx/commit"
        
        # Current timestamp (use CEST time)
        cest_tz = pytz.timezone('Europe/Berlin')
        timestamp = datetime.now(cest_tz).strftime("%Y-%m-%d %H:%M:%S")
        
        # Query to create or update the Attacker node with status 'blocked'
        query = """
        MERGE (a:Attacker {ip: $attacker_ip})
        ON CREATE SET a.status = 'Blocked', a.timestamp = $timestamp
        ON MATCH SET a.status = 'Blocked', a.timestamp = $timestamp
        """
        
        # Data for creating/updating attacker node
        data = {
            "statements": [
                {
                    "statement": query,
                    "parameters": {
                        "attacker_ip": attacker_ip,
                        "timestamp": timestamp
                    }
                }
            ]
        }
        
        response = requests.post(url, auth=('neo4j', 'sindit-neo4j'), json=data)
    except Exception as e:
        print(f"Error creating/updating attacker node: {e}")

def update_attacker_node_redirection(attacker_ip):
    try:
        url = "http://localhost:7474/db/neo4j/tx/commit"
        
        # Current timestamp (use CEST time)
        cest_tz = pytz.timezone('Europe/Berlin')
        timestamp = datetime.now(cest_tz).strftime("%Y-%m-%d %H:%M:%S")
        
        # Query to create or update the Attacker node with status 'blocked'
        query = """
        MERGE (a:Attacker {ip: $attacker_ip})
        ON CREATE SET a.status = 'Redirecting Traffic', a.timestamp = $timestamp
        ON MATCH SET a.status = 'Redirecting Traffic', a.timestamp = $timestamp
        """
        
        # Data for creating/updating attacker node
        data = {
            "statements": [
                {
                    "statement": query,
                    "parameters": {
                        "attacker_ip": attacker_ip,
                        "timestamp": timestamp
                    }
                }
            ]
        }
        
        response = requests.post(url, auth=('neo4j', 'sindit-neo4j'), json=data)
        
    except Exception as e:
        print(f"Error creating/updating attacker node: {e}")

def reset_route_stop_honeypot_dashboard(attacker_ip):
    try:
        url = "http://localhost:7474/db/neo4j/tx/commit"
        
        # Current timestamp (use CEST time)
        cest_tz = pytz.timezone('Europe/Berlin')
        timestamp = datetime.now(cest_tz).strftime("%Y-%m-%d %H:%M:%S")
        
        # Query to create or update the Attacker node with status 'blocked'
        query = """
        MERGE (a:Attacker {ip: $attacker_ip})
        ON CREATE SET a.status = 'Quarantined: Reset Traffic and Stop Honeypot', a.timestamp = $timestamp
        ON MATCH SET a.status = 'Quarantined: Reset Traffic and Stop Honeypot', a.timestamp = $timestamp
        """
        
        # Data for creating/updating attacker node
        data = {
            "statements": [
                {
                    "statement": query,
                    "parameters": {
                        "attacker_ip": attacker_ip,
                        "timestamp": timestamp
                    }
                }
            ]
        }
        
        response = requests.post(url, auth=('neo4j', 'sindit-neo4j'), json=data)
        
    except Exception as e:
        print(f"Error creating/updating attacker node: {e}")

# Neo4J update function with logging, and timestamps
def update_neo4j_dashboard(attacker_ip, response, reason):
    cleanup_neo4j_dashboard()  # Clean up old data before updating
    url = "http://localhost:7474/db/neo4j/tx/commit"
    
    # Get the current timestamp
    cest_tz = pytz.timezone('Europe/Berlin')  # CEST is the same as Europe/Berlin
    timestamp = datetime.now(cest_tz).strftime("%Y-%m-%d %H:%M:%S")

    # Create a new RESPONSE node with timestamp
    create_query = (
        "MERGE (s:SOAR {ip: $attacker_ip}) "
        "CREATE (s)-[:RESPONSE]->(resp:RESPONSE {ip: $attacker_ip, response: $response, reason: $reason, timestamp: $timestamp})"
    )
    
    data = {
        "statements": [
            {
                "statement": create_query,
                "parameters": {
                    "attacker_ip": attacker_ip,
                    "response": response,
                    "reason": reason,
                    "timestamp": timestamp
                }
            }
        ]
    }

    # Perform the update
    try:
        response = requests.post(url, auth=('neo4j', 'sindit-neo4j'), json=data)
        if response.status_code == 200:
            print(f"Neo4J dashboard updated successfully at {timestamp}")
        else:
            print(f"Failed to update Neo4J dashboard. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error updating Neo4J dashboard: {e}")

@app.route('/update_playbook', methods=['POST'])
def orchestrator():
    # Receive the playbook JSON data
    start_playbook_receive_time = time.time()
    playbook_data = request.get_json()
    
    # Extract the relevant action from the playbook
    action = extract_action(playbook_data)
    time_taken_playbook_extraction = time.time() - start_playbook_receive_time # Calculate time taken
    logging.info(f"Playbook Extraction Time: {time_taken_playbook_extraction:.6f} seconds")
    

    attacker_ip = get_attacker_ip()  # logic to get the attacker's IP
       
    if attacker_ip:
        if action == "Block IP SDN Controller":
            start_action_automator_time = time.time()  
            action_automator(attacker_ip)
            time_taken_by_action_automator = time.time() - start_action_automator_time  # Calculate time taken
            logging.info(f" Execution Time Taken by Action Automator: {time_taken_by_action_automator:.6f} seconds")
        elif action == "Block IP Firewall":
            start_action_automator_time = time.time()
            action_automator_pfsense(attacker_ip)
            time_taken_by_action_automator = time.time() - start_action_automator_time  # Calculate time taken
            logging.info(f" Execution Time Taken by Action Automator: {time_taken_by_action_automator:.6f} seconds")
        elif action == "Start Honeypot Server":
            start_action_automator_time = time.time()
            action_automator_honeypot_start(attacker_ip)
            time_taken_by_action_automator = time.time() - start_action_automator_time  # Calculate time taken
            logging.info(f" Execution Time Taken by Action Automator: {time_taken_by_action_automator:.6f} seconds")
        elif action == "Redirect Traffic":
            redirect_traffic_to_honeypot(attacker_ip)
        elif action == "Reset Routing":
            action_automator_reset_routing(attacker_ip)
        elif action == "Stop Honeypot Server":
            action_automator_stop_honeypot(attacker_ip) 
        elif action == "Do Nothing":
            action_automator_do_nothing(attacker_ip) 
        else:
            return jsonify({"error": "Unknown action"}), 400
    else:
        return jsonify({"error": "Attacker IP not found"}), 404
    
    return jsonify({"message": "Action processed successfully"}), 200

def extract_action(playbook_data):
    # Logic to extract the relevant action from the playbook
    try:
        # Navigate to the workflow section to find actions
        workflow = playbook_data.get("workflow", {})
        for key, value in workflow.items():
            if value.get("type") == "action":
                if value.get("name") == "Block IP SDN Controller":
                    return "Block IP SDN Controller"
                elif value.get("name") == "Block IP Firewall":
                    return "Block IP Firewall"
                elif value.get("name") == "Start Honeypot Server":
                    return "Start Honeypot Server"
                elif value.get("name") == "Redirect Traffic":
                    return "Redirect Traffic"
                elif value.get("name") == "Reset Routing":
                    return "Reset Routing"
                elif value.get("name") == "Stop Honeypot Server":
                    return "Stop Honeypot Server"
            elif value.get("name") == "start workflow Do Nothing":
                return "Do Nothing"
    except Exception as e:
        print(f"Error extracting action: {e}")
    return None

def action_automator(attacker_ip, dpid="00004665efb56049"):
    # Construct the firewall rule without explicit actions
    firewall_rule = {
        "nw_src": f"{attacker_ip}/32",  # Source IP to block
        "priority": 1,  # Priority of the rule
        "actions": "DENY"
    }
    
    # Log the firewall rule for debugging
    print("[ACTION AUTOMATOR] Automating response as per playbook")
    print(f"Sending the following firewall rule to the Ryu controller: {json.dumps(firewall_rule, indent=4)}")

    # Send the rule to the Ryu controller to block the attacker's IP
    r = requests.post(controller_uri, headers={'Content-Type': 'application/json'}, data=json.dumps(firewall_rule))
    
    # Print the status code and response body for debugging
    print(f"Response from Ryu: {r.status_code} - {r.text}")

    if r.status_code == 200:
        print(f"Successfully blocked attacker {attacker_ip} on switch {dpid}.")
        print("Updating Dashboard")
        update_neo4j_dashboard(attacker_ip, "Block Attacker IP by Ryu SDN", "Potential DoS Detected Against CSMS")
        update_attacker_node(attacker_ip)
    else:
        print(f"Failed to block attacker {attacker_ip}. Response: {r.status_code}, {r.text}")

def action_automator_stop_honeypot(attacker_ip):
    try:
        # Find the process using port 80 and kill it
        find_process_cmd = "sudo lsof -t -i:80"
        process_id = subprocess.check_output(find_process_cmd, shell=True).strip().decode('utf-8')

        if process_id:
            kill_cmd = f"sudo kill -9 {process_id}"
            subprocess.run(kill_cmd, shell=True, check=True)
            print(f"Honeypot Server Running on Port 80 Stopped Successfully (PID: {process_id}).")
            print("Updating Dashboard")
            # Update Neo4J after stopping honeypot
            update_neo4j_dashboard(attacker_ip, "Reset Routing and Stop Honeypot", "Reset Routing and Honeypot Stopped After Mitigation")
            reset_route_stop_honeypot_dashboard(attacker_ip)
        else:
            print("No Process Found Running on Port 80.")
    except subprocess.CalledProcessError as e:
        print(f"Error stopping honeypot server: {e}")


def action_automator_reset_routing(attacker_ip):
    # Reset the routing by removing the iptables rule that redirects traffic to the honeypot
    print("[ACTION AUTOMATOR] Reset Routing")
    try:
        reset_cmd = f"iptables -t nat -D PREROUTING -p tcp -s {attacker_ip} --dport 80 -j DNAT --to-destination {HONEYPOT_IP}:80"
        subprocess.run(reset_cmd, shell=True, check=True)
        print(f"Resetting Routing for {attacker_ip}. Traffic is No Longer Redirected to the Honeypot.")
        print("[ACTION AUTOMATOR] Stopping Honeypot Server")
        # Stop Honeypot Sever
        action_automator_stop_honeypot(attacker_ip)
    except subprocess.CalledProcessError as e:
        print(f"Error executing iptables reset command: {e}")


def action_automator_do_nothing(attacker_ip):
    print("[ACTION AUTOMATOR] Received Action (Do Nothing) to Execute")
    print("Updating Dashboard")
    update_neo4j_dashboard(attacker_ip, "Do Nothing", "Nothing to Execute")
    update_attacker_node_do_nothing(attacker_ip)

def action_automator_pfsense(attacker_ip):
    # Define the ipsense API endpoint and headers
    ipsense_uri = "https://10.250.100.1/api/v2/firewall/rule"
    headers = {
        'accept': 'application/json',
        'x-api-key': 'ae1ebac9cf11000fd84a833aa39c74a4',
        'Content-Type': 'application/json'
    }

    # Construct the firewall rule payload to block the attacker's IP
    ipsense_payload = {
        "type": "block",
        "interface": ["WAN"],  # Interface where the rule applies
        "ipprotocol": "inet",  # IP protocol (IPv4)
        "source": "1.1.1.1",  # Source IP to block 
        "destination": "8.8.8.8",  
        "descr": "Automatic rule by DYNABIC"
    }

    print(f"[ACTION AUTOMATOR] Blocking IP {attacker_ip} by pfsense")

    try:
        # Send the POST request to ipsense with the firewall rule
        response = requests.post(
            ipsense_uri,
            headers=headers,
            data=json.dumps(ipsense_payload),
            verify=False  # Disable SSL verification like --insecure
        )

        # Check if the request was successful
        if response.status_code == 200:
            #print(f"Response from pfsense: {response.status_code} - {response.text}")
            print(f"Response from pfsense: {response.status_code}")
            print("Updating Dashboard")
            update_neo4j_dashboard(attacker_ip, "Block Attacker IP by pfsense", "Potential DoS Detected Against CSMS")
            update_attacker_node(attacker_ip)
        else:
            print(f"Failed to block IP by pfsense: {response.status_code} - {response.text}")

    except Exception as e:
        print(f"Error while sending request to pfsense: {e}")

def redirect_traffic_to_honeypot(attacker_ip):
    try:
        # Redirect attacker's traffic to the Pentbox honeypot server using iptables
        redirect_cmd = f"iptables -t nat -A PREROUTING -p tcp -s {attacker_ip} --dport 80 -j DNAT --to-destination {HONEYPOT_IP}:80"
        subprocess.run(redirect_cmd, shell=True, check=True)
        print(f"Redirecting traffic from {attacker_ip} to Pentbox honeypot.")
        # Update Neo4J after redirecting
        update_neo4j_dashboard(attacker_ip, "Start Pentbox Honeypot and Redirect Attacker Traffic", "Potential DoS Detected Against CSMS")
        update_attacker_node_redirection(attacker_ip)
    except subprocess.CalledProcessError as e:
        print(f"Error executing iptables command: {e}")

def action_automator_honeypot_start(attacker_ip):
    try:
        script_path = "/home/user/pentbox_run.sh"
        # Run the Pentbox honeypot shell script
        subprocess.run(["sudo", script_path], check=True)
        print("Pentbox honeypot server started successfully.")
        redirect_traffic_to_honeypot(attacker_ip)
    except subprocess.CalledProcessError as e:
        print(f"Error starting honeypot: {e}")


def get_attacker_ip():
    # Fetch the attacker IP from Wazuh API
    query = json.dumps({
        "size": 1,
        "query": {
            "match": {
                "data.Analyzer.Name": "DYNABIC UC1",
            }
        }
    })
    
    # Suppress InsecureRequestWarning due to SSL verification being disabled 
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

    # Send request to Wazuh API and get the response
    response = requests.get(uri, headers=HEADERS, data=query, verify=False)
    response_data = response.json()
    for hit in response_data['hits']['hits']:
            # Extract the description field from each hit
            description = hit['_source']['rule']['description']
            
            # Check if "DoS" (Denial of Service) is mentioned in the description
            if "DoS" in description:
                # Extract the attacker's IP (under 'Source')
                attacker_ip = hit['_source']['data']['Source'][0]['IP']  
                #print(f"Attacker IP Found: {attacker_ip}")
                return attacker_ip  # Return the attacker IP

    return None  # Return None if no attacker IP is found

def print_event_handler_message():
    cleanup_neo4j_dashboard()
    start_detection_time = time.time()  # Start timing
    time.sleep(7)  # Wait for 7 seconds
    get_attacker_ip()
    print("[EVENT HANDLER] Potential Denial of Service (DoS) attack against CSMS detected.")
    time_taken_detection = time.time() - start_detection_time  # Calculate time taken
    logging.info(f"DDoS Attack Detection Time: {time_taken_detection:.6f} seconds")

    print("[ORCHESTRATOR] Getting Playbook Rule")

if __name__ == '__main__':
    # Start the thread to print the event handler message
    threading.Thread(target=print_event_handler_message).start()
    app.run(host='localhost', port=5005)