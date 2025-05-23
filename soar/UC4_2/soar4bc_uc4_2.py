from flask import Flask, request, jsonify
import requests
import json
import threading
import time
import subprocess
import os
import pytz
import logging
import warnings
from datetime import datetime
from kafka import KafkaConsumer, KafkaProducer
import json

# Suppress InsecureRequestWarning
warnings.filterwarnings('ignore', 'Unverified HTTPS request')

# Set up logging
logging.basicConfig(level=logging.INFO)

#app = Flask(__name__)

# Kafka Configuration
KAFKA_SERVER = 'kafka.dynabic.dev:9092'
TOPIC = 'UC4.SOAR4BC.playbook'
RESULT_TOPIC = 'UC4.SOAR4BC.result'

# Configure KAFKA SOAR4BC Password (XXXX)
# Configure Kafka producer
def create_kafka_producer():
    return KafkaProducer(
        bootstrap_servers=[KAFKA_SERVER],
        security_protocol='SASL_PLAINTEXT',
        sasl_mechanism='PLAIN',
        sasl_plain_username='soar4bc',
        sasl_plain_password='XXXXX',
        value_serializer=lambda x: json.dumps(x).encode('utf-8')
    )


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

def kafka_playbook_consumer():
    """
    Kafka consumer function to receive security playbooks
    """
    consumer = KafkaConsumer(
        TOPIC, 
        bootstrap_servers=[KAFKA_SERVER], 
        security_protocol='SASL_PLAINTEXT', 
        sasl_mechanism='PLAIN', 
        sasl_plain_username='soar4bc', 
        sasl_plain_password='XXXXX', 
        auto_offset_reset='earliest',
        enable_auto_commit=True, 
        value_deserializer=lambda x: json.loads(x.decode('utf-8')) if x else None
    )

    print(f'Listening for messages on topic: {TOPIC}')
    
    try:
        for message in consumer:
            try:
                # Parse the Kafka message
                playbook_data = message.value
                
                # Log received playbook
                #logging.info(f"Received playbook from Kafka: {playbook_data}")
                logging.info("Received Playbook from Kafka")
                
                # Extract the relevant action from the playbook
                start_playbook_receive_time = time.time()
                action = extract_action(playbook_data)
                time_taken_playbook_extraction = time.time() - start_playbook_receive_time
                logging.info(f"Playbook Extraction Time: {time_taken_playbook_extraction:.6f} seconds")

                # Get attacker IP from the playbook
                attacker_ip = get_attacker_ip(playbook_data)
                
                if attacker_ip:
                    if action == "Block IP":
                        start_action_automator_time = time.time()
                        action_automator_pfsense(attacker_ip)
                        time_taken_by_action_automator = time.time() - start_action_automator_time
                        logging.info(f"Execution Time Taken by Action Automator: {time_taken_by_action_automator:.6f} seconds") 
                    elif action == "Do Nothing":
                        action_automator_do_nothing(attacker_ip) 
                    else:
                        logging.error(f"Unknown action: {action}")
                else:
                    logging.error("Attacker IP not found in playbook")
            
            except Exception as e:
                logging.error(f"Error processing Kafka message: {e}")
    
    except KeyboardInterrupt:
        print("Kafka Consumer stopped.")
    finally:
        consumer.close()

def start_kafka_consumer():
    """
    Start Kafka consumer in a separate thread
    """
    kafka_thread = threading.Thread(target=kafka_playbook_consumer, daemon=True)
    kafka_thread.start()
    return kafka_thread
      
def extract_action(playbook_data):
    # Logic to extract the relevant action from the playbook
    try:
        # Navigate to the workflow section to find actions
        workflow = playbook_data.get("workflow", {})
        for key, value in workflow.items():
            if value.get("type") == "action":
                if value.get("name") == "Block IP":
                    return "Block IP"
                elif value.get("name") == "Block IP Firewall":
                    return "Block IP"
                elif value.get("name") == "Blocking IP":
                    return "Block IP"
            elif value.get("name") == "start workflow Do Nothing":
                return "Do Nothing"
    except Exception as e:
        print(f"Error extracting action: {e}")
    return None


def action_automator_do_nothing(attacker_ip):
    print("[ACTION AUTOMATOR] Received Action (Do Nothing) to Execute")
    print("Updating Dashboard")
    update_neo4j_dashboard(attacker_ip, "Do Nothing", "Nothing to Execute")
    update_attacker_node_do_nothing(attacker_ip)
    
    # Publish result to Kafka
    publish_action_result(attacker_ip, "Do Nothing", "success", "No action was required")

def action_automator_pfsense(attacker_ip):
    # Define the ipsense API endpoint and headers
    ipsense_uri = "https://192.168.61.5/api/v2/firewall/rule"
    headers = {
        'accept': 'application/json',
        'x-api-key': 'db8b91b25d87da99ac8fa12655649c84',
        'Content-Type': 'application/json'
    }

    # Construct the firewall rule payload to block the attacker's IP
    # Updated payload as per the new requirements
    ipsense_payload = {
        "type": "block",
        "interface": ["opt4"],
        "ipprotocol": "inet",
        "protocol": "tcp/udp",
        "source": attacker_ip,  # Use the suspicious IP directly
        "destination": "192.168.61.50",
        "enabled": "true",
        "descr": "Custom Rule"
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
            update_neo4j_dashboard(attacker_ip, "Block Attacker IP by pfsense", "Potential DoS attack detected by the ML Algorithm")
            update_attacker_node(attacker_ip)
            
            # Publish result to Kafka
            publish_action_result(attacker_ip, "Block IP", "success", "Firewall rule applied successfully")
        else:
            print(f"Failed to block IP by pfsense: {response.status_code} - {response.text}")
            # Publish failure result to Kafka
            publish_action_result(attacker_ip, "Block IP", "failure", f"Failed with status code: {response.status_code}")

    except Exception as e:
        print(f"Error while sending request to pfsense: {e}")
        # Publish exception result to Kafka
        publish_action_result(attacker_ip, "Block IP", "error", str(e))


def get_attacker_ip(playbook_data=None):
    """
    Extract attacker IP from the playbook data received via Kafka.
    If no playbook_data is provided, return a static IP for backward compatibility.
    """
    if playbook_data is None:
        # Return static IP for backward compatibility (testing purposes)
        return "192.168.61.57"
    
    try:
        # Look for external_references in the playbook
        external_refs = playbook_data.get("external_references", [])
        
        for ref in external_refs:
            # Check if this reference contains objects 
            if ref.get("type") == "bundle" and "objects" in ref:
                objects = ref.get("objects", [])
                
                # Look for ipv4-addr objects
                for obj in objects:
                    if obj.get("type") == "ipv4-addr":
                        # Check if this is the source IP (attacker IP)
                        obj_id = obj.get("id", "")
                        if "src_asset_uuid" in obj_id or obj_id.startswith("ipv4-addr--"):
                            ip_value = obj.get("value")
                            if ip_value:
                                logging.info(f"Extracted attacker IP from playbook: {ip_value}")
                                return ip_value
        
        # If no IP found in external_references, log warning and return None
        logging.warning("No attacker IP found in playbook external_references")
        return None
        
    except Exception as e:
        logging.error(f"Error extracting attacker IP from playbook: {e}")
        return None

def print_event_handler_message():
    cleanup_neo4j_dashboard()
    start_detection_time = time.time()  # Start timing
    time.sleep(7)  # Wait for 7 seconds
    print("[EVENT HANDLER] Potential Denial of Service (DoS) attack detected by the ML Algorithm.")
    time_taken_detection = time.time() - start_detection_time  # Calculate time taken
    logging.info(f"DDoS Attack Detection Time: {time_taken_detection:.6f} seconds")

    print("[ORCHESTRATOR] Waiting for Playbook via Kafka")

def publish_action_result(attacker_ip, action, status, details):
    """
    Publish action result to Kafka result topic
    """
    try:
        # Create producer if not exists
        producer = create_kafka_producer()
        
        # Get the current timestamp
        cest_tz = pytz.timezone('Europe/Berlin')
        timestamp = datetime.now(cest_tz).strftime("%Y-%m-%d %H:%M:%S")
        
        # Create the result payload
        result_payload = {
            "action": action,
            "target_ip": attacker_ip,
            "status": status,
            "details": details,
            "timestamp": timestamp
        }
        
        # Send the result to Kafka
        producer.send(RESULT_TOPIC, result_payload)
        producer.flush()
        logging.info(f"Published action result to Kafka topic {RESULT_TOPIC}")
    except Exception as e:
        logging.error(f"Error publishing action result to Kafka: {e}")

if __name__ == '__main__':
    # Start the thread to print the event handler message
    threading.Thread(target=print_event_handler_message).start()
    
    # Start Kafka consumer thread
    kafka_consumer_thread = start_kafka_consumer()

    # Keep the main thread running
    kafka_consumer_thread.join()