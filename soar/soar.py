from firewall_service import Firewall_Service
from access_service import Access_Service
from event_handler import Event_Handler
from data_processor import Data_Processor
from orchestrator import Orchestrator
from action_automator import Action_Automator
from digital_twin import Digital_Twin

import json
import time
import requests
import sys
from threading import Thread
from threading import Event

# SOAR Class that runs the SOAR system.
class Soar:
    def __init__(self, ip):
        firewall = Firewall_Service(ip)
        access = Access_Service(ip)
        event_handler = Event_Handler(ip)
        data_processor = Data_Processor()
        orchestrator = Orchestrator()
        action_automator = Action_Automator(firewall, access)

        # Initialize tools on test bed:
        try: 
            firewall.enable_all_communication()
            access.enable_access_rules()
        except (KeyboardInterrupt, requests.exceptions.RequestException) as e:
            print(e)
            print("[ERORR] No Connection to Mininet Firewall or OPA")
            sys.exit()

        # Clean up old data from database:
        try: 
            url = "http://localhost:7474/db/neo4j/tx/commit"
            data = {"statements":[
                    {"statement":"MATCH ()-[r:QUARANTINE]->() DELETE r"}, # Delete old components in quarantine
                    {"statement":"MATCH ()-[r:DATA]->(n:Digital_Twin) DELETE r, n"}, # Delete old Digital Twin data
                    {"statement":"MATCH (s:SOAR)-[r:RESPONSE]->(resp:RESPONSE) DELETE s, r, resp"}]} # Delete old SOAR responses
            response = requests.post(url, auth=('neo4j', 'sindit-neo4j'), json=data)
            print(response)
        except (KeyboardInterrupt, requests.exceptions.RequestException) as e:
            print(e)
            print("[ERROR] No Connection to Neo4j database")
            sys.exit()

        # Set up run event for threads
        run_event = Event()
        run_event.set()

        # Set up the digital twin threads
        digital_twin = Digital_Twin(ip, run_event, orchestrator, action_automator)
        thread1 = Thread(target=digital_twin.data_reception) # seperate thread for digital twin
        thread1.start()
        thread2 = Thread(target=digital_twin.incident_handler) # another thread for digital twin
        thread2.start()

        # Infinite loop for the SOAR
        while True:
            try:
                response = event_handler.check_events()
                if response == 0: # no response
                    #time.sleep(1) # Comment this part out for real-time
                    continue
                else:
                    processed_data = data_processor.interpret_event_data(response)
                    for ip, reason, value in processed_data:
                            response = orchestrator.get_playbook_rule(ip, reason, value, "IDS")
                            action_automator.automate_plan(ip, response)

            except (KeyboardInterrupt):
                # Clear the event and join the threads to exit the program
                print("Initiating Clean Exit of Program")
                run_event.clear()
                thread1.join()
                thread2.join()
                sys.exit()
            except (requests.exceptions.RequestException):
                print("Connection refused by the server...")
                print("Retrying in 5 seconds...")

                try:
                    time.sleep(5)
                except (KeyboardInterrupt):
                    # Clear the event and join the threads to exit the program
                    print("Initiating Clean Exit of Program")
                    run_event.clear()
                    thread1.join()
                    thread2.join()
                    sys.exit()
                continue

# Add Mininet IP Address from CLI
if len(sys.argv) == 1:
    print("ERROR: Please provide Mininet IP Address.")
    print("How to run: python soar.py <mininet_ip>")
    sys.exit()

ip = sys.argv[1]
soar = Soar(ip)