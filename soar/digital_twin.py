import requests
import time
import sys
from collections import deque

from data_processor import Data_Processor
from threading import Semaphore
from orchestrator import Orchestrator
from action_automator import Action_Automator

# This Digital Twin should not be considered as a true implementation.
# It receives data from the Shark IDS due to ease of implementation,
# as getting it directly from the Mininet gateway would require NAT configuration which got a bit messy.

# There is also no true MQTT/OPC-UA implementation done in this project,
# which the Digital Twin would receive information from in a real-world scenario.

class Digital_Twin:

    def __init__(self, ip, run_event, orchestrator, action_automator):
        self.ip = ip # IP address of the Mininet server
        self.length = 0 # keeping track of length to know when new events get added
        self.run_event = run_event # Run event for clean exiting of threads
        self.semaphore = Semaphore(0) # Semaphore synchronization for the two threads running in this class

        self.data_processor = Data_Processor() # Data processor for data processing
        self.orchestrator = orchestrator # Orchestrator object
        self.action_automator = action_automator # Action Automator object

        # Keep track of IDs for each host
        self.identification = [{"10.0.0.3":1}, {"10.0.0.4":1}, {"10.0.0.5":1}, {"10.0.0.6":1}, {"10.0.0.7":1}, {"10.0.0.8":1}]

        # Keep track of IP and value of data within the Digital Twin
        # We use a deque as this is thread-safe for pops from the left and appends from the right
        self.data_queue = deque()

        # A simple hack for not getting false positives for when the IDS already knows of the issue
        # This variable could be dynamically updated based on the information in policies.rego
        # But for simulating the data this works just fine
        self.ids_tracker = ["No Value"]


    # This method retrieves information about the physical twin and saves it to the database
    def data_reception(self):
        while self.run_event.is_set():
            try:
                response = requests.get(f'http://{self.ip}:8001/digital_twin')
                data = response.json()
                
                if len(data) > self.length: # Then we have received new data
                    leng = self.length
                    self.length = len(data)

                    url = "http://localhost:7474/db/neo4j/tx/commit"

                    for info in data[leng:]:
                        for ip, value in info.items():

                            # Get ID and update it
                            dt_id = 0
                            for d in self.identification:
                                for key, id in d.items():
                                    if key == ip:
                                        dt_id = id
                                        d.update({key:id+1})
                                        break

                            # Update dashboard
                            db_data = {"statements":[
                                {"statement":"MATCH (host:Component{ip:$ip}) CREATE (host)-[:DATA]->(digital_twin:Digital_Twin{dt_id:$dt_id, ip:$ip, data:$data_var})",
                                "parameters":{"dt_id":dt_id, "ip": ip, "data_var":value}}]}
                            response = requests.post(url, auth=('neo4j', 'sindit-neo4j'), json=db_data)

                            # Add the data to the queue for the secondary thread
                            self.data_queue.append({ip:value})
                            self.semaphore.release()

            except (requests.exceptions.RequestException) as e:
                print("Digital Twin lost connection to server...")
                print("Retrying in 5 seconds...")
                time.sleep(5)
                continue


    # This method processes the digital twin data to check for incidents
    def incident_handler(self):
        while self.run_event.is_set():
            # Try and acquire a semaphore ticket, this will happen whenever new data gets added from the other thread
            sema = self.semaphore.acquire(timeout=1)
            if not sema:
                continue

            # Get data from the queue
            value = self.data_queue.popleft()

            # Process the data
            result = self.data_processor.interpret_event_data([value])

            # If there is no problem with the value, we do nothing with the result and continue to the next
            if result[0][1] == "OK Value":
                continue

            # Check if IDS already knows of this issue, in this case this is a false positive
            if result[0][1] in self.ids_tracker:
                continue

            # Do two things with the result, first fix the missing access control,
            # and then deploy fix on the data violation
            for ip, reason, value in result:
                self.ids_tracker.append(reason) # Add the reason to our list to avoid future false positives
                
                response = self.orchestrator.get_playbook_rule(ip, "Missing Access Control", "AC Fix", "Digital Twin")
                self.action_automator.automate_plan(reason, response)
                response = self.orchestrator.get_playbook_rule(ip, reason, value, "Digital Twin")
                self.action_automator.automate_plan(ip, response)

