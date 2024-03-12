import json
import requests

class Orchestrator:
    def __init__(self):
        self.id = 1 # Keeping track of IDs for SOAR Responses
    
    # Simple creation of a plan based on data retrieved
        # Address: IP Address of the IoT Device
        # Reason: Processed reason by the Data Processor
        # Value: Value of the data
        # Source: Source where the capture of data originated from (ex IDS or Digital Twin)
    def get_playbook_rule(self, address, reason, value, source):
        print("[ORCHESTRATOR] Getting Playbook Rule")

        playbook = json.load(open('playbook.json'))

        for rule in playbook['Playbook Rules']:
            if rule['Type'] == reason:
                
                url = "http://localhost:7474/db/neo4j/tx/commit"
                # Update dashboard
                data = {"statements":[
                    {"statement":"CREATE (soar:SOAR)-[:RESPONSE]->(response:RESPONSE{soar_id:$soar_id, ip:$ip, reason:$reas, response:$resp, value:$value, source:$source})",
                    "parameters":{"soar_id":self.id, "ip": address, "reas":rule['Type'], "resp":rule['Response'], "value":value, "source":source}}]}
                response = requests.post(url, auth=('neo4j', 'sindit-neo4j'), json=data)

                self.id = self.id + 1 # update id by 1

                return rule['Response'] # return the response

