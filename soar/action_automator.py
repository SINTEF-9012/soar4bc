import requests
from data_processor import Data_Processor

class Action_Automator:

    def __init__(self, firewall, access):
        self.firewall = firewall
        self.access = access
        self.data_processor = Data_Processor()

    # Automate the plan based on the orchestrated response
    def automate_plan(self, address, response):
        print("[ACTION AUTOMATOR] Automating Response, Updating Dashboard")
        
        url = "http://localhost:7474/db/neo4j/tx/commit"

        if response == "Disable Communication":
            self.firewall.disable_communication(address)

            # Update dashboard
            data = {"statements":[
                {"statement":"MATCH (host:Component{ip:$ip}), (quarantine:Quarantine{name:$name}) CREATE (host)-[:QUARANTINE]->(quarantine)",
                 "parameters":{"ip": address, "name":"Quarantine"}}]}
            requests.post(url, auth=('neo4j', 'sindit-neo4j'), json=data)

        if response == "Update Access Service":
            # Just a hack for now, but whenever we want to update access service, the address variable
            # holds the playbook reason, which we can use here
            rule = self.data_processor.interpret_playbook_data(address)
            self.access.update_access_rule(rule)