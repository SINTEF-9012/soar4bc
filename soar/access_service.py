import requests

class Access_Service:
    def __init__(self, ip):
        self.ip = ip

    # Enable access rules based on predefined policies
    def enable_access_rules(self):
        policies = open('policies.rego').read()
        response = requests.put(f'http://{self.ip}:8181/v1/policies/access_policies', data=policies)
        #response = requests.get(f'http://{self.ip}:8181/v1/policies')
        print(response.text)

    # Update access rules, in a real deployment, we would want to save the changes to the policies.rego file as well,
    # but since this is just simulation, we won't do that
    def update_access_rule(self, rule):
        policies = open('policies.rego').read()
        policies += "\n\nviolation[packet.data] {\n\tpacket := input.packet\n \tpacket.data " + rule + "\n}"

        response = requests.put(f'http://{self.ip}:8181/v1/policies/access_policies', data=policies)
