import requests

# This class is an infinite loop that will check for event updates from interface(s)
class Event_Handler:
    def __init__(self, ip):
        self.ip = ip
        self.length = 0 # keeping track of length to know when new events get added

    def check_events(self):
        response = requests.get(f'http://{self.ip}:8000/events')
        data = response.json()
        
        if len(data) > self.length: # Then we have received new data
            print("[EVENT HANDLER] New Data Captured")
            
            leng = self.length
            self.length = len(data)
            return data[leng:]

        return 0 # no new data
