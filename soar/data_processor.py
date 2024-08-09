

class Data_Processor:

    # Simple method, just interpreting integer data
    def interpret_event_data(self, data):
              
        interpreted_data = []
        for info in data:
            for ip, value in info.items():
                int_value = int(value)

                new_value = ""
                
                if int_value == 90:
                    new_value = "No Value"

                elif int_value < 0:
                    new_value = "Negative Value"

                elif int_value >= 10000:
                    new_value = "Value Too Big"

                else:
                    new_value = "OK Value"

                interpreted_data.append((ip, new_value, value))
                    
        
        return interpreted_data
    
    # Reversing the data
    def interpret_playbook_data(self, data):

        value = None

        match data:
            case "No Value":
                value = "== 0"
            case "Negative Value":
                value = "< 0"
            case "Value Too Big":
                value = ">= 10000"
                    
        
        return value