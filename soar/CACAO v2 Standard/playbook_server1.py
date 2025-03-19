from flask import Flask, request, jsonify

app = Flask(__name__)

playbook_data = []

def extract_action_and_name(data):
    action_name = None
    name = None

    if isinstance(data, dict):
        # Check if 'actions' and 'name' keys exist in the dictionary
        if 'actions' in data and 'name' in data:
            for action in data['actions']:
                if action.get('action_name') == 'Block IP':
                    action_name = action['action_name']
                    name = data['name']
                    break
        else:
            # If keys are not found, recursively search in the values
            for value in data.values():
                action_name, name = extract_action_and_name(value)
                if action_name is not None and name is not None:
                    break

    elif isinstance(data, list):
        # If data is a list, iterate through its elements
        for item in data:
            action_name, name = extract_action_and_name(item)
            if action_name is not None and name is not None:
                break

    return action_name, name

@app.route('/update_playbook', methods=['POST'])
def update_playbook():
    global playbook_data
    
    if request.method == 'POST':
        data = request.json
        
        print("Received JSON data:")
        #print(data)
        
        action_name, name = extract_action_and_name(data)
        
        if action_name and name:
            playbook_data.append({"action_name": action_name, "name": name})
        
        print("Received playbook rules:")
        for rule in playbook_data:
            print(rule)
        
        return 'JSON received!'

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=4005)
