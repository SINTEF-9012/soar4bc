from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/update_playbook', methods=['POST'])
def process_json():
    json_data = request.json  # Assuming the data is sent as JSON in the request body
    
    try:
        condition = json_data['workflow']['if-condition--9c654f27-a3ff-4f12-8502-853e2c5c17a5']['condition']
        name = json_data['workflow']['playbook-action--80dda560-21a0-4157-85e9-d93be5e6a1da']['name']
        print("Condition:", condition)
        print("Name:", name)
        return 'JSON Received!'
    except KeyError as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, port=4005)
