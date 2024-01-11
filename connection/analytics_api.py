from flask import Flask, request, jsonify
from CogniGPT.gpt.api import generate_code
import io
import sys

app = Flask(__name__)

# Define a function to set the CORS headers
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = 'http://localhost:3000'  # allowed origin
    response.headers['Access-Control-Allow-Methods'] = 'GET'  # Adjust as needed
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

# Apply the CORS function to all routes using the after_request decorator
@app.after_request
def apply_cors(response):
    return add_cors_headers(response)

@app.route('/generate_code', methods=['GET'])
def generate():
    task = request.args.get('task')
    wrapped_task = wrap(task)
    print("Received request to generate code based on task:", wrapped_task)
    code_and_lib = generate_code(wrapped_task)
    code = code_and_lib["code"]
    lib = code_and_lib["lib"]
    # Return the output as JSON:
    response_content = {'code': code, 'lib': lib}
    return jsonify(response_content)

@app.route('/run_code', methods=['GET'])
def run():
    code = request.args.get('code')
    lib = request.args.get('lib') 
    print(f"Received request to run code. Installing following libraries: {lib}")
    response = run_code(code, lib)
    # Return the output as JSON:
    response_content = {'response': response}
    return jsonify(response_content)

def wrap(task : str):
    '''
        Wraps task with additional information about file position and context. 
    Args:
        task (str) : Task given by user in string form
    '''
    # TODO: To achieve better results, update the oracle in CogniGPT/cognigpt/gpt/api.py.
    wrapped_task = '''I have the following task:  ' ''' + task  + ''' '. If the task is not related to processing PCAP files, generate a function called ignore_pcap that prints None, and does nothing else.
                    Otherwise, assume I have a PCAP file on path ./temp/sample.pcap and generate a function that first reads the file on the given path (using dpkt), solves
                    the task, and prints the results. Make sure to include one line of code to call to the function directly, do not use the __main__ segment. '''
    return wrapped_task


def run_code(code, lib):
    # TODO: Change oracle so that the libraries are listed in a "pip install <lib>" format or change extract_code. For now, we ignore lib, and manually install in env via poetry instead.
    # TODO: Change to safer approach that does not have a risk for code injection.
    # Create a StringIO object to capture output
    output_buffer = io.StringIO()
    # Save the current stdout so that we can restore it later
    original_stdout = sys.stdout
    # Redirect stdout to the buffer
    sys.stdout = output_buffer
    scope = {}
    exec(code, scope)
    # Restore the original stdout
    sys.stdout = original_stdout
    # Get the content of the buffer
    output = output_buffer.getvalue()
    # Close the buffer
    output_buffer.close()
    return output

if __name__ == '__main__':
    app.run(host="localhost", port=5002)
