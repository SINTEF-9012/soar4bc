import React, { useEffect, useState } from 'react';
import { ChartProps } from '../Chart';
import { generateCypher } from '../../openai/TextToCypher';
import axios from 'axios'; // HTTP client

/**
 * Renders Neo4j records as their JSON representation.
 */

const AnalyticsChart = (props: ChartProps) => {
  //const { generated, setGenerated } = useState(0);
  const { records, settings, getGlobalParameter } = props;
  const node = records && records[0] && records[0]._fields && records[0]._fields[0] ? records[0]._fields[0] : {};
  const name = node.properties['name'] // Obs. We use name as identifier - TODO: use something else
  const [inputText, setInputText] = useState('');
  const [endpoint, setEndpoint] = useState('');
  const [type, setType] = useState('');
  const [resultText, setResultText] = useState('');
  // const [url, setUrl] = useState(''); 

  const handleInputChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setInputText(event.target.value);
  };

  const handleSubmit = async () => {
    
    try {
      // Store user input in Neo4J:
      const updateTaskResponse = await axios.post('http://localhost:5001/update_task', {
        node_name: name,
        task: inputText
      });
  
      // If the task update is successful, call the analytics API to generate code:
      if (updateTaskResponse.status === 200) {
        const codeResponse = await axios.get(`http://localhost:5002/generate_code`, {
          params: { task: inputText }
        });
        const generatedCode = codeResponse.data.code;
        const generatedLib = codeResponse.data.lib;

        // Store generated code/libraries in Neo4J:
        try {
          const updateCodeResponse = await axios.post('http://localhost:5001/update_code', {
            node_name: name,
            code: generatedCode
          });
          const updateLibResponse = await axios.post('http://localhost:5001/update_lib', {
            node_name: name,
            lib: generatedLib
          });

          // If the code and lib update is successful, call the analytics API to download data and then run generated code:
          if (updateCodeResponse.status === 200 && updateLibResponse.status === 200) {
            // Fetch the endpoint of the static node linked to current node:
            try {
              const response = await axios.post('http://localhost:5001/fetch_endpoint', { node_name: name});
              setEndpoint(response.data.toString()); // Assuming response data is the endpoint
              console.log('Fetched following endpoint from static node:', endpoint);
              } catch (error) {
              console.error('Failed fetching endpoint from static node:', error);
            }
            // Fetch the type of the static node linked to current node:
            try {
              const response = await axios.post('http://localhost:5001/fetch_type', { node_name: name});
              setType(response.data.toString()); // Assuming response data is the endpoint
              console.log('Fetched following type from static node:', type);
              } catch (error) {
              console.error('Failed fetching type from static node:', error);
            }
            // Download data using endpoint in Minio database:
            const filename = endpoint + '.' + type;
            console.log('Downloading data for ', filename);
            const httpString = 'http://localhost:5000/minio_download?file_name=' + filename;
            axios.get(httpString).then((response) => { const apiStatus = response.data.status;
                                                      console.log('Download status:', apiStatus);
                                                     }).catch((error) => {console.error('Failed to download data:', error);});
            console.log('Running generated code ...');
            const runResponse = await axios.get(`http://localhost:5002/run_code`, {params: {code: generatedCode, lib: generatedLib}});
            // Save in local (card) variable:
            setResultText(runResponse.data.response);
            // Store the result from running code in Neo4J:
            const updateResultResponse = await axios.post('http://localhost:5001/update_result', {node_name: name, result: runResponse.data.response});
            console.log('Status for updating result:', updateResultResponse.status);
          } else {
            // Handle unsuccessful update for code/lib:
            console.error('Failed to update code and lib. Status for updating code in Neo4J:', updateCodeResponse.status);
            console.error('Failed to update code and lib. Status for updating lib in Neo4J:', updateLibResponse.status);
          }
        } catch (error) {
          console.error('Error updating code in Neo4J:', error);
          alert('Failed to update code in Neo4J.');
        }
      } else {
        // Handle unsuccessful task update response
        console.error('Failed to update task:', updateTaskResponse.status);
        alert('Failed to update task in Neo4J.');
      }
    } catch (error) {
      console.error('Failed in processing task:', error);
      alert('Failed to process task.');
    }
  };

  return (
    <div style={{ marginTop: '20px', height: 'auto', textAlign: 'center', padding: '20px' }}>
      <p style={{ fontSize: '18px' }}>Describe the task in natural language:</p>
      <textarea
        value={inputText}
        onChange={handleInputChange}
        placeholder="Example: I want the number of unique IP addresses."
        style={{ width: '100%', height: '250px', fontSize: '18px', padding: '12px', margin: '10px auto', display: 'block',  border: '1px solid black' }}
      />
      <button
        onClick={handleSubmit}
        style={{
          width: '100px',
          height: '60px',
          fontSize: '20px',
          padding: '12px 20px',
          marginTop: '15px',
          marginBottom: '15px',
          cursor: 'pointer',
          display: 'block',
          margin: 'auto'
        }}
      >
        Solve
      </button>
  
      {/* Result display area */}
      <p style={{ fontSize: '18px' }}>Result:</p>
      <div style={{ marginTop: '20px', textAlign: 'left', border: '1px solid black', minHeight: '250px', padding: '12px', width: '100%', margin: '10px auto',  fontSize: '18px'}}>
        <div style={{ whiteSpace: 'pre-wrap' }}>{resultText}</div>
      </div>
    </div>
  );
  
};

export default AnalyticsChart;

