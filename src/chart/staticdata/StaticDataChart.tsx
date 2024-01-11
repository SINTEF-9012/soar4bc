import React, { useEffect, useState } from 'react';
import { ChartProps } from '../Chart';
import { generateCypher } from '../../openai/TextToCypher';
import axios from 'axios'; // HTTP client

/**
 * Renders Neo4j records as their JSON representation.
 */

const StaticDataChart = (props: ChartProps) => {
  //const { generated, setGenerated } = useState(0);

  const { records, settings, getGlobalParameter } = props;
  const node = records && records[0] && records[0]._fields && records[0]._fields[0] ? records[0]._fields[0] : {};
  const [url, setUrl] = useState('');
  const endpoint = node.properties['endpoint']
  const type = node.properties['type']
  const filename = endpoint + '.' + type; // Add extension to name

  const fetchUrl = () => {
    // Existing code to fetch the URL
    const httpString = 'http://localhost:5000/minio_get_url?file_name=' + filename;
    axios.get(httpString)
      .then((response) => {
        const apiUrl = response.data.url;
        setUrl(apiUrl);  // This will trigger the useEffect listening to `url`
      })
      .catch((error) => {
        console.error('Error fetching URL:', error);
      });
  };

  useEffect(() => {
    // Fetch the URL when the component mounts
    fetchUrl();
  }, [endpoint]);

  useEffect(() => {
    const fetchAndUpdateUrl = async () => {
      try {
        // Update the URL in the Neo4J graph
        if (url) {
          await axios.post('http://localhost:5001/update_url', {
            node_endpoint: endpoint,  // Replace with actual node name
            url: url
          });
          console.log('Node updated with URL:', url);
        }
      } catch (error) {
        console.error('Error in fetchAndUpdateUrl:', error);
      }
    };
    // TODO: Change according to time expire date:
    if (endpoint) {
      fetchAndUpdateUrl();
    }
  }, [url, endpoint]); // Re-run when `endpoint` and 'url' changes

  return ( 
    <div style={{ marginTop: '0px', height: '100%', textAlign: 'center'}}>
      <p style={{ fontSize: '18px' }}> Click to download PCAP: </p>
      {url && <a href={url} target="_blank" rel="noopener noreferrer"><button style={{ fontSize: '18px', padding: '10px 20px' }}>Download</button></a>}
    </div>
  );
};

export default StaticDataChart;

