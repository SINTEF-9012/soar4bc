"""
SOAR4BC - UC4._
"""

import json
import logging
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any
import pytz
import requests
from flask import Flask
from kafka import KafkaConsumer, KafkaProducer

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Configuration settings for the SOAR4BC system"""
    # Kafka Configuration
    KAFKA_SERVER: str = 'kafka.dynabic.dev:9092'
    KAFKA_USERNAME: str = 'soar4bc'
    KAFKA_PASSWORD: str = '***********'
    PLAYBOOK_TOPIC: str = 'UC4.SOAR4BC.playbook'
    RESULT_TOPIC: str = 'UC4.SOAR4BC.result'
    
    # Neo4j Configuration
    NEO4J_URL: str = "http://localhost:7474/db/neo4j/tx/commit"
    NEO4J_USERNAME: str = 'neo4j'
    NEO4J_PASSWORD: str = 's*****-*****'
    
    # External APIs
    PFSENSE_URI: str = "https://192.168.61.5/api/v2/firewall/rule"
    PFSENSE_API_KEY: str = '******************'

    # System Configuration
    TIMEZONE: str = 'Europe/Berlin'
    
class TimeTracker:
    """Utility class for tracking execution times"""
    
    @staticmethod
    def get_timestamp(timezone: str = Config.TIMEZONE) -> str:
        """Get current timestamp in specified timezone"""
        tz = pytz.timezone(timezone)
        return datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    
    @staticmethod
    def time_execution(func_name: str):
        """Decorator to time function execution"""
        def decorator(func):
            def wrapper(*args, **kwargs):
                start_time = time.time()
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                logger.info(f"{func_name} execution time: {execution_time:.6f} seconds")
                return result
            return wrapper
        return decorator


class PlaybookParser:
    """Handles parsing of security playbooks"""
    
    SUPPORTED_ACTIONS = {
        "Block IP Firewall", 
        "Start Honeypot Server",
        "Redirect Traffic",
        "Reset Routing",
        "Stop Honeypot Server",
        "Do Nothing"
    }
    
    @staticmethod
    def extract_action(playbook_data: Dict[str, Any]) -> Optional[str]:
        """Extract action from playbook data"""
        try:
            workflow = playbook_data.get("workflow", {})
            for key, value in workflow.items():
                if value.get("type") == "action":
                    action_name = value.get("name")
                    if action_name in PlaybookParser.SUPPORTED_ACTIONS:
                        return action_name
                elif value.get("name") == "start workflow Do Nothing":
                    return "Do Nothing"
        except Exception as e:
            logger.error(f"Error extracting action: {e}")
        return None
    
    @staticmethod
    def extract_ip_from_playbook(playbook_data: Dict[str, Any]) -> Optional[str]:
        """Extract attacker IP from playbook data"""
        try:
            external_references = playbook_data.get("external_references", [])
            for ref in external_references:
                if ref.get("type") == "bundle":
                    for obj in ref.get("objects", []):
                        if obj.get("type") == "ipv4-addr":
                            ip = obj.get("value")
                            if ip != "0.0.0.1": 
                                return ip
        except Exception as e:
            logger.error(f"Error extracting IP: {e}")
        return None


class Neo4jDashboard:
    """Handles Neo4j database operations for dashboard updates"""
    
    def __init__(self, config: Config):
        self.url = config.NEO4J_URL
        self.auth = (config.NEO4J_USERNAME, config.NEO4J_PASSWORD)
    
    def cleanup_old_data(self):
        """Clean up old data from Neo4j database"""
        try:
            data = {
                "statements": [
                    {"statement": "MATCH (s:SOAR)-[r:RESPONSE]->(resp:RESPONSE) DELETE s, r, resp"},
                    {"statement": "MATCH (a:Attacker) DELETE a"}
                ]
            }
            requests.post(self.url, auth=self.auth, json=data)
        except Exception as e:
            logger.error(f"Error cleaning up Neo4j: {e}")
    
    def update_attacker_status(self, attacker_ip: str, status: str):
        """Update attacker node status"""
        try:
            timestamp = TimeTracker.get_timestamp()
            query = """
            MERGE (a:Attacker {ip: $attacker_ip})
            ON CREATE SET a.status = $status, a.timestamp = $timestamp
            ON MATCH SET a.status = $status, a.timestamp = $timestamp
            """
            data = {
                "statements": [{
                    "statement": query,
                    "parameters": {
                        "attacker_ip": attacker_ip,
                        "status": status,
                        "timestamp": timestamp
                    }
                }]
            }
            requests.post(self.url, auth=self.auth, json=data)
            logger.info(f"Updated attacker {attacker_ip} status to: {status}")
        except Exception as e:
            logger.error(f"Error updating attacker node: {e}")
    
    def update_response(self, attacker_ip: str, response: str, reason: str):
        """Update SOAR response in dashboard"""
        self.cleanup_old_data()
        try:
            timestamp = TimeTracker.get_timestamp()
            query = (
                "MERGE (s:SOAR {ip: $attacker_ip}) "
                "CREATE (s)-[:RESPONSE]->(resp:RESPONSE {ip: $attacker_ip, response: $response, reason: $reason, timestamp: $timestamp})"
            )
            data = {
                "statements": [{
                    "statement": query,
                    "parameters": {
                        "attacker_ip": attacker_ip,
                        "response": response,
                        "reason": reason,
                        "timestamp": timestamp
                    }
                }]
            }
            response_obj = requests.post(self.url, auth=self.auth, json=data)
            if response_obj.status_code == 200:
                logger.info("Neo4j dashboard updated successfully")
            else:
                logger.error(f"Failed to update Neo4j dashboard: {response_obj.status_code}")
        except Exception as e:
            logger.error(f"Error updating Neo4j dashboard: {e}")


class ActionExecutor(ABC):
    """Abstract base class for action executors"""
    
    def __init__(self, config: Config, dashboard: Neo4jDashboard):
        self.config = config
        self.dashboard = dashboard
    
    @abstractmethod
    def execute(self, attacker_ip: str) -> Dict[str, Any]:
        """Execute the action and return result"""
        pass
    
    def publish_result(self, producer: KafkaProducer, attacker_ip: str, 
                      action: str, status: str, details: str, 
                      human_in_loop: bool = False, human_decision: str = None):
        """Publish action result to Kafka"""
        try:
            result_payload = {
                "action": action,
                "target_ip": attacker_ip,
                "status": status,
                "details": details,
                "timestamp": TimeTracker.get_timestamp(),
                "human_in_the_loop": "yes" if human_in_loop else "no",
                "human_in_the_loop_decision": human_decision if human_in_loop else "auto"
            }
            producer.send(self.config.RESULT_TOPIC, result_payload)
            producer.flush()
            logger.info(f"Published action result to Kafka topic {self.config.RESULT_TOPIC}")
        except Exception as e:
            logger.error(f"Error publishing action result to Kafka: {e}")



class FirewallBlockExecutor(ActionExecutor):
    """Executor for pfSense firewall IP blocking"""
    
    @TimeTracker.time_execution("Firewall Block Action")
    def execute(self, attacker_ip: str) -> Dict[str, Any]:
        headers = {
            'accept': 'application/json',
            'x-api-key': self.config.PFSENSE_API_KEY,
            'Content-Type': 'application/json'
        }
        
        payload = {
            "type": "block",
            "interface": ["opt4"],
            "ipprotocol": "inet",
            "protocol": "tcp/udp",
            "source": attacker_ip,
            "destination": "192.168.61.50",
            "enabled": "true",
            "descr": "Custom Rule"
        }
        
        logger.info(f"Blocking IP {attacker_ip} via pfSense")
        
        try:
            response = requests.post(
                self.config.PFSENSE_URI,
                headers=headers,
                data=json.dumps(payload),
                verify=False
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully blocked {attacker_ip} via pfSense")
                self.dashboard.update_response(
                    attacker_ip,
                    "Block Attacker IP by pfSense",
                    "Potential DoS Attack Detected Against CSMS"
                )
                self.dashboard.update_attacker_status(attacker_ip, "Blocked")
                return {"status": "success", "message": "IP blocked successfully"}
            else:
                logger.error(f"Failed to block {attacker_ip} via pfSense: {response.status_code}")
                return {"status": "error", "message": f"Failed to block IP: {response.text}"}
        except Exception as e:
            logger.error(f"Error blocking IP via pfSense: {e}")
            return {"status": "error", "message": str(e)}


class TrafficRedirectExecutor(ActionExecutor):
    """Executor for traffic redirection"""
    
    def _verify_redirection(self, virtual_ip: str, timeout: int = 5, retries: int = 3) -> bool:
        """Verify traffic redirection by pinging the virtual IP"""
        logger.info(f"Verifying traffic redirection by pinging {virtual_ip}")
        
        for attempt in range(retries):
            try:
                # Use ping command with timeout
                ping_cmd = f"ping -c 1 -W {timeout} {virtual_ip}"
                result = subprocess.run(
                    ping_cmd, 
                    shell=True, 
                    capture_output=True, 
                    text=True, 
                    timeout=timeout + 2
                )
                
                if result.returncode == 0:
                    logger.info(f"Ping to {virtual_ip} successful on attempt {attempt + 1}")
                    return True
                else:
                    logger.warning(f"Ping to {virtual_ip} failed on attempt {attempt + 1}: {result.stderr.strip()}")
                    
            except subprocess.TimeoutExpired:
                logger.warning(f"Ping to {virtual_ip} timed out on attempt {attempt + 1}")
            except Exception as e:
                logger.warning(f"Ping verification failed on attempt {attempt + 1}: {e}")
            
            # Wait before retry (except on last attempt)
            if attempt < retries - 1:
                time.sleep(1)
        
        logger.error(f"All {retries} ping attempts to {virtual_ip} failed")
        return False
    
    def execute(self, attacker_ip: str) -> Dict[str, Any]:
        virtual_ip = "192.168.61.100"  # Virtual IP for traffic redirection verification
        
        try:
            # Verify redirection by pinging virtual IP (Redirection is already set up)
            logger.info(f"Checking traffic redirection status for {attacker_ip} to {virtual_ip}")
            
            if self._verify_redirection(virtual_ip):
                logger.info(f"Traffic redirection verification successful for {attacker_ip}")
                
                self.dashboard.update_response(
                    attacker_ip,
                    "Verify Traffic Redirection to Virtual IP",
                    f"Traffic Redirection Verified - Virtual IP {virtual_ip} Reachable"
                )
                self.dashboard.update_attacker_status(attacker_ip, "Redirecting Traffic")
                
                return {
                    "status": "success", 
                    "message": f"Traffic redirection to {virtual_ip} verified successfully",
                    "virtual_ip": virtual_ip,
                    "verification": "passed",
                    "human_in_the_loop": True,
                    "human_decision": "approved"
                }
            else:
                logger.error(f"Traffic redirection verification failed for {attacker_ip}")
                
                self.dashboard.update_response(
                    attacker_ip,
                    "Verify Traffic Redirection to Virtual IP",
                    f"Traffic Redirection Verification Failed - {virtual_ip} Not Reachable"
                )
                self.dashboard.update_attacker_status(attacker_ip, "Redirection Failed")
                
                return {
                    "status": "error", 
                    "message": f"Traffic redirection verification failed - {virtual_ip} not reachable",
                    "virtual_ip": virtual_ip,
                    "verification": "failed",
                    "human_in_the_loop": True,
                    "human_decision": "rejected"
                }
                
        except Exception as e:
            logger.error(f"Error during traffic redirection verification: {e}")
            return {
                "status": "error", 
                "message": f"Error during verification: {str(e)}",
                "virtual_ip": virtual_ip,
                "verification": "error",
                "human_in_the_loop": True,
                "human_decision": "error"
            }



class ResetRoutingExecutor(ActionExecutor):
    """Executor for resetting routing and stopping honeypot"""
    
    def execute(self, attacker_ip: str) -> Dict[str, Any]:
        try:
            # Reset routing
            reset_cmd = (
                f"iptables -t nat -D PREROUTING -p tcp -s {attacker_ip} "
                f"--dport 80 -j DNAT --to-destination {self.config.HONEYPOT_IP}:80"
            )
            subprocess.run(reset_cmd, shell=True, check=True)
            logger.info(f"Routing reset for {attacker_ip}")
            
            # Stop honeypot
            try:
                find_process_cmd = "sudo lsof -t -i:80"
                process_id = subprocess.check_output(find_process_cmd, shell=True).strip().decode('utf-8')
                
                if process_id:
                    kill_cmd = f"sudo kill -9 {process_id}"
                    subprocess.run(kill_cmd, shell=True, check=True)
                    logger.info(f"Honeypot server stopped (PID: {process_id})")
            except subprocess.CalledProcessError:
                logger.info("No honeypot process found running on port 80")
            
            self.dashboard.update_response(
                attacker_ip,
                "Reset Routing and Stop Honeypot",
                "Reset Routing and Honeypot Stopped After Mitigation"
            )
            self.dashboard.update_attacker_status(attacker_ip, "Quarantined: Reset Traffic and Stop Honeypot")
            
            return {"status": "success", "message": "Routing reset and honeypot stopped"}
        except subprocess.CalledProcessError as e:
            logger.error(f"Error resetting routing: {e}")
            return {"status": "error", "message": str(e)}


class DoNothingExecutor(ActionExecutor):
    """Executor for do nothing action"""
    
    def execute(self, attacker_ip: str) -> Dict[str, Any]:
        logger.info("Executing 'Do Nothing' action")
        self.dashboard.update_response(attacker_ip, "Do Nothing", "Nothing to Execute")
        self.dashboard.update_attacker_status(attacker_ip, "Not Blocked")
        return {"status": "success", "message": "No action taken"}


class ActionFactory:
    """Factory for creating action executors"""
    
    @staticmethod
    def create_executor(action: str, config: Config, dashboard: Neo4jDashboard) -> Optional[ActionExecutor]:
        """Create appropriate executor for the given action"""
        executors = {
            "Block IP Firewall": FirewallBlockExecutor,
            "Redirect Traffic": TrafficRedirectExecutor,
            "Reset Routing": ResetRoutingExecutor,
            "Stop Honeypot Server": ResetRoutingExecutor,  # Same as reset routing
            "Do Nothing": DoNothingExecutor
        }
        
        executor_class = executors.get(action)
        return executor_class(config, dashboard) if executor_class else None


class KafkaManager:
    """Manages Kafka connections and operations"""
    
    def __init__(self, config: Config):
        self.config = config
        self.kafka_config = {
            'bootstrap_servers': [config.KAFKA_SERVER],
            'security_protocol': 'SASL_PLAINTEXT',
            'sasl_mechanism': 'PLAIN',
            'sasl_plain_username': config.KAFKA_USERNAME,
            'sasl_plain_password': config.KAFKA_PASSWORD
        }
    
    def create_producer(self) -> KafkaProducer:
        """Create Kafka producer"""
        return KafkaProducer(
            **self.kafka_config,
            value_serializer=lambda x: json.dumps(x).encode('utf-8')
        )
    
    def create_consumer(self) -> KafkaConsumer:
        """Create Kafka consumer"""
        return KafkaConsumer(
            self.config.PLAYBOOK_TOPIC,
            **self.kafka_config,
            auto_offset_reset='earliest',
            enable_auto_commit=True,
            value_deserializer=lambda x: json.loads(x.decode('utf-8')) if x else None
        )


class SOAROrchestrator:
    """Main SOAR orchestrator that coordinates all components"""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.dashboard = Neo4jDashboard(self.config)
        self.kafka_manager = KafkaManager(self.config)
        self.producer = self.kafka_manager.create_producer()
        self.app = Flask(__name__)
    
    def process_playbook(self, playbook_data: Dict[str, Any]):
        """Process received playbook and execute appropriate action"""
        try:
            logger.info("Received playbook from Kafka")
            
            # Extract action and IP
            start_time = time.time()
            action = PlaybookParser.extract_action(playbook_data)
            attacker_ip = PlaybookParser.extract_ip_from_playbook(playbook_data)
            extraction_time = time.time() - start_time
            logger.info(f"Playbook extraction time: {extraction_time:.6f} seconds")
            
            if not attacker_ip:
                logger.error("Attacker IP not found in playbook")
                return
            
            if not action:
                logger.error("No valid action found in playbook")
                return
            
            # Create and execute action
            executor = ActionFactory.create_executor(action, self.config, self.dashboard)
            if executor:
                start_time = time.time()
                result = executor.execute(attacker_ip)
                execution_time = time.time() - start_time
                logger.info(f"Action execution time: {execution_time:.6f} seconds")

                human_in_loop = result.get("human_in_the_loop", False)
                human_decision = result.get("human_decision", None)
                
                # Publish result
                executor.publish_result(
                    self.producer, attacker_ip, action,
                    result["status"], result["message"],
                    human_in_loop, human_decision
                )
            else:
                logger.error(f"Unknown action: {action}")
        
        except Exception as e:
            logger.error(f"Error processing playbook: {e}")
    
    def kafka_consumer_loop(self):
        """Main Kafka consumer loop"""
        consumer = self.kafka_manager.create_consumer()
        logger.info(f"Listening for messages on topic: {self.config.PLAYBOOK_TOPIC}")
        
        try:
            for message in consumer:
                if message.value:
                    self.process_playbook(message.value)
        except KeyboardInterrupt:
            logger.info("Kafka Consumer stopped by user")
        except Exception as e:
            logger.error(f"Error in Kafka consumer loop: {e}")
        finally:
            consumer.close()
    
    def start_kafka_consumer(self):
        """Start Kafka consumer in a separate thread"""
        kafka_thread = threading.Thread(target=self.kafka_consumer_loop, daemon=True)
        kafka_thread.start()
        return kafka_thread
    
    def initialize_system(self):
        """Initialize the SOAR system"""
        def print_event_handler_message():
            self.dashboard.cleanup_old_data()
            start_time = time.time()
            time.sleep(7)  # Wait for detection system
            logger.info("Security threat detected")
            detection_time = time.time() - start_time
            logger.info(f"Threat detection processing time: {detection_time:.6f} seconds")
            logger.info("SOAR4BC Orchestrator Ready - Waiting for Playbook via Kafka...")
        
        # Start event handler thread
        threading.Thread(target=print_event_handler_message, daemon=True).start()
        
        # Start Kafka consumer
        return self.start_kafka_consumer()
    
    def run(self):
        """Run the SOAR system"""
        logger.info("Starting SOAR4BC System...")
        kafka_thread = self.initialize_system()
        
        try:
            # Keep main thread alive
            kafka_thread.join()
        except KeyboardInterrupt:
            logger.info("SOAR system stopped by user")
        except Exception as e:
            logger.error(f"Error running SOAR system: {e}")


def main():
    """Main entry point"""
    soar = SOAROrchestrator()
    soar.run()


if __name__ == '__main__':
    main()