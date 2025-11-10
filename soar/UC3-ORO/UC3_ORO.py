"""
SOAR4BC - UC3 Extended for Datacenter Scenarios
Handles:
- Scenario 1: Fibre Cut + DDoS
- Scenario 2: Power Outage + VM Migration
"""

import json
import logging
import subprocess
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
import pytz
import re
import requests
from flask import Flask
from kafka import KafkaConsumer, KafkaProducer

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("kafka").setLevel(logging.WARNING)
logging.getLogger("kafka").setLevel(logging.ERROR)
logging.getLogger("kafka.conn").setLevel(logging.CRITICAL)
logging.getLogger("kafka.client").setLevel(logging.CRITICAL)
logging.getLogger("kafka.cluster").setLevel(logging.CRITICAL)
logging.getLogger("kafka.consumer").setLevel(logging.CRITICAL)
logging.getLogger("kafka.producer").setLevel(logging.CRITICAL)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class Config:
    """Configuration settings for the SOAR system"""
    # Kafka Configuration
    KAFKA_SERVER: str = 'kafka.dynabic.dev:9092'
    KAFKA_USERNAME: str = 'soar4bc'
    KAFKA_PASSWORD: str = 'xxxxx'
    PLAYBOOK_TOPIC: str = 'UC3.SOAR4BC.playbook'
    RESULT_TOPIC: str = 'UC3.SOAR4BC.result'
    
    # Neo4j Configuration
    NEO4J_URL: str = "http://localhost:7474/db/neo4j/tx/commit"
    NEO4J_USERNAME: str = 'neo4j'
    NEO4J_PASSWORD: str = 'xxx-xxxx'
    
    # ORO Management APIs
    DC_MANAGEMENT_BASE_URL: str = 'http://172.28.16.39:8080'

    # Default values for ORO scenarios
    DEFAULT_VM_ID: str = 'b7a055d3-395a-4f5b-bea3-c89f28122178'
    DEFAULT_POLICY_NAME: str = 'ddos_attack_filter'
    DEFAULT_TRAFFIC_POLICY: str = 'traffic_policy'
    
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
        "Do Nothing",
        "Apply Filtering Policy",
        "Apply Traffic Policy",
        "Migrate VM"
    }
    
    @staticmethod
    def extract_actions_sequential(playbook_data: Dict[str, Any]) -> List[str]:
        """Extract all actions in sequential order from workflow"""
        actions = []
        try:
            workflow = playbook_data.get("workflow", {})
            workflow_start = playbook_data.get("workflow_start")
            
            if not workflow_start:
                logger.warning("No workflow_start found, attempting to parse all actions")
                for key, value in workflow.items():
                    if value.get("type") == "action":
                        action_name = value.get("name")
                        if action_name in PlaybookParser.SUPPORTED_ACTIONS:
                            actions.append(action_name)
                return actions
            
            # Follow workflow sequence
            current_step = workflow_start
            visited = set()
            
            while current_step and current_step not in visited:
                visited.add(current_step)
                step_data = workflow.get(current_step)
                
                if not step_data:
                    break
                
                if step_data.get("type") == "action":
                    action_name = step_data.get("name")
                    if action_name in PlaybookParser.SUPPORTED_ACTIONS:
                        actions.append(action_name)
                        logger.info(f"Found action in sequence: {action_name}")
                
                current_step = step_data.get("on_completion")
            
            logger.info(f"Extracted {len(actions)} actions in sequence: {actions}")
            
        except Exception as e:
            logger.error(f"Error extracting sequential actions: {e}")
        
        return actions

    @staticmethod
    def extract_ips_from_playbook(playbook_data: Dict[str, Any]) -> Tuple[Optional[str], Optional[str]]:
        """
        Extract attacker IP (src) and target IP (dst) from playbook data
        Returns: (attacker_ip, target_ip)
        """
        attacker_ip = None
        target_ip = None
        
        try:
            external_references = playbook_data.get("external_reference", [])
            
            for ref in external_references:
                if ref.get("type") == "bundle":
                    objects = ref.get("objects", [])
                    
                    for obj in objects:
                        if obj.get("type") == "ipv4-addr":
                            obj_id = obj.get("id", "")
                            ip_value = obj.get("value")
                            
                            # Check if this is source (attacker) or destination (target)
                            if "src_asset_uuid" in obj_id or obj_id.endswith("src_asset_uuid}"):
                                attacker_ip = ip_value
                                logger.info(f"Found attacker IP (src): {attacker_ip}")
                            elif "dst_asset_uuid" in obj_id or obj_id.endswith("dst_asset_uuid}"):
                                target_ip = ip_value
                                logger.info(f"Found target IP (dst): {target_ip}")
            
            # Fallback: If IPs found but not properly identified
            if not attacker_ip and not target_ip:
                for ref in external_references:
                    if ref.get("type") == "bundle":
                        objects = ref.get("objects", [])
                        ip_list = [obj.get("value") for obj in objects if obj.get("type") == "ipv4-addr"]
                        
                        if len(ip_list) >= 2:
                            attacker_ip = ip_list[0]
                            target_ip = ip_list[1]
                            logger.info(f"Using fallback IP extraction - Attacker: {attacker_ip}, Target: {target_ip}")
                        elif len(ip_list) == 1:
                            attacker_ip = ip_list[0]
                            logger.info(f"Only one IP found: {attacker_ip}")
        
        except Exception as e:
            logger.error(f"Error extracting IPs: {e}")
        
        return attacker_ip, target_ip


# class PlaybookParser:
#     """Handles parsing of security playbooks"""
    
#     SUPPORTED_ACTIONS = {
#         "Do Nothing",
#         # NEW: ORO scenario actions
#         "Apply Filtering Policy",
#         "Apply Traffic Policy",
#         "Migrate VM"
#     }
    
#     @staticmethod
#     def extract_action(playbook_data: Dict[str, Any]) -> Optional[str]:
#         """Extract action from playbook data"""
#         try:
#             workflow = playbook_data.get("workflow", {})
#             for key, value in workflow.items():
#                 if value.get("type") == "action":
#                     action_name = value.get("name")
#                     if action_name in PlaybookParser.SUPPORTED_ACTIONS:
#                         return action_name
#                 elif value.get("name") == "start workflow Do Nothing":
#                     return "Do Nothing"
#         except Exception as e:
#             logger.error(f"Error extracting action: {e}")
#         return None

#     @staticmethod
#     def extract_ip_from_playbook(playbook_data: Dict[str, Any]) -> Optional[str]:
#         """Extract attacker IP from playbook data"""
#         try:
#             external_references = playbook_data.get("external_references", []) or playbook_data.get("external_reference")
#             for ref in external_references:
#                 if ref.get("type") == "bundle":
#                     for obj in ref.get("objects", []):
#                         if obj.get("type") == "ipv4-addr":
#                             ip = obj.get("value")
#                             if ip != "0.0.0.1": 
#                                 return ip
#         except Exception as e:
#             logger.error(f"Error extracting IP: {e}")
#         return None
    
#     @staticmethod
#     def extract_vm_id(playbook_data: Dict[str, Any]) -> Optional[str]:
#         """Extract VM ID from playbook data"""
#         try:
#             # Look for VM ID in external references
#             external_references = playbook_data.get("external_references", []) or playbook_data.get("external_reference", [])
#             for ref in external_references:
#                 if ref.get("type") == "bundle":
#                     for obj in ref.get("objects", []):
#                         if obj.get("type") == "vm" or obj.get("type") == "virtual-machine":
#                             return obj.get("value") or obj.get("id")
            
#             # Alternative: Look in workflow parameters
#             workflow = playbook_data.get("workflow", {})
#             for key, value in workflow.items():
#                 if "vm_id" in value:
#                     return value["vm_id"]
#                 if "target" in value and "vm" in str(value["target"]).lower():
#                     return value["target"]
#         except Exception as e:
#             logger.error(f"Error extracting VM ID: {e}")
#         return None
    
#     @staticmethod
#     def extract_policy_name(playbook_data: Dict[str, Any]) -> Optional[str]:
#         """Extract policy name from playbook data"""
#         try:
#             workflow = playbook_data.get("workflow", {})
#             for key, value in workflow.items():
#                 if "policy_name" in value:
#                     return value["policy_name"]
#                 if "policy" in value:
#                     return value["policy"]
#         except Exception as e:
#             logger.error(f"Error extracting policy name: {e}")
#         return None


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
                    {"statement": "MATCH (a:Attacker) DELETE a"},
                    {"statement": "MATCH (d:DCIncident) DELETE d"}
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
    
    def update_dc_incident(self, incident_type: str, status: str, details: str):
        """Update datacenter incident status"""
        try:
            timestamp = TimeTracker.get_timestamp()
            query = """
            MERGE (d:DCIncident {type: $incident_type})
            ON CREATE SET d.status = $status, d.details = $details, d.timestamp = $timestamp
            ON MATCH SET d.status = $status, d.details = $details, d.timestamp = $timestamp
            """
            data = {
                "statements": [{
                    "statement": query,
                    "parameters": {
                        "incident_type": incident_type,
                        "status": status,
                        "details": details,
                        "timestamp": timestamp
                    }
                }]
            }
            requests.post(self.url, auth=self.auth, json=data)
            logger.info(f"Updated DC incident {incident_type} status to: {status}")
        except Exception as e:
            logger.error(f"Error updating DC incident node: {e}")
    
    def update_response(
        self,
        target: str,
        response: str,
        reason: str,
        human_in_loop: str = "no",
        human_decision: str = "auto"
    ):
        """Update SOAR response in dashboard"""
        try:
            timestamp = TimeTracker.get_timestamp()
            query = (
                "MERGE (s:SOAR {target: $target}) "
                "CREATE (s)-[:RESPONSE]->(resp:RESPONSE {"
                "target: $target, "
                "response: $response, "
                "reason: $reason, "
                "timestamp: $timestamp, "
                "human_in_the_loop: $human_in_loop, "
                "human_decision: $human_decision})"
            )
            data = {
                "statements": [{
                    "statement": query,
                    "parameters": {
                        "target": target,
                        "response": response,
                        "reason": reason,
                        "timestamp": timestamp,
                        "human_in_loop": human_in_loop,
                        "human_decision": human_decision
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
    def execute(self, **kwargs) -> Dict[str, Any]:
        """Execute the action and return result"""
        pass
    
    def publish_result(self, producer: KafkaProducer, action: str, status: str, details: str, 
                      attacker_ip: str = None, target_ip: str = None, 
                      human_in_loop: bool = False, human_decision: str = None):
        """Publish action result to Kafka"""
        try:
            result_payload = {
                "action": action,
                "status": status,
                "details": details,
                "timestamp": TimeTracker.get_timestamp(),
                "human_in_the_loop": "yes" if human_in_loop else "no",
                "human_in_the_loop_decision": human_decision if human_in_loop else "auto"
            }

            # Add IPs if available
            if attacker_ip:
                result_payload["attacker_ip"] = attacker_ip
            if target_ip:
                result_payload["target_ip"] = target_ip

            producer.send(self.config.RESULT_TOPIC, result_payload)
            producer.flush()
            logger.info(f"Published action result to Kafka topic {self.config.RESULT_TOPIC}")
        except Exception as e:
            logger.error(f"Error publishing action result to Kafka: {e}")


class DoNothingExecutor(ActionExecutor):
    """Executor for do nothing action"""
    
    def execute(self, attacker_ip: str = None, **kwargs) -> Dict[str, Any]:
        target = attacker_ip or "N/A"
        logger.info("Executing 'Do Nothing' action")
        self.dashboard.update_response(target, "Do Nothing", "Nothing to Execute")
        if attacker_ip:
            self.dashboard.update_attacker_status(attacker_ip, "Not Blocked")
        return {"status": "success", "message": "No action taken"}


# ============================================================================
# NEW EXECUTORS FOR UC3 SCENARIOS
# ============================================================================

class FilteringPolicyExecutor(ActionExecutor):
    """
    Executor for applying WAF filtering policy
    Scenario 1: Fibre Cut + DDoS - Apply filtering to affected VM
    """
    
    @TimeTracker.time_execution("Apply Filtering Policy Action")
    def execute(self, vm_id: str = None, policy_name: str = None, **kwargs) -> Dict[str, Any]:
        # Using default values from config if not provided
        if not vm_id:
            vm_id = self.config.DEFAULT_VM_ID
        if not policy_name:
            policy_name = self.config.DEFAULT_POLICY_NAME
        
        endpoint = f"{self.config.DC_MANAGEMENT_BASE_URL}/apply_filtering_policy"
        
        payload = {
            "policy_name": policy_name,
            "vm_id": vm_id
        }
        
        logger.info(f"Applying filtering policy '{policy_name}' to VM {vm_id}")
        
        try:
            response = requests.post(
                endpoint,
                headers={'Content-Type': 'application/json'},
                data=json.dumps(payload),
                timeout=30
            )
            
            response_data = response.json()
            
            if response.status_code == 200 and response_data.get("status") == "success":
                logger.info(f"Successfully applied filtering policy to VM {vm_id}")
                
                self.dashboard.update_response(
                    vm_id,
                    f"Applied Filtering Policy: {policy_name}",
                    "DDoS Attack Mitigation - ORO WAF Filter Deployed",
                    human_in_loop="no",
                    human_decision="auto"
                )
                self.dashboard.update_dc_incident(
                    "DDoS_Attack",
                    "Mitigated",
                    f"Filtering policy applied to VM {vm_id}"
                )
                
                return {
                    "status": "success",
                    "message": response_data.get("message", "Filtering policy applied successfully"),
                    "human_in_the_loop": False,
                    "human_in_the_loop_decision": "auto"
                }
            else:
                error_msg = response_data.get("message", "Unknown error")
                logger.error(f"Failed to apply filtering policy: {error_msg}")
                return {"status": "error", "message": error_msg}
                
        except requests.exceptions.Timeout:
            logger.error("Timeout while applying filtering policy")
            return {"status": "error", "message": "Request timeout"}
        except Exception as e:
            logger.error(f"Error applying filtering policy: {e}")
            return {"status": "error", "message": str(e)}


class TrafficPolicyExecutor(ActionExecutor):
    """
    Executor for applying traffic re-routing and prioritization policy
    Scenario 1: Fibre Cut + DDoS - Reroute from affected link to healthy link
    """
    
    @TimeTracker.time_execution("Apply Traffic Policy Action")
    def execute(self, policy_name: str = None, **kwargs) -> Dict[str, Any]:
        if not policy_name:
            policy_name = self.config.DEFAULT_TRAFFIC_POLICY

        endpoint = f"{self.config.DC_MANAGEMENT_BASE_URL}/apply_traffic_policy"
        
        payload = {
            "policy_name": policy_name
        }
        
        logger.info(f"Applying traffic policy '{policy_name}'")
        
        try:
            response = requests.post(
                endpoint,
                headers={'Content-Type': 'application/json'},
                data=json.dumps(payload),
                timeout=30
            )
            
            response_data = response.json()
            
            if response.status_code == 200 and response_data.get("status") == "success":
                logger.info(f"Successfully applied traffic policy")
                
                self.dashboard.update_response(
                    policy_name,
                    f"Applied Traffic Policy: {policy_name}",
                    "Traffic Re-routing & Prioritization - Link A to Link B",
                    human_in_loop="no",
                    human_decision="auto"
                )
                self.dashboard.update_dc_incident(
                    "Fibre_Cut",
                    "Mitigated",
                    f"Traffic rerouted to healthy link with priority"
                )
                
                return {
                    "status": "success",
                    "message": response_data.get("message", "Traffic policy applied successfully"),
                    "human_in_the_loop": False,
                    "human_in_the_loop_decision": "auto"
                }
            else:
                error_msg = response_data.get("message", "Unknown error")
                logger.error(f"Failed to apply traffic policy: {error_msg}")
                return {"status": "error", "message": error_msg}
                
        except requests.exceptions.Timeout:
            logger.error("Timeout while applying traffic policy")
            return {"status": "error", "message": "Request timeout"}
        except Exception as e:
            logger.error(f"Error applying traffic policy: {e}")
            return {"status": "error", "message": str(e)}


class VMMigrationExecutor(ActionExecutor):
    """
    Executor for VM migration
    Scenario 2: Power Outage - Migrate VM to healthy datacenter
    """
    
    @TimeTracker.time_execution("VM Migration Action")
    def execute(self, vm_id: str = None, **kwargs) -> Dict[str, Any]:
        if not vm_id:
            vm_id = self.config.DEFAULT_VM_ID
        
        endpoint = f"{self.config.DC_MANAGEMENT_BASE_URL}/migrate_vm"
        
        payload = {
            "vm_id": vm_id
        }
        
        logger.info(f"Migrating VM {vm_id} to healthy datacenter")
        
        try:
            response = requests.post(
                endpoint,
                headers={'Content-Type': 'application/json'},
                data=json.dumps(payload),
                timeout=60  # Longer timeout for VM migration
            )
            
            response_data = response.json()
            
            if response.status_code == 200 and response_data.get("status") == "success":
                logger.info(f"Successfully migrated VM {vm_id}")
                
                self.dashboard.update_response(
                    vm_id,
                    f"VM Migration: {vm_id}",
                    "Power Outage Recovery - VM Migrated to Healthy DC",
                    human_in_loop="no",
                    human_decision="auto"
                )
                self.dashboard.update_dc_incident(
                    "Power_Outage",
                    "Mitigated",
                    f"VM {vm_id} successfully migrated with network reconfiguration"
                )
                
                return {
                    "status": "success",
                    "message": response_data.get("message", "VM migrated successfully"),
                    "human_in_the_loop": False,
                    "human_in_the_loop_decision": "auto"
                }
            else:
                error_msg = response_data.get("message", "Unknown error")
                logger.error(f"Failed to migrate VM: {error_msg}")
                return {"status": "error", "message": error_msg}
                
        except requests.exceptions.Timeout:
            logger.error("Timeout while migrating VM")
            return {"status": "error", "message": "VM migration timeout"}
        except Exception as e:
            logger.error(f"Error migrating VM: {e}")
            return {"status": "error", "message": str(e)}


class ActionFactory:
    """Factory for creating action executors"""
    
    @staticmethod
    def create_executor(action: str, config: Config, dashboard: Neo4jDashboard) -> Optional[ActionExecutor]:
        """Create appropriate executor for the given action"""
        executors = {
            # Original actions
            "Do Nothing": DoNothingExecutor,
            # ORO UC3 Datacenter scenario actions
            "Apply Filtering Policy": FilteringPolicyExecutor,
            "Apply Traffic Policy": TrafficPolicyExecutor,
            "Migrate VM": VMMigrationExecutor
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
            group_id="soar4bc-uc3consumer",
            auto_offset_reset='latest',
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
            
            # Extract action
            start_time = time.time()
            attacker_ip, target_ip = PlaybookParser.extract_ips_from_playbook(playbook_data)

            # Extract all actions in sequence
            actions = PlaybookParser.extract_actions_sequential(playbook_data)

            extraction_time = time.time() - start_time
            logger.info(f"Playbook extraction time: {extraction_time:.6f} seconds")
            logger.info(f"Attacker IP: {attacker_ip}, Target IP: {target_ip}")
            logger.info(f"Actions to execute: {actions}")
            
            if not actions:
                logger.error("No valid action found in playbook")
                return
            
            # Execute actions sequentially
            for idx, action in enumerate(actions, 1):
                logger.info(f"\n{'='*60}")
                logger.info(f"Executing action {idx}/{len(actions)}: {action}")
                logger.info(f"{'='*60}")
                
                # Create executor
                executor = ActionFactory.create_executor(action, self.config, self.dashboard)
                
                if not executor:
                    logger.error(f"Unknown action: {action}")
                    continue
                
                # Prepare execution parameters
                exec_params = {}
            
                # Execute action
                start_time = time.time()
                result = executor.execute(**exec_params)
                execution_time = time.time() - start_time
                logger.info(f"Action '{action}' execution time: {execution_time:.6f} seconds")
                
                # Publish result with IPs
                human_flag = result.get("human_in_the_loop", False)
                decision = result.get("human_in_the_loop_decision", "auto")
                
                executor.publish_result(
                    self.producer,
                    action,
                    result["status"],
                    result["message"],
                    attacker_ip=attacker_ip,
                    target_ip=target_ip,
                    human_in_loop=human_flag,
                    human_decision=decision
                )
                
                # Log completion
                logger.info(f"Action '{action}' completed with status: {result['status']}")
                
                # Small delay between sequential actions if multiple actions
                if idx < len(actions):
                    time.sleep(1)
            
            logger.info(f"\n{'='*60}")
            logger.info(f"All {len(actions)} actions completed successfully")
            logger.info(f"{'='*60}\n")
        
        except Exception as e:
            logger.error(f"Error processing playbook: {e}")
            import traceback
            logger.error(traceback.format_exc())
    
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
            logger.info("Potential incident detected")
            detection_time = time.time() - start_time
            logger.info(f"Incident Detection Time: {detection_time:.6f} seconds")
            logger.info("Waiting for Playbook via Kafka...")
        
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
            logger.info("SOAR4BC system stopped by user")
        except Exception as e:
            logger.error(f"Error running SOAR4BC system: {e}")


def main():
    """Main entry point"""
    soar = SOAROrchestrator()
    soar.run()


if __name__ == '__main__':
    main()