#!/usr/bin/env python3
"""
PGOP Pivot Workflow Engine
IF-THEN-THAT style automation for OSINT research sequences
"""

import json
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable, Union
from dataclasses import dataclass, field
from enum import Enum
import logging

logger = logging.getLogger(__name__)

class ConditionOperator(Enum):
    EQUALS = "equals"
    CONTAINS = "contains"
    MATCHES_REGEX = "matches_regex"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    IN_LIST = "in_list"
    NOT_EMPTY = "not_empty"

class ActionType(Enum):
    EXTRACT_DATA = "extract_data"
    CREATE_TARGET = "create_target"
    SET_VARIABLE = "set_variable"
    TRIGGER_SCAN = "trigger_scan"
    GENERATE_REPORT = "generate_report"
    SEND_NOTIFICATION = "send_notification"

@dataclass
class Condition:
    field: str
    operator: ConditionOperator
    value: Any
    description: str = ""

@dataclass
class Action:
    type: ActionType
    config: Dict[str, Any]
    description: str = ""

@dataclass
class WorkflowRule:
    name: str
    description: str
    conditions: List[Condition]
    actions: List[Action]
    priority: int = 100
    enabled: bool = True

@dataclass
class WorkflowContext:
    findings: List[Dict]
    variables: Dict[str, Any] = field(default_factory=dict)
    targets: List[Dict] = field(default_factory=list)
    execution_log: List[str] = field(default_factory=list)

class PivotWorkflowEngine:
    """Advanced workflow engine for automated OSINT pivot sequences"""
    
    def __init__(self):
        self.rules = []
        self.extractors = self._initialize_extractors()
        self.execution_stats = {
            'rules_executed': 0,
            'actions_performed': 0,
            'targets_generated': 0
        }
    
    def _initialize_extractors(self) -> Dict[str, Callable]:
        """Initialize data extraction functions"""
        return {
            'email_domain': lambda email: email.split('@')[1] if '@' in email else None,
            'url_domain': lambda url: re.search(r'https?://([^/]+)', url).group(1) if re.search(r'https?://([^/]+)', url) else None,
            'subdomain_parent': lambda subdomain: '.'.join(subdomain.split('.')[1:]) if '.' in subdomain else None,
            'username_from_url': self._extract_username_from_social_url,
            'phone_country_code': lambda phone: re.search(r'^\+(\d{1,3})', phone).group(1) if re.search(r'^\+(\d{1,3})', phone) else None,
            'hash_type': self._detect_hash_type,
            'ip_class': lambda ip: f"{'.'.join(ip.split('.')[:2])}.*" if self._is_valid_ip(ip) else None
        }
    
    def _extract_username_from_social_url(self, url: str) -> Optional[str]:
        """Extract username from social media URLs"""
        patterns = [
            r'twitter\.com/([^/\?]+)',
            r'linkedin\.com/in/([^/\?]+)', 
            r'github\.com/([^/\?]+)',
            r'instagram\.com/([^/\?]+)',
            r'facebook\.com/([^/\?]+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                username = match.group(1)
                if username not in ['home', 'login', 'signup', 'about']:
                    return username
        return None
    
    def _detect_hash_type(self, hash_value: str) -> Optional[str]:
        """Detect hash type based on length and format"""
        hash_value = hash_value.strip().lower()
        
        if re.match(r'^[a-f0-9]{32}$', hash_value):
            return 'MD5'
        elif re.match(r'^[a-f0-9]{40}$', hash_value):
            return 'SHA1'
        elif re.match(r'^[a-f0-9]{64}$', hash_value):
            return 'SHA256'
        return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Check if string is valid IP address"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except ValueError:
            return False
    
    def add_rule(self, rule: WorkflowRule):
        """Add a workflow rule to the engine"""
        self.rules.append(rule)
        # Sort by priority (lower number = higher priority)
        self.rules.sort(key=lambda r: r.priority)
        logger.info(f"📋 Added workflow rule: {rule.name}")
    
    def load_rules_from_json(self, json_file: str):
        """Load workflow rules from JSON configuration"""
        with open(json_file, 'r') as f:
            rules_data = json.load(f)
        
        for rule_data in rules_data:
            conditions = []
            for cond_data in rule_data.get('conditions', []):
                condition = Condition(
                    field=cond_data['field'],
                    operator=ConditionOperator(cond_data['operator']),
                    value=cond_data['value'],
                    description=cond_data.get('description', '')
                )
                conditions.append(condition)
            
            actions = []
            for action_data in rule_data.get('actions', []):
                action = Action(
                    type=ActionType(action_data['type']),
                    config=action_data['config'],
                    description=action_data.get('description', '')
                )
                actions.append(action)
            
            rule = WorkflowRule(
                name=rule_data['name'],
                description=rule_data['description'],
                conditions=conditions,
                actions=actions,
                priority=rule_data.get('priority', 100),
                enabled=rule_data.get('enabled', True)
            )
            
            self.add_rule(rule)
    
    def evaluate_condition(self, condition: Condition, context: WorkflowContext) -> bool:
        """Evaluate a single condition against the context"""
        try:
            # Get value from context (finding data or variables)
            field_value = None
            
            # Check if it's a variable reference
            if condition.field.startswith('$'):
                var_name = condition.field[1:]
                field_value = context.variables.get(var_name)
            else:
                # Look through findings for matching field
                for finding in context.findings:
                    if condition.field in finding:
                        field_value = finding[condition.field]
                        break
            
            if field_value is None:
                return False
            
            # Apply condition operator
            if condition.operator == ConditionOperator.EQUALS:
                return field_value == condition.value
            
            elif condition.operator == ConditionOperator.CONTAINS:
                return str(condition.value).lower() in str(field_value).lower()
            
            elif condition.operator == ConditionOperator.MATCHES_REGEX:
                return bool(re.search(condition.value, str(field_value), re.IGNORECASE))
            
            elif condition.operator == ConditionOperator.GREATER_THAN:
                return float(field_value) > float(condition.value)
            
            elif condition.operator == ConditionOperator.LESS_THAN:
                return float(field_value) < float(condition.value)
            
            elif condition.operator == ConditionOperator.IN_LIST:
                return field_value in condition.value
            
            elif condition.operator == ConditionOperator.NOT_EMPTY:
                return bool(field_value and str(field_value).strip())
            
            return False
            
        except Exception as e:
            logger.warning(f"⚠️ Condition evaluation failed: {e}")
            return False
    
    def execute_action(self, action: Action, context: WorkflowContext) -> bool:
        """Execute a single action"""
        try:
            if action.type == ActionType.EXTRACT_DATA:
                return self._execute_extract_data(action, context)
            
            elif action.type == ActionType.CREATE_TARGET:
                return self._execute_create_target(action, context)
            
            elif action.type == ActionType.SET_VARIABLE:
                return self._execute_set_variable(action, context)
            
            elif action.type == ActionType.TRIGGER_SCAN:
                return self._execute_trigger_scan(action, context)
            
            elif action.type == ActionType.GENERATE_REPORT:
                return self._execute_generate_report(action, context)
            
            elif action.type == ActionType.SEND_NOTIFICATION:
                return self._execute_send_notification(action, context)
            
            return False
            
        except Exception as e:
            logger.error(f"❌ Action execution failed: {e}")
            return False
    
    def _execute_extract_data(self, action: Action, context: WorkflowContext) -> bool:
        """Execute data extraction action"""
        source_field = action.config.get('source_field')
        extractor = action.config.get('extractor')
        target_variable = action.config.get('target_variable')
        
        if not all([source_field, extractor, target_variable]):
            return False
        
        # Get source data
        source_value = None
        for finding in context.findings:
            if source_field in finding:
                source_value = finding[source_field]
                break
        
        if not source_value:
            return False
        
        # Apply extractor
        if extractor in self.extractors:
            extracted_value = self.extractors[extractor](source_value)
            if extracted_value:
                context.variables[target_variable] = extracted_value
                context.execution_log.append(f"Extracted {extracted_value} from {source_value}")
                return True
        
        return False
    
    def _execute_create_target(self, action: Action, context: WorkflowContext) -> bool:
        """Execute create target action"""
        target_value = action.config.get('value')
        target_type = action.config.get('type')
        source = action.config.get('source', 'workflow_pivot')
        
        # Support variable substitution
        if target_value and target_value.startswith('$'):
            var_name = target_value[1:]
            target_value = context.variables.get(var_name)
        
        if target_value and target_type:
            target = {
                'value': target_value,
                'type': target_type,
                'source': source,
                'created_at': datetime.now().isoformat()
            }
            context.targets.append(target)
            context.execution_log.append(f"Created target: {target_value} ({target_type})")
            self.execution_stats['targets_generated'] += 1
            return True
        
        return False
    
    def _execute_set_variable(self, action: Action, context: WorkflowContext) -> bool:
        """Execute set variable action"""
        variable = action.config.get('variable')
        value = action.config.get('value')
        
        if variable:
            context.variables[variable] = value
            context.execution_log.append(f"Set variable {variable} = {value}")
            return True
        
        return False
    
    def _execute_trigger_scan(self, action: Action, context: WorkflowContext) -> bool:
        """Execute trigger scan action (would integrate with SpiderFoot)"""
        scan_type = action.config.get('scan_type', 'comprehensive')
        target_variable = action.config.get('target_variable')
        
        if target_variable and target_variable in context.variables:
            target_value = context.variables[target_variable]
            context.execution_log.append(f"Triggered {scan_type} scan for {target_value}")
            # In real implementation, this would call SpiderFoot API
            return True
        
        return False
    
    def _execute_generate_report(self, action: Action, context: WorkflowContext) -> bool:
        """Execute generate report action"""
        report_type = action.config.get('type', 'summary')
        context.execution_log.append(f"Generated {report_type} report")
        return True
    
    def _execute_send_notification(self, action: Action, context: WorkflowContext) -> bool:
        """Execute send notification action"""
        message = action.config.get('message', 'Workflow notification')
        context.execution_log.append(f"Notification: {message}")
        return True
    
    def execute_workflow(self, findings: List[Dict], initial_variables: Dict[str, Any] = None) -> WorkflowContext:
        """Execute complete workflow against findings"""
        context = WorkflowContext(
            findings=findings,
            variables=initial_variables or {}
        )
        
        logger.info(f"🔄 Starting workflow execution with {len(findings)} findings")
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            # Check all conditions for this rule
            conditions_met = True
            for condition in rule.conditions:
                if not self.evaluate_condition(condition, context):
                    conditions_met = False
                    break
            
            if conditions_met:
                logger.info(f"✅ Rule triggered: {rule.name}")
                context.execution_log.append(f"Rule triggered: {rule.name}")
                
                # Execute all actions for this rule
                for action in rule.actions:
                    success = self.execute_action(action, context)
                    if success:
                        self.execution_stats['actions_performed'] += 1
                
                self.execution_stats['rules_executed'] += 1
        
        logger.info(f"🎉 Workflow completed: {self.execution_stats}")
        return context
    
    def create_example_workflow(self) -> List[Dict]:
        """Create example workflow rules for demonstration"""
        return [
            {
                "name": "email_to_domain_pivot",
                "description": "Extract domain from email addresses and create domain targets",
                "priority": 10,
                "conditions": [
                    {
                        "field": "data_type",
                        "operator": "equals",
                        "value": "EMAIL_ADDRESS"
                    }
                ],
                "actions": [
                    {
                        "type": "extract_data",
                        "config": {
                            "source_field": "data_value",
                            "extractor": "email_domain",
                            "target_variable": "extracted_domain"
                        }
                    },
                    {
                        "type": "create_target",
                        "config": {
                            "value": "$extracted_domain",
                            "type": "DOMAIN_NAME",
                            "source": "email_domain_extraction"
                        }
                    }
                ]
            },
            {
                "name": "social_username_extraction",
                "description": "Extract usernames from social media URLs",
                "priority": 20,
                "conditions": [
                    {
                        "field": "data_type",
                        "operator": "equals",
                        "value": "LINKED_URL_EXTERNAL"
                    },
                    {
                        "field": "data_value",
                        "operator": "contains",
                        "value": "twitter.com"
                    }
                ],
                "actions": [
                    {
                        "type": "extract_data",
                        "config": {
                            "source_field": "data_value",
                            "extractor": "username_from_url",
                            "target_variable": "social_username"
                        }
                    },
                    {
                        "type": "create_target",
                        "config": {
                            "value": "$social_username",
                            "type": "USERNAME",
                            "source": "social_media_extraction"
                        }
                    }
                ]
            },
            {
                "name": "high_confidence_pivot",
                "description": "Create additional targets for high-confidence findings",
                "priority": 30,
                "conditions": [
                    {
                        "field": "confidence",
                        "operator": "greater_than",
                        "value": 80
                    },
                    {
                        "field": "data_type",
                        "operator": "in_list",
                        "value": ["DOMAIN_NAME", "IP_ADDRESS"]
                    }
                ],
                "actions": [
                    {
                        "type": "trigger_scan",
                        "config": {
                            "scan_type": "deep_infrastructure",
                            "target_variable": "data_value"
                        }
                    },
                    {
                        "type": "set_variable",
                        "config": {
                            "variable": "high_confidence_target",
                            "value": "$data_value"
                        }
                    }
                ]
            }
        ]

# Example usage and testing
if __name__ == "__main__":
    # Initialize workflow engine
    engine = PivotWorkflowEngine()
    
    # Create example rules
    example_rules = engine.create_example_workflow()
    
    # Save example rules to file
    with open('/home/monkeyflower/Have-I-Been-Rekt/osint-research-fork/workflows/example_rules.json', 'w') as f:
        json.dump(example_rules, f, indent=2)
    
    # Load rules into engine
    engine.load_rules_from_json('/home/monkeyflower/Have-I-Been-Rekt/osint-research-fork/workflows/example_rules.json')
    
    # Example findings data
    test_findings = [
        {
            "data_type": "EMAIL_ADDRESS",
            "data_value": "suspicious@example.com",
            "confidence": 85,
            "source_module": "test"
        },
        {
            "data_type": "LINKED_URL_EXTERNAL", 
            "data_value": "https://twitter.com/suspicioususer",
            "confidence": 90,
            "source_module": "test"
        },
        {
            "data_type": "DOMAIN_NAME",
            "data_value": "malicious-site.com",
            "confidence": 95,
            "source_module": "test"
        }
    ]
    
    # Execute workflow
    result = engine.execute_workflow(test_findings)
    
    print(f"🎯 Workflow Results:")
    print(f"   Rules executed: {engine.execution_stats['rules_executed']}")
    print(f"   Actions performed: {engine.execution_stats['actions_performed']}")
    print(f"   Targets generated: {len(result.targets)}")
    print(f"   Variables created: {len(result.variables)}")
    
    print(f"\n🔍 Generated Targets:")
    for target in result.targets:
        print(f"   - {target['value']} ({target['type']}) from {target['source']}")
    
    print(f"\n📝 Execution Log:")
    for log_entry in result.execution_log[-5:]:  # Show last 5 entries
        print(f"   - {log_entry}")