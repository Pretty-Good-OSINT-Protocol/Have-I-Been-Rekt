#!/usr/bin/env python3
"""
PGOP Form Automation System
Automated data collection and form filling for OSINT research workflows
"""

import json
import re
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging

from spiderfoot_automation import SpiderFootAutomation, ResearchTarget, TargetType, OSINTFinding

logger = logging.getLogger(__name__)

class FieldType(Enum):
    TEXT = "text"
    EMAIL = "email"
    URL = "url"
    PHONE = "phone"
    DATE = "date"
    TEXTAREA = "textarea"
    SELECT = "select"
    CHECKBOX = "checkbox"
    MULTI_SELECT = "multi_select"

@dataclass
class FormField:
    name: str
    label: str
    field_type: FieldType
    required: bool = False
    description: str = ""
    validation_regex: Optional[str] = None
    options: List[str] = field(default_factory=list)
    auto_fill_sources: List[str] = field(default_factory=list)
    pivot_triggers: List[str] = field(default_factory=list)

@dataclass
class FormTemplate:
    name: str
    description: str
    version: str
    fields: List[FormField]
    workflow_config: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)

@dataclass
class FormData:
    template_name: str
    form_id: str
    submitted_data: Dict[str, Any]
    auto_filled_data: Dict[str, Any] = field(default_factory=dict)
    research_results: Dict[str, Any] = field(default_factory=dict)
    submission_time: datetime = field(default_factory=datetime.now)

class FormAutomationEngine:
    """Automated form filling using OSINT research results"""
    
    def __init__(self, spiderfoot_url: str = "http://localhost:5001"):
        self.spiderfoot = SpiderFootAutomation(spiderfoot_url)
        self.templates = {}
        self.extraction_rules = self._initialize_extraction_rules()
        
    def _initialize_extraction_rules(self) -> Dict[str, Callable]:
        """Define extraction rules for different data types"""
        return {
            'email_addresses': self._extract_emails,
            'phone_numbers': self._extract_phones,
            'social_media_urls': self._extract_social_urls,
            'domain_names': self._extract_domains,
            'ip_addresses': self._extract_ips,
            'physical_addresses': self._extract_addresses,
            'company_names': self._extract_companies,
            'person_names': self._extract_persons,
            'usernames': self._extract_usernames,
            'certificates': self._extract_certificates,
            'technologies': self._extract_technologies
        }
    
    def register_template(self, template: FormTemplate):
        """Register a new form template"""
        self.templates[template.name] = template
        logger.info(f"📋 Registered template: {template.name}")
    
    def load_template_from_json(self, json_file: str) -> FormTemplate:
        """Load form template from JSON configuration"""
        with open(json_file, 'r') as f:
            template_data = json.load(f)
        
        fields = []
        for field_data in template_data.get('fields', []):
            field = FormField(
                name=field_data['name'],
                label=field_data['label'],
                field_type=FieldType(field_data['type']),
                required=field_data.get('required', False),
                description=field_data.get('description', ''),
                validation_regex=field_data.get('validation_regex'),
                options=field_data.get('options', []),
                auto_fill_sources=field_data.get('auto_fill_sources', []),
                pivot_triggers=field_data.get('pivot_triggers', [])
            )
            fields.append(field)
        
        template = FormTemplate(
            name=template_data['name'],
            description=template_data['description'],
            version=template_data['version'],
            fields=fields,
            workflow_config=template_data.get('workflow_config', {})
        )
        
        self.register_template(template)
        return template
    
    def process_form_submission(self, template_name: str, form_data: Dict[str, Any]) -> FormData:
        """Process form submission and trigger automated research"""
        if template_name not in self.templates:
            raise ValueError(f"Template {template_name} not found")
        
        template = self.templates[template_name]
        form_id = str(uuid.uuid4())
        
        # Create form data object
        submission = FormData(
            template_name=template_name,
            form_id=form_id,
            submitted_data=form_data
        )
        
        # Extract research targets from form data
        initial_targets = self._extract_research_targets(template, form_data)
        
        # Execute automated research workflow
        if initial_targets:
            logger.info(f"🔍 Starting automated research for {len(initial_targets)} targets")
            
            workflow_config = template.workflow_config
            max_depth = workflow_config.get('max_depth', 2)
            
            research_results = self.spiderfoot.automated_research_workflow(
                initial_targets, 
                max_depth=max_depth
            )
            
            submission.research_results = research_results
            
            # Auto-fill form fields based on research results
            auto_filled = self._auto_fill_fields(template, research_results)
            submission.auto_filled_data = auto_filled
        
        logger.info(f"✅ Processed form submission {form_id}")
        return submission
    
    def _extract_research_targets(self, template: FormTemplate, form_data: Dict[str, Any]) -> List[ResearchTarget]:
        """Extract research targets from form submission"""
        targets = []
        
        for field in template.fields:
            field_value = form_data.get(field.name)
            
            if not field_value or field_value == "":
                continue
            
            # Determine target type based on field characteristics
            if field.field_type == FieldType.EMAIL:
                targets.append(ResearchTarget(field_value, TargetType.EMAIL_ADDRESS))
                
                # Also add domain from email
                if '@' in field_value:
                    domain = field_value.split('@')[1]
                    targets.append(ResearchTarget(domain, TargetType.DOMAIN))
            
            elif field.field_type == FieldType.URL:
                targets.append(ResearchTarget(field_value, TargetType.URL))
                
                # Extract domain from URL
                domain_match = re.search(r'https?://([^/]+)', field_value)
                if domain_match:
                    domain = domain_match.group(1)
                    targets.append(ResearchTarget(domain, TargetType.DOMAIN))
            
            elif field.field_type == FieldType.PHONE:
                targets.append(ResearchTarget(field_value, TargetType.PHONE_NUMBER))
            
            elif 'domain' in field.name.lower() or 'website' in field.name.lower():
                targets.append(ResearchTarget(field_value, TargetType.DOMAIN))
            
            elif 'ip' in field.name.lower():
                targets.append(ResearchTarget(field_value, TargetType.IP_ADDRESS))
            
            elif 'name' in field.name.lower() and 'company' not in field.name.lower():
                targets.append(ResearchTarget(field_value, TargetType.PERSON_NAME))
            
            elif 'company' in field.name.lower() or 'organization' in field.name.lower():
                targets.append(ResearchTarget(field_value, TargetType.COMPANY))
            
            elif 'username' in field.name.lower() or 'handle' in field.name.lower():
                targets.append(ResearchTarget(field_value, TargetType.USERNAME))
        
        logger.info(f"🎯 Extracted {len(targets)} research targets from form")
        return targets
    
    def _auto_fill_fields(self, template: FormTemplate, research_results: Dict[str, Any]) -> Dict[str, Any]:
        """Auto-fill form fields based on research results"""
        auto_filled = {}
        all_findings = research_results.get('final_findings', [])
        
        for field in template.fields:
            if not field.auto_fill_sources:
                continue
            
            field_data = []
            
            for source_type in field.auto_fill_sources:
                if source_type in self.extraction_rules:
                    extracted_data = self.extraction_rules[source_type](all_findings)
                    field_data.extend(extracted_data)
            
            if field_data:
                if field.field_type == FieldType.MULTI_SELECT:
                    auto_filled[field.name] = list(set(field_data))  # Remove duplicates
                elif field.field_type in [FieldType.TEXT, FieldType.TEXTAREA]:
                    auto_filled[field.name] = '\n'.join(set(field_data))
                else:
                    auto_filled[field.name] = field_data[0]  # Take first result
        
        logger.info(f"📝 Auto-filled {len(auto_filled)} form fields")
        return auto_filled
    
    # Extraction rule implementations
    def _extract_emails(self, findings: List[OSINTFinding]) -> List[str]:
        emails = []
        for finding in findings:
            if finding.data_type == "EMAIL_ADDRESS":
                emails.append(finding.data_value)
        return list(set(emails))
    
    def _extract_phones(self, findings: List[OSINTFinding]) -> List[str]:
        phones = []
        for finding in findings:
            if finding.data_type == "PHONE_NUMBER":
                phones.append(finding.data_value)
        return list(set(phones))
    
    def _extract_social_urls(self, findings: List[OSINTFinding]) -> List[str]:
        social_urls = []
        social_domains = ['twitter.com', 'linkedin.com', 'facebook.com', 'instagram.com', 'github.com']
        
        for finding in findings:
            if finding.data_type in ["LINKED_URL_EXTERNAL", "SOCIAL_MEDIA"]:
                url = finding.data_value
                if any(domain in url.lower() for domain in social_domains):
                    social_urls.append(url)
        
        return list(set(social_urls))
    
    def _extract_domains(self, findings: List[OSINTFinding]) -> List[str]:
        domains = []
        for finding in findings:
            if finding.data_type in ["DOMAIN_NAME", "SUBDOMAIN"]:
                domains.append(finding.data_value)
        return list(set(domains))
    
    def _extract_ips(self, findings: List[OSINTFinding]) -> List[str]:
        ips = []
        for finding in findings:
            if finding.data_type == "IP_ADDRESS":
                ips.append(finding.data_value)
        return list(set(ips))
    
    def _extract_addresses(self, findings: List[OSINTFinding]) -> List[str]:
        addresses = []
        for finding in findings:
            if finding.data_type == "PHYSICAL_ADDRESS":
                addresses.append(finding.data_value)
        return list(set(addresses))
    
    def _extract_companies(self, findings: List[OSINTFinding]) -> List[str]:
        companies = []
        for finding in findings:
            if finding.data_type == "COMPANY_NAME":
                companies.append(finding.data_value)
        return list(set(companies))
    
    def _extract_persons(self, findings: List[OSINTFinding]) -> List[str]:
        persons = []
        for finding in findings:
            if finding.data_type == "HUMAN_NAME":
                persons.append(finding.data_value)
        return list(set(persons))
    
    def _extract_usernames(self, findings: List[OSINTFinding]) -> List[str]:
        usernames = []
        for finding in findings:
            if finding.data_type == "USERNAME":
                usernames.append(finding.data_value)
        return list(set(usernames))
    
    def _extract_certificates(self, findings: List[OSINTFinding]) -> List[str]:
        certs = []
        for finding in findings:
            if finding.data_type == "SSL_CERTIFICATE":
                certs.append(finding.data_value)
        return list(set(certs))
    
    def _extract_technologies(self, findings: List[OSINTFinding]) -> List[str]:
        technologies = []
        for finding in findings:
            if finding.data_type in ["SOFTWARE_USED", "WEBSERVER_BANNER"]:
                technologies.append(finding.data_value)
        return list(set(technologies))
    
    def generate_template_example(self) -> Dict[str, Any]:
        """Generate an example template structure"""
        return {
            "name": "threat_actor_investigation",
            "description": "Comprehensive threat actor investigation form",
            "version": "1.0",
            "workflow_config": {
                "max_depth": 3,
                "auto_pivot": True,
                "report_format": "comprehensive"
            },
            "fields": [
                {
                    "name": "target_email",
                    "label": "Target Email Address",
                    "type": "email",
                    "required": True,
                    "description": "Primary email address to investigate",
                    "auto_fill_sources": ["email_addresses"],
                    "pivot_triggers": ["domain_extraction", "breach_check"]
                },
                {
                    "name": "associated_domains",
                    "label": "Associated Domains",
                    "type": "multi_select",
                    "description": "Domains associated with the target",
                    "auto_fill_sources": ["domain_names"],
                    "pivot_triggers": ["subdomain_enumeration"]
                },
                {
                    "name": "social_media_profiles",
                    "label": "Social Media Profiles",
                    "type": "textarea",
                    "description": "Discovered social media profiles",
                    "auto_fill_sources": ["social_media_urls"]
                },
                {
                    "name": "phone_numbers",
                    "label": "Phone Numbers",
                    "type": "textarea", 
                    "description": "Associated phone numbers",
                    "auto_fill_sources": ["phone_numbers"]
                },
                {
                    "name": "ip_addresses",
                    "label": "IP Addresses",
                    "type": "textarea",
                    "description": "Infrastructure IP addresses",
                    "auto_fill_sources": ["ip_addresses"]
                },
                {
                    "name": "technologies_used",
                    "label": "Technologies Identified",
                    "type": "multi_select",
                    "description": "Software and technologies in use",
                    "auto_fill_sources": ["technologies"]
                }
            ]
        }

# Example usage
if __name__ == "__main__":
    # Initialize form automation engine
    automation = FormAutomationEngine()
    
    # Generate and save example template
    example_template = automation.generate_template_example()
    
    with open('osint-research-fork/templates/threat_actor_template.json', 'w') as f:
        json.dump(example_template, f, indent=2)
    
    print("📋 Generated example template: threat_actor_template.json")
    print("🔧 Customize this template to match your specific data collection needs")
    
    # Example form processing (would be triggered by web interface)
    # form_data = {
    #     "target_email": "suspicious@example.com",
    #     "investigation_notes": "Initial investigation target"
    # }
    # 
    # result = automation.process_form_submission("threat_actor_investigation", form_data)
    # print(f"✅ Form processed: {result.form_id}")
    # print(f"📊 Research findings: {len(result.research_results.get('final_findings', []))}")