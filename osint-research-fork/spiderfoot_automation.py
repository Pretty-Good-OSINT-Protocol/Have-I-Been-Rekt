#!/usr/bin/env python3
"""
PGOP SpiderFoot Automation Engine
Automated OSINT data collection with intelligent pivot sequences
"""

import requests
import json
import time
import uuid
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class TargetType(Enum):
    DOMAIN = "DOMAIN_NAME"
    IP_ADDRESS = "IP_ADDRESS"
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    PHONE_NUMBER = "PHONE_NUMBER"
    PERSON_NAME = "HUMAN_NAME"
    USERNAME = "USERNAME"
    COMPANY = "COMPANY_NAME"
    URL = "LINKED_URL_INTERNAL"

@dataclass
class ResearchTarget:
    value: str
    type: TargetType
    source: str = "manual_input"
    confidence: float = 1.0
    discovered_at: datetime = field(default_factory=datetime.now)

@dataclass
class OSINTFinding:
    source_module: str
    data_type: str
    data_value: str
    source_data: str
    confidence: float
    discovery_time: datetime
    parent_target: str

@dataclass
class PivotRule:
    name: str
    description: str
    trigger_data_types: List[str]
    extract_function: Callable
    target_type: TargetType
    confidence_threshold: float = 0.7

class SpiderFootAutomation:
    """Automated SpiderFoot scanning with intelligent pivot sequences"""
    
    def __init__(self, spiderfoot_url: str = "http://localhost:5001"):
        self.spiderfoot_url = spiderfoot_url
        self.session = requests.Session()
        self.scan_results = {}
        self.discovered_targets = {}
        self.pivot_rules = self._initialize_pivot_rules()
        
    def _initialize_pivot_rules(self) -> List[PivotRule]:
        """Define intelligent pivot rules for automated research expansion"""
        return [
            PivotRule(
                name="email_to_domain",
                description="Extract domains from email addresses",
                trigger_data_types=["EMAIL_ADDRESS"],
                extract_function=lambda email: email.split('@')[1] if '@' in email else None,
                target_type=TargetType.DOMAIN
            ),
            PivotRule(
                name="domain_to_subdomains",
                description="Discover subdomains from main domain findings",
                trigger_data_types=["SUBDOMAIN"],
                extract_function=lambda subdomain: subdomain,
                target_type=TargetType.DOMAIN
            ),
            PivotRule(
                name="social_profile_extraction",
                description="Extract usernames from social media URLs",
                trigger_data_types=["LINKED_URL_EXTERNAL"],
                extract_function=self._extract_username_from_url,
                target_type=TargetType.USERNAME
            ),
            PivotRule(
                name="company_domain_association",
                description="Link company names to potential domains",
                trigger_data_types=["COMPANY_NAME"],
                extract_function=lambda company: f"{company.lower().replace(' ', '')}.com",
                target_type=TargetType.DOMAIN
            ),
            PivotRule(
                name="phone_to_carrier",
                description="Research phone number carriers and geography",
                trigger_data_types=["PHONE_NUMBER"],
                extract_function=lambda phone: phone,
                target_type=TargetType.PHONE_NUMBER
            ),
        ]
    
    def _extract_username_from_url(self, url: str) -> Optional[str]:
        """Extract username from social media URLs"""
        social_patterns = {
            'twitter.com': r'/([^/]+)/?$',
            'linkedin.com/in': r'/in/([^/]+)/?$',
            'github.com': r'/([^/]+)/?$',
            'instagram.com': r'/([^/]+)/?$',
            'facebook.com': r'/([^/]+)/?$'
        }
        
        import re
        for platform, pattern in social_patterns.items():
            if platform in url.lower():
                match = re.search(pattern, url)
                if match:
                    return match.group(1)
        return None
    
    def create_scan(self, target: ResearchTarget, scan_name: str = None) -> str:
        """Create a new SpiderFoot scan for the given target"""
        if not scan_name:
            scan_name = f"PGOP_OSINT_{target.type.value}_{int(time.time())}"
        
        # Get available modules
        modules = self._get_optimal_modules_for_target(target.type)
        
        scan_data = {
            "scanname": scan_name,
            "scantarget": target.value,
            "targettype": target.type.value,
            "modulelist": modules,
            "typelist": self._get_relevant_data_types()
        }
        
        try:
            response = self.session.post(
                f"{self.spiderfoot_url}/newscan",
                data=scan_data
            )
            
            if response.status_code == 200:
                scan_id = response.json().get('id')
                logger.info(f"✅ Created scan {scan_id} for {target.value}")
                return scan_id
            else:
                logger.error(f"❌ Failed to create scan: {response.text}")
                return None
                
        except Exception as e:
            logger.error(f"❌ SpiderFoot connection error: {e}")
            return None
    
    def _get_optimal_modules_for_target(self, target_type: TargetType) -> List[str]:
        """Return optimal SpiderFoot modules based on target type"""
        
        # Core modules everyone needs
        base_modules = [
            "sfp_dns", "sfp_dnsresolve", "sfp_dnsbrute", "sfp_whois",
            "sfp_threatcrowd", "sfp_virustotal", "sfp_abuse_ch",
            "sfp_alienvault", "sfp_certspotter"
        ]
        
        target_specific_modules = {
            TargetType.DOMAIN: [
                "sfp_sublist3r", "sfp_crt", "sfp_google", "sfp_bing",
                "sfp_hunter", "sfp_emailrep", "sfp_haveibeenpwned",
                "sfp_shodan", "sfp_censys", "sfp_securitytrails"
            ],
            TargetType.EMAIL_ADDRESS: [
                "sfp_hunter", "sfp_emailrep", "sfp_haveibeenpwned",
                "sfp_trumail", "sfp_emailformat", "sfp_breachdb"
            ],
            TargetType.IP_ADDRESS: [
                "sfp_shodan", "sfp_censys", "sfp_greynoise", "sfp_abuseipdb",
                "sfp_ipinfo", "sfp_ipgeolocation", "sfp_neutrinoapi"
            ],
            TargetType.PHONE_NUMBER: [
                "sfp_truecaller", "sfp_numverify", "sfp_phonevalidator"
            ],
            TargetType.PERSON_NAME: [
                "sfp_social", "sfp_pipl", "sfp_fullcontact", "sfp_peekyou"
            ],
            TargetType.USERNAME: [
                "sfp_social", "sfp_whatsmyname", "sfp_sherlock"
            ]
        }
        
        return base_modules + target_specific_modules.get(target_type, [])
    
    def _get_relevant_data_types(self) -> List[str]:
        """Return comprehensive list of data types to collect"""
        return [
            "IP_ADDRESS", "DOMAIN_NAME", "SUBDOMAIN", "EMAIL_ADDRESS",
            "PHONE_NUMBER", "SOCIAL_MEDIA", "LINKED_URL_EXTERNAL",
            "LINKED_URL_INTERNAL", "USERNAME", "HUMAN_NAME", "COMPANY_NAME",
            "PHYSICAL_ADDRESS", "BITCOIN_ADDRESS", "HASH_MD5", "HASH_SHA1",
            "VULNERABILITY", "MALICIOUS_SUBDOMAIN", "MALICIOUS_IPADDR",
            "BLACKLISTED_INTERNET_NAME", "DEFACED_INTERNET_NAME",
            "SSL_CERTIFICATE", "WEBSERVER_BANNER", "SOFTWARE_USED"
        ]
    
    def wait_for_scan_completion(self, scan_id: str, max_wait: int = 3600) -> bool:
        """Wait for scan to complete with progress monitoring"""
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            try:
                response = self.session.get(f"{self.spiderfoot_url}/scanstatus?id={scan_id}")
                
                if response.status_code == 200:
                    status_data = response.json()
                    status = status_data.get('status', 'UNKNOWN')
                    
                    if status == 'FINISHED':
                        logger.info(f"✅ Scan {scan_id} completed successfully")
                        return True
                    elif status == 'ERROR-FAILED':
                        logger.error(f"❌ Scan {scan_id} failed")
                        return False
                    else:
                        logger.info(f"🔄 Scan {scan_id} status: {status}")
                        
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"❌ Error checking scan status: {e}")
                time.sleep(30)
        
        logger.error(f"⏰ Scan {scan_id} timed out after {max_wait} seconds")
        return False
    
    def collect_scan_results(self, scan_id: str) -> List[OSINTFinding]:
        """Collect and parse scan results into structured findings"""
        try:
            response = self.session.get(f"{self.spiderfoot_url}/scaneventresults?id={scan_id}")
            
            if response.status_code != 200:
                logger.error(f"❌ Failed to get results for scan {scan_id}")
                return []
            
            raw_results = response.json()
            findings = []
            
            for result in raw_results:
                finding = OSINTFinding(
                    source_module=result.get('module', 'unknown'),
                    data_type=result.get('type', 'unknown'),
                    data_value=result.get('data', ''),
                    source_data=result.get('sourceData', ''),
                    confidence=result.get('confidence', 50) / 100.0,
                    discovery_time=datetime.fromtimestamp(result.get('created', 0)),
                    parent_target=result.get('sourceData', '')
                )
                findings.append(finding)
            
            logger.info(f"📊 Collected {len(findings)} findings from scan {scan_id}")
            return findings
            
        except Exception as e:
            logger.error(f"❌ Error collecting results: {e}")
            return []
    
    def apply_pivot_rules(self, findings: List[OSINTFinding]) -> List[ResearchTarget]:
        """Apply pivot rules to generate new research targets"""
        new_targets = []
        
        for finding in findings:
            for pivot_rule in self.pivot_rules:
                if finding.data_type in pivot_rule.trigger_data_types:
                    if finding.confidence >= pivot_rule.confidence_threshold:
                        try:
                            extracted_value = pivot_rule.extract_function(finding.data_value)
                            
                            if extracted_value:
                                new_target = ResearchTarget(
                                    value=extracted_value,
                                    type=pivot_rule.target_type,
                                    source=f"pivot_from_{finding.source_module}",
                                    confidence=finding.confidence * 0.8,  # Reduce confidence for pivoted targets
                                    discovered_at=datetime.now()
                                )
                                new_targets.append(new_target)
                                
                                logger.info(f"🎯 Pivot rule '{pivot_rule.name}' generated target: {extracted_value}")
                                
                        except Exception as e:
                            logger.warning(f"⚠️ Pivot rule '{pivot_rule.name}' failed: {e}")
        
        # Deduplicate targets
        unique_targets = {}
        for target in new_targets:
            key = f"{target.type.value}:{target.value}"
            if key not in unique_targets or target.confidence > unique_targets[key].confidence:
                unique_targets[key] = target
        
        logger.info(f"🎯 Generated {len(unique_targets)} unique pivot targets")
        return list(unique_targets.values())
    
    def automated_research_workflow(self, initial_targets: List[ResearchTarget], max_depth: int = 3) -> Dict[str, Any]:
        """Execute complete automated research workflow with pivoting"""
        workflow_id = str(uuid.uuid4())
        workflow_results = {
            'workflow_id': workflow_id,
            'start_time': datetime.now(),
            'initial_targets': initial_targets,
            'scan_results': {},
            'pivot_generations': [],
            'final_findings': [],
            'target_tree': {}
        }
        
        current_targets = initial_targets.copy()
        depth = 0
        
        while current_targets and depth < max_depth:
            logger.info(f"🔍 Research depth {depth + 1}: Processing {len(current_targets)} targets")
            depth_results = []
            
            for target in current_targets:
                logger.info(f"🎯 Scanning target: {target.value} ({target.type.value})")
                
                # Create and execute scan
                scan_id = self.create_scan(target, f"depth_{depth}_{target.type.value}")
                
                if scan_id:
                    if self.wait_for_scan_completion(scan_id):
                        findings = self.collect_scan_results(scan_id)
                        
                        workflow_results['scan_results'][scan_id] = {
                            'target': target,
                            'findings': findings,
                            'depth': depth
                        }
                        
                        depth_results.extend(findings)
            
            # Generate pivot targets for next iteration
            if depth < max_depth - 1:
                pivot_targets = self.apply_pivot_rules(depth_results)
                
                # Filter out targets we've already scanned
                new_targets = [
                    t for t in pivot_targets 
                    if f"{t.type.value}:{t.value}" not in workflow_results.get('scanned_targets', set())
                ]
                
                workflow_results['pivot_generations'].append({
                    'depth': depth,
                    'generated_targets': len(pivot_targets),
                    'new_targets': len(new_targets)
                })
                
                current_targets = new_targets[:10]  # Limit to prevent explosion
                
                # Track scanned targets
                if 'scanned_targets' not in workflow_results:
                    workflow_results['scanned_targets'] = set()
                
                for target in current_targets:
                    workflow_results['scanned_targets'].add(f"{target.type.value}:{target.value}")
            else:
                current_targets = []
            
            depth += 1
        
        # Consolidate all findings
        all_findings = []
        for scan_data in workflow_results['scan_results'].values():
            all_findings.extend(scan_data['findings'])
        
        workflow_results['final_findings'] = all_findings
        workflow_results['end_time'] = datetime.now()
        workflow_results['total_findings'] = len(all_findings)
        
        logger.info(f"🎉 Workflow complete: {len(all_findings)} total findings across {depth} depths")
        
        return workflow_results

# Example usage and testing
if __name__ == "__main__":
    # Initialize automation engine
    automation = SpiderFootAutomation()
    
    # Example targets
    test_targets = [
        ResearchTarget("example.com", TargetType.DOMAIN),
        ResearchTarget("test@example.com", TargetType.EMAIL_ADDRESS)
    ]
    
    # Run automated workflow
    results = automation.automated_research_workflow(test_targets, max_depth=2)
    
    print(f"Research workflow completed:")
    print(f"- Workflow ID: {results['workflow_id']}")
    print(f"- Total findings: {results['total_findings']}")
    print(f"- Scans executed: {len(results['scan_results'])}")
    print(f"- Duration: {results['end_time'] - results['start_time']}")