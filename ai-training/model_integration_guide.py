#!/usr/bin/env python3
"""
Model Integration Guide for Have I Been Rekt
Connects your trained comprehensive threat intelligence model to the application
"""

import torch
import json
from transformers import AutoTokenizer, AutoModel
from pathlib import Path
import asyncio
from typing import Dict, List, Any, Optional

class ComprehensiveThreatAnalyzer:
    """Production-ready threat intelligence analyzer"""
    
    def __init__(self, model_path: str):
        self.model_path = Path(model_path)
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        
        # Load model and tokenizer
        print(f"🔄 Loading model from {model_path}...")
        self.tokenizer = AutoTokenizer.from_pretrained(model_path)
        self.model = torch.load(f"{model_path}/pytorch_model.bin", map_location=self.device)
        self.model.eval()
        print(f"✅ Model loaded on {self.device}")
        
        # Threat level mapping
        self.threat_levels = {
            0: "Low",
            1: "Medium", 
            2: "High"
        }
    
    def analyze_wallet_submission(self, form_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze wallet form submission from your React app
        This integrates with WalletCheckForm data structure
        """
        print(f"🔍 Analyzing wallet submission: {form_data.get('walletAddress', 'N/A')}")
        
        # Extract all threat indicators from form
        threat_indicators = []
        
        # 1. Blockchain address analysis
        if form_data.get('walletAddress'):
            blockchain_analysis = self._analyze_address(form_data['walletAddress'])
            threat_indicators.append(blockchain_analysis)
        
        # 2. Domain analysis from known scam URL
        if form_data.get('knownScamURL'):
            domain_analysis = self._analyze_domain(form_data['knownScamURL'])
            threat_indicators.append(domain_analysis)
        
        # 3. Contact analysis (username/email patterns)
        if form_data.get('scammerContact'):
            contact_analysis = self._analyze_contact(form_data['scammerContact'])
            threat_indicators.append(contact_analysis)
        
        # 4. Email analysis if provided
        if form_data.get('contactEmail'):
            email_analysis = self._analyze_email(form_data['contactEmail'])
            threat_indicators.append(email_analysis)
        
        # Combine all analyses for final threat assessment
        combined_analysis = self._combine_threat_analyses(threat_indicators)
        
        return {
            'wallet_address': form_data.get('walletAddress'),
            'overall_threat_level': combined_analysis['threat_level'],
            'confidence_score': combined_analysis['confidence'],
            'threat_indicators': threat_indicators,
            'recommendations': self._generate_recommendations(combined_analysis),
            'analysis_timestamp': int(asyncio.get_event_loop().time())
        }
    
    def _analyze_address(self, address: str) -> Dict[str, Any]:
        """Analyze blockchain address"""
        feature_text = f"Type: blockchain_intelligence | Address: {address}"
        
        prediction = self._predict_threat_level(feature_text)
        
        return {
            'type': 'blockchain_address',
            'value': address,
            'threat_level': prediction['threat_level'],
            'confidence': prediction['confidence'],
            'indicators': self._get_address_indicators(address)
        }
    
    def _analyze_domain(self, url: str) -> Dict[str, Any]:
        """Analyze domain/URL for phishing indicators"""
        # Extract domain from URL
        from urllib.parse import urlparse
        parsed = urlparse(url if url.startswith('http') else f'http://{url}')
        domain = parsed.netloc or parsed.path.split('/')[0]
        
        # Check for phishing patterns
        phishing_indicators = []
        if 'binance' in domain and 'binance.com' not in domain:
            phishing_indicators.append('Fake Binance domain')
        if 'metamask' in domain and 'metamask.io' not in domain:
            phishing_indicators.append('Fake MetaMask domain')
        if any(char in domain for char in ['0', '1', 'l', 'I']) and len(domain) > 10:
            phishing_indicators.append('Character substitution')
        if domain.endswith(('.tk', '.ml', '.ga')):
            phishing_indicators.append('Suspicious TLD')
        
        feature_text = f"Type: domain_intelligence | Domain: {domain} | Phishing indicators: {len(phishing_indicators)}"
        prediction = self._predict_threat_level(feature_text)
        
        return {
            'type': 'domain',
            'value': domain,
            'original_url': url,
            'threat_level': prediction['threat_level'],
            'confidence': prediction['confidence'],
            'phishing_indicators': phishing_indicators
        }
    
    def _analyze_contact(self, contact: str) -> Dict[str, Any]:
        """Analyze scammer contact information"""
        # Check if it's a username pattern
        scam_patterns = [
            'crypto_king', 'moon_shot', 'quick_profit', 'guaranteed_returns',
            'official_support', 'admin_help', 'binance_official', 'metamask_help'
        ]
        
        detected_patterns = []
        contact_lower = contact.lower()
        for pattern in scam_patterns:
            if pattern in contact_lower:
                detected_patterns.append(pattern)
        
        feature_text = f"Type: username_intelligence | Username: {contact} | Scam patterns: {', '.join(detected_patterns)}"
        prediction = self._predict_threat_level(feature_text)
        
        return {
            'type': 'contact',
            'value': contact,
            'threat_level': prediction['threat_level'],
            'confidence': prediction['confidence'],
            'detected_patterns': detected_patterns
        }
    
    def _analyze_email(self, email: str) -> Dict[str, Any]:
        """Analyze email address for suspicious patterns"""
        suspicious_patterns = []
        
        if 'noreply' in email or 'admin' in email:
            suspicious_patterns.append('Administrative email pattern')
        if 'support' in email and any(provider in email for provider in ['gmail.com', 'yahoo.com']):
            suspicious_patterns.append('Support email on free provider')
        
        # Check domain
        domain = email.split('@')[1] if '@' in email else ''
        
        feature_text = f"Type: email_intelligence | Email: {email} | Risk indicators: {', '.join(suspicious_patterns)}"
        prediction = self._predict_threat_level(feature_text)
        
        return {
            'type': 'email',
            'value': email,
            'domain': domain,
            'threat_level': prediction['threat_level'],
            'confidence': prediction['confidence'],
            'suspicious_patterns': suspicious_patterns
        }
    
    def _predict_threat_level(self, feature_text: str) -> Dict[str, Any]:
        """Make prediction using trained model"""
        # Tokenize input
        inputs = self.tokenizer(
            feature_text,
            return_tensors='pt',
            truncation=True,
            padding=True,
            max_length=512
        )
        inputs = {k: v.to(self.device) for k, v in inputs.items()}
        
        # Make prediction
        with torch.no_grad():
            outputs = self.model(**inputs)
            probabilities = torch.nn.functional.softmax(outputs['logits'], dim=-1)
            predicted_class = torch.argmax(probabilities, dim=-1).item()
            confidence = probabilities[0][predicted_class].item()
        
        return {
            'threat_level': self.threat_levels[predicted_class],
            'confidence': confidence,
            'probabilities': {
                'Low': probabilities[0][0].item(),
                'Medium': probabilities[0][1].item(),
                'High': probabilities[0][2].item()
            }
        }
    
    def _get_address_indicators(self, address: str) -> List[str]:
        """Get blockchain address threat indicators"""
        indicators = []
        
        # Basic checks (you can expand these)
        if not address.startswith('0x'):
            indicators.append('Invalid address format')
        if len(address) != 42:
            indicators.append('Invalid address length')
        
        # Add more sophisticated checks here using your Ethereum dataset
        
        return indicators
    
    def _combine_threat_analyses(self, analyses: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Combine multiple threat analyses into overall assessment"""
        if not analyses:
            return {'threat_level': 'Low', 'confidence': 0.0}
        
        # Calculate weighted threat score
        threat_weights = {'Low': 0, 'Medium': 1, 'High': 2}
        total_score = 0
        total_confidence = 0
        
        for analysis in analyses:
            weight = threat_weights.get(analysis['threat_level'], 0)
            confidence = analysis['confidence']
            total_score += weight * confidence
            total_confidence += confidence
        
        if total_confidence == 0:
            return {'threat_level': 'Low', 'confidence': 0.0}
        
        average_score = total_score / total_confidence
        
        # Determine overall threat level
        if average_score >= 1.5:
            overall_threat = 'High'
        elif average_score >= 0.5:
            overall_threat = 'Medium'
        else:
            overall_threat = 'Low'
        
        return {
            'threat_level': overall_threat,
            'confidence': min(total_confidence / len(analyses), 1.0),
            'score': average_score
        }
    
    def _generate_recommendations(self, analysis: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        threat_level = analysis['threat_level']
        confidence = analysis['confidence']
        
        if threat_level == 'High' and confidence > 0.7:
            recommendations.extend([
                "🚨 HIGH RISK: Avoid interacting with this wallet/address",
                "📞 Consider reporting to relevant authorities",
                "🔒 Review your security practices immediately",
                "💰 Check for unauthorized transactions"
            ])
        elif threat_level == 'Medium':
            recommendations.extend([
                "⚠️ MEDIUM RISK: Exercise caution",
                "🔍 Investigate further before any transactions",
                "📋 Document all interactions for potential reporting",
                "🛡️ Enable additional security measures"
            ])
        else:
            recommendations.extend([
                "✅ LOW RISK: Appears relatively safe",
                "👀 Continue monitoring for any changes",
                "📚 Stay informed about emerging threats"
            ])
        
        # Add general security recommendations
        recommendations.extend([
            "🔐 Always verify addresses through official channels",
            "🚫 Never share private keys or seed phrases",
            "📱 Use hardware wallets for large amounts"
        ])
        
        return recommendations


# Integration example for your React app
async def analyze_wallet_form_data(form_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main integration function for your WalletCheckForm
    Call this from your backend API
    """
    
    # Initialize analyzer (you'll need to update this path)
    MODEL_PATH = "/path/to/your/trained/model"  # Update this path
    
    try:
        analyzer = ComprehensiveThreatAnalyzer(MODEL_PATH)
        result = analyzer.analyze_wallet_submission(form_data)
        
        return {
            'success': True,
            'analysis': result,
            'message': f"Analysis complete - {result['overall_threat_level']} threat level detected"
        }
        
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': "Analysis failed - please try again"
        }


# Example usage with your React form data
if __name__ == "__main__":
    # Sample form data from your WalletCheckForm
    sample_form_data = {
        'walletAddress': '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb6',
        'incidentDate': '2024-01-15',
        'description': 'I think I was scammed by a fake DeFi protocol',
        'knownScamURL': 'fake-uniswap.org',
        'scammerContact': '@crypto_king_2024',
        'contactEmail': 'user@example.com',
        'optInToFollowUp': True,
        'consent': True
    }
    
    # This would be called from your backend API
    print("🧪 Testing integration with sample data...")
    
    # Note: This requires your trained model to be available
    # result = asyncio.run(analyze_wallet_form_data(sample_form_data))
    # print(json.dumps(result, indent=2))
    
    print("✅ Integration guide ready!")
    print("📋 Next steps:")
    print("   1. Train your model using the Colab notebook")
    print("   2. Download and save the trained model")
    print("   3. Update MODEL_PATH in this file")
    print("   4. Create API endpoint using this analyzer")
    print("   5. Connect to your React WalletCheckForm")