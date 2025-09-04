#!/usr/bin/env python3
"""
HIBR AI Model Service
Provides AI-powered threat detection using the trained PyTorch model
"""

import os
import torch
import torch.nn as nn
import numpy as np
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime
import json

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RealDeepThreatDetector(nn.Module):
    """Deep neural network for threat detection (matches training architecture)"""
    def __init__(self, input_size=12, dropout_rate=0.4):
        super(RealDeepThreatDetector, self).__init__()
        
        self.network = nn.Sequential(
            # Layer 1: 2048 neurons
            nn.Linear(input_size, 2048),
            nn.BatchNorm1d(2048),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            
            # Layer 2: 1024 neurons  
            nn.Linear(2048, 1024),
            nn.BatchNorm1d(1024),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            
            # Layer 3: 512 neurons
            nn.Linear(1024, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            
            # Layer 4: 256 neurons
            nn.Linear(512, 256),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            
            # Layer 5: 128 neurons
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            
            # Layer 6: 64 neurons
            nn.Linear(128, 64),
            nn.BatchNorm1d(64),
            nn.ReLU(),
            nn.Dropout(dropout_rate),
            
            # Output layer
            nn.Linear(64, 1),
            nn.Sigmoid()
        )
    
    def forward(self, x):
        return self.network(x).squeeze()
    
    def get_logits(self, x):
        """Get raw logits before sigmoid for better discrimination"""
        for i, layer in enumerate(self.network):
            x = layer(x)
            if i == len(self.network) - 2:  # Before sigmoid
                return x.squeeze()
        return x.squeeze()

class HIBRAIService:
    """Main AI service for HIBR threat detection"""
    
    def __init__(self, model_path: str = "best_real_hibr_model.pth"):
        self.model_path = model_path
        self.model = None
        self.device = torch.device('cpu')  # Use CPU for production stability
        self._load_model()
        
    def _load_model(self):
        """Load the trained model"""
        try:
            if not os.path.exists(self.model_path):
                logger.error(f"Model file not found: {self.model_path}")
                return False
                
            self.model = RealDeepThreatDetector(input_size=12)
            checkpoint = torch.load(self.model_path, map_location=self.device)
            self.model.load_state_dict(checkpoint)
            self.model.eval()
            
            logger.info(f"✅ AI model loaded successfully from {self.model_path}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to load AI model: {e}")
            self.model = None
            return False
    
    def extract_features(self, indicator: str) -> List[float]:
        """Extract 12 features from any indicator (domain, address, URL, etc.)"""
        try:
            indicator = str(indicator).lower().strip()
            features = [
                len(indicator),                                    # 0: Length
                indicator.count('.'),                              # 1: Dots
                indicator.count('-'),                              # 2: Hyphens
                indicator.count('_'),                              # 3: Underscores
                sum(1 for c in indicator if c.isdigit()),          # 4: Digits
                sum(1 for c in indicator if c.isalpha()),          # 5: Letters
                indicator.count('0'),                              # 6: Zeros
                1 if indicator.startswith('0x') else 0,            # 7: Is crypto address
                1 if any(word in indicator for word in ['phish', 'scam', 'fake', 'fraud']) else 0,  # 8: Scam words
                1 if any(word in indicator for word in ['btc', 'eth', 'crypto', 'coin']) else 0,     # 9: Crypto words
                1 if '.eth' in indicator else 0,                   # 10: ENS domain
                1 if any(ext in indicator for ext in ['.com', '.org', '.net', '.io']) else 0  # 11: Web domain
            ]
            return features[:12]
        except Exception as e:
            logger.error(f"Feature extraction failed for '{indicator}': {e}")
            return [0.0] * 12
    
    def classify_risk_by_logit(self, logit: float) -> Tuple[str, str, str]:
        """Classify risk based on raw logit values with color coding"""
        if logit < 10:
            return "LOW", "likely legitimate", "🟢"
        elif logit < 15:
            return "MEDIUM", "needs verification", "🟡"
        elif logit < 20:
            return "HIGH", "probably suspicious", "🟠"
        else:
            return "VERY HIGH", "likely scam", "🔴"
    
    def analyze_indicator(self, indicator: str) -> Dict[str, Any]:
        """Analyze a single indicator and return risk assessment"""
        if not self.model:
            return {
                "error": "AI model not available",
                "status": "model_unavailable"
            }
        
        try:
            # Extract features
            features = self.extract_features(indicator)
            features_tensor = torch.FloatTensor(features).unsqueeze(0).to(self.device)
            
            # Get predictions
            with torch.no_grad():
                logit = self.model.get_logits(features_tensor).item()
                sigmoid_score = self.model(features_tensor).item()
            
            # Classify risk
            risk_level, risk_description, risk_emoji = self.classify_risk_by_logit(logit)
            
            # Calculate confidence (how far from neutral)
            confidence = min(abs(logit - 12) * 8, 100)  # 12 is roughly neutral, scale to 0-100
            
            return {
                "indicator": indicator,
                "risk_level": risk_level,
                "risk_description": risk_description,
                "risk_emoji": risk_emoji,
                "confidence": round(confidence, 1),
                "raw_logit": round(logit, 3),
                "sigmoid_score": round(sigmoid_score, 6),
                "features": {
                    "length": features[0],
                    "dots": features[1],
                    "hyphens": features[2],
                    "underscores": features[3],
                    "digits": features[4],
                    "letters": features[5],
                    "zeros": features[6],
                    "is_crypto": bool(features[7]),
                    "has_scam_words": bool(features[8]),
                    "has_crypto_words": bool(features[9]),
                    "is_ens_domain": bool(features[10]),
                    "is_web_domain": bool(features[11])
                },
                "analysis_timestamp": datetime.now().isoformat(),
                "model_version": "hibr_v1_rtx4090_trained"
            }
            
        except Exception as e:
            logger.error(f"Analysis failed for '{indicator}': {e}")
            return {
                "error": f"Analysis failed: {str(e)}",
                "status": "analysis_failed",
                "indicator": indicator
            }
    
    def analyze_batch(self, indicators: List[str]) -> List[Dict[str, Any]]:
        """Analyze multiple indicators efficiently"""
        results = []
        for indicator in indicators:
            result = self.analyze_indicator(indicator)
            results.append(result)
        return results
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model"""
        if not self.model:
            return {"status": "model_not_loaded"}
        
        total_params = sum(p.numel() for p in self.model.parameters())
        
        return {
            "status": "loaded",
            "model_path": self.model_path,
            "total_parameters": total_params,
            "device": str(self.device),
            "architecture": "6-layer deep neural network",
            "input_features": 12,
            "training_dataset": "725k balanced samples",
            "training_time": "4.75 hours on RTX 4090",
            "training_auc": "96.27%",
            "model_version": "hibr_v1_rtx4090_trained"
        }

# Global service instance (singleton pattern)
_ai_service = None

def get_ai_service() -> HIBRAIService:
    """Get or create the global AI service instance"""
    global _ai_service
    if _ai_service is None:
        _ai_service = HIBRAIService()
    return _ai_service

def analyze_threat(indicator: str) -> Dict[str, Any]:
    """Convenience function for single indicator analysis"""
    service = get_ai_service()
    return service.analyze_indicator(indicator)

def analyze_threats(indicators: List[str]) -> List[Dict[str, Any]]:
    """Convenience function for batch analysis"""
    service = get_ai_service()
    return service.analyze_batch(indicators)

if __name__ == "__main__":
    # Test the service
    service = HIBRAIService()
    
    test_cases = [
        "google.com",
        "phishing-site-eth.com", 
        "0x1234567890abcdef",
        "fake-metamask.io"
    ]
    
    print("🧪 Testing HIBR AI Service")
    print("=" * 50)
    
    for test in test_cases:
        result = service.analyze_indicator(test)
        if "error" not in result:
            print(f"\n📌 {test}")
            print(f"   Risk: {result['risk_emoji']} {result['risk_level']} ({result['confidence']}% confidence)")
            print(f"   Assessment: {result['risk_description']}")
            print(f"   Raw logit: {result['raw_logit']}")
        else:
            print(f"\n❌ {test}: {result['error']}")
    
    print(f"\n📊 Model Info:")
    model_info = service.get_model_info()
    for key, value in model_info.items():
        print(f"   {key}: {value}")