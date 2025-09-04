# How to Test Your HIBR AI Model

## Step 1: Install Dependencies

```bash
# Install PyTorch and NumPy
pip install torch numpy

# Or in a virtual environment:
python3 -m venv hibr_test_env
source hibr_test_env/bin/activate
pip install torch numpy
```

## Step 2: Download the Trained Model

The model file `best_real_hibr_model.pth` should be downloaded from your RTX 4090 training session.

## Step 3: Test the Model

Run the existing test script:

```bash
python test_with_logits.py
```

This will test the model with these indicators:
- `google.com` (should be LOW-MEDIUM risk)
- `ethereum.org` (should be LOW-MEDIUM risk)
- `phishing-site-eth.com` (should be HIGH risk)
- `fake-metamask-security.io` (should be HIGH risk)

## Step 4: Manual Testing

Create a simple test script:

```python
import torch
import torch.nn as nn

# Load model (adjust path as needed)
model_path = "best_real_hibr_model.pth"

class RealDeepThreatDetector(nn.Module):
    def __init__(self, input_size=12, dropout_rate=0.4):
        super().__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, 2048), nn.BatchNorm1d(2048), nn.ReLU(), nn.Dropout(dropout_rate),
            nn.Linear(2048, 1024), nn.BatchNorm1d(1024), nn.ReLU(), nn.Dropout(dropout_rate),
            nn.Linear(1024, 512), nn.BatchNorm1d(512), nn.ReLU(), nn.Dropout(dropout_rate),
            nn.Linear(512, 256), nn.BatchNorm1d(256), nn.ReLU(), nn.Dropout(dropout_rate),
            nn.Linear(256, 128), nn.BatchNorm1d(128), nn.ReLU(), nn.Dropout(dropout_rate),
            nn.Linear(128, 64), nn.BatchNorm1d(64), nn.ReLU(), nn.Dropout(dropout_rate),
            nn.Linear(64, 1), nn.Sigmoid()
        )
    
    def forward(self, x):
        return self.network(x).squeeze()
    
    def get_logits(self, x):
        for i, layer in enumerate(self.network):
            x = layer(x)
            if i == len(self.network) - 2:  # Before sigmoid
                return x.squeeze()
        return x.squeeze()

def extract_features(indicator):
    """Extract 12 features from any indicator"""
    indicator = str(indicator).lower().strip()
    return [
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

def classify_risk(logit):
    """Classify risk based on logit value"""
    if logit < 10:
        return "LOW", "likely legitimate", "🟢"
    elif logit < 15:
        return "MEDIUM", "needs verification", "🟡"
    elif logit < 20:
        return "HIGH", "probably suspicious", "🟠"
    else:
        return "VERY HIGH", "likely scam", "🔴"

# Load and test model
try:
    model = RealDeepThreatDetector()
    model.load_state_dict(torch.load(model_path, map_location='cpu'))
    model.eval()
    
    # Test cases
    test_cases = ["google.com", "phishing-site.com", "0x1234567890abcdef"]
    
    for test_case in test_cases:
        features = extract_features(test_case)
        features_tensor = torch.FloatTensor(features).unsqueeze(0)
        
        with torch.no_grad():
            logit = model.get_logits(features_tensor).item()
            risk_level, risk_desc, emoji = classify_risk(logit)
        
        print(f"{emoji} {test_case}: {risk_level} ({risk_desc}) - Logit: {logit:.2f}")

except Exception as e:
    print(f"Error: {e}")
    print("Make sure the model file exists and PyTorch is installed.")
```

## Expected Results

- **Legitimate sites** (google.com, ethereum.org): LOW-MEDIUM risk (logits 8-15)
- **Phishing sites**: HIGH-VERY HIGH risk (logits 16-25+)
- **Crypto addresses**: Varies based on patterns

The model uses logit values for classification rather than sigmoid scores for better discrimination.