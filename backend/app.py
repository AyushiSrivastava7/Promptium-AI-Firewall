from flask import Flask, request, jsonify
from flask_cors import CORS
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import re
import base64


app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

import os

# Try multiple possible paths
possible_paths = [
    "./model",
    "./distilbert_model/content/distilbert_malicious_prompt_detector"
]

MODEL_PATH = None
for path in possible_paths:
    abs_path = os.path.abspath(path)
    config_file = os.path.join(abs_path, "config.json")
    if os.path.exists(config_file):
        MODEL_PATH = abs_path
        print(f"✓ Found model at: {MODEL_PATH}")
        break

if MODEL_PATH is None:
    print("ERROR: Could not find model files!")
    exit(1)

device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

print("Loading model...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH, local_files_only=True)
model.to(device)
model.eval()
print("Model loaded successfully!")

# Threat categories (adjust based on your training labels)
THREAT_TYPES = {
    0: "safe",
    1: "prompt_injection",
    2: "jailbreak",
    3: "data_exfiltration"
}

# Rule-based patterns
MALICIOUS_PATTERNS = [
    r"ignore\s+(previous|above|all|prior)\s+(instructions?|prompts?|rules?)",
    r"(system\s+prompt|new\s+instructions?|you\s+are\s+now)",
    r"(forget|disregard|override)\s+(everything|all|previous)",
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"data:text/html",
    r"(execute|eval|run)\s+(code|command|script)",
    r"reveal\s+(your\s+)?(system\s+)?(prompt|instructions?)",
    r"what\s+(are|were)\s+your\s+(original|initial)\s+instructions?"
]

def rule_based_filter(text):
    """Quick rule-based checks"""
    text_lower = text.lower()
    
    # Pattern matching
    for pattern in MALICIOUS_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE):
            return {
                "is_threat": True,
                "reason": "Matched malicious pattern",
                "confidence": 0.95,
                "method": "rule_based"
            }
    
    # Excessive special characters
    special_chars = sum(not c.isalnum() and not c.isspace() for c in text)
    if len(text) > 0 and special_chars / len(text) > 0.3:
        return {
            "is_threat": True,
            "reason": "Excessive special characters",
            "confidence": 0.85,
            "method": "rule_based"
        }
    
    # Base64 detection
    try:
        if len(text) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', text.replace('\n', '')):
            decoded = base64.b64decode(text)
            # Check if decoded content contains suspicious patterns
            decoded_text = decoded.decode('utf-8', errors='ignore').lower()
            for pattern in MALICIOUS_PATTERNS[:5]:  # Check first few patterns
                if re.search(pattern, decoded_text, re.IGNORECASE):
                    return {
                        "is_threat": True,
                        "reason": "Base64 encoded malicious content",
                        "confidence": 0.90,
                        "method": "rule_based"
                    }
    except:
        pass
    
    return {"is_threat": False}

def predict_with_model(text):
    """AI model prediction"""
    try:
        # Tokenize
        inputs = tokenizer(
            text,
            truncation=True,
            padding=True,
            max_length=512,
            return_tensors="pt"
        )
        inputs = {k: v.to(device) for k, v in inputs.items()}
        
        # Predict
        with torch.no_grad():
            outputs = model(**inputs)
            logits = outputs.logits
            probabilities = torch.softmax(logits, dim=1)
            predicted_class = torch.argmax(probabilities, dim=1).item()
            confidence = probabilities[0][predicted_class].item()
        
        return {
            "predicted_class": predicted_class,
            "threat_type": THREAT_TYPES.get(predicted_class, "unknown"),
            "confidence": float(confidence),
            "all_scores": {THREAT_TYPES.get(i, f"class_{i}"): float(probabilities[0][i]) 
                          for i in range(len(probabilities[0]))}
        }
    except Exception as e:
        print(f"Model prediction error: {e}")
        return None

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "model_loaded": model is not None,
        "device": str(device)
    })

@app.route('/scan', methods=['POST'])
def scan_prompt():
    """Main scanning endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'prompt' not in data:
            return jsonify({"error": "Missing 'prompt' in request"}), 400
        
        prompt = data['prompt']
        
        if not prompt or len(prompt.strip()) == 0:
            return jsonify({"error": "Empty prompt"}), 400
        
        # Layer 1: Rule-based filter
        rule_result = rule_based_filter(prompt)
        if rule_result['is_threat']:
            return jsonify({
                "blocked": True,
                "threat_detected": True,
                "threat_type": "pattern_match",
                "confidence": rule_result['confidence'],
                "reason": rule_result['reason'],
                "detection_method": "rule_based",
                "prompt_length": len(prompt)
            })
        
        # Layer 2: AI Model
        model_result = predict_with_model(prompt)
        
        if not model_result:
            return jsonify({"error": "Model prediction failed"}), 500
        
        # Determine if threat (threshold: 0.7 for confidence)
        is_threat = (model_result['predicted_class'] != 0 and 
                    model_result['confidence'] > 0.7)
        
        return jsonify({
            "blocked": is_threat,
            "threat_detected": is_threat,
            "threat_type": model_result['threat_type'],
            "confidence": model_result['confidence'],
            "all_scores": model_result['all_scores'],
            "detection_method": "ai_model",
            "prompt_length": len(prompt),
            "reason": f"AI detected: {model_result['threat_type']}" if is_threat else "Prompt appears safe"
        })
        
    except Exception as e:
        print(f"Error in scan_prompt: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/batch-scan', methods=['POST'])
def batch_scan():
    """Scan multiple prompts at once"""
    try:
        data = request.get_json()
        
        if not data or 'prompts' not in data:
            return jsonify({"error": "Missing 'prompts' array in request"}), 400
        
        prompts = data['prompts']
        results = []
        
        for prompt in prompts:
            # Reuse scan logic
            rule_result = rule_based_filter(prompt)
            if rule_result['is_threat']:
                results.append({
                    "prompt": prompt[:50] + "..." if len(prompt) > 50 else prompt,
                    "blocked": True,
                    "threat_type": "pattern_match",
                    "confidence": rule_result['confidence']
                })
            else:
                model_result = predict_with_model(prompt)
                if model_result:
                    is_threat = (model_result['predicted_class'] != 0 and 
                                model_result['confidence'] > 0.7)
                    results.append({
                        "prompt": prompt[:50] + "..." if len(prompt) > 50 else prompt,
                        "blocked": is_threat,
                        "threat_type": model_result['threat_type'],
                        "confidence": model_result['confidence']
                    })
        
        return jsonify({"results": results, "total": len(results)})
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


