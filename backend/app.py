from flask import Flask, request, jsonify
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

app = Flask(__name__)

# Load model
model_name = "roberta-base"
tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForSequenceClassification.from_pretrained(model_name)

@app.route('/')
def home():
    return jsonify({"message": "Promptium AI Firewall Backend Running ✅"})

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    text = data.get('text', '')
    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True)
    outputs = model(**inputs)
    predictions = torch.softmax(outputs.logits, dim=-1)
    label = torch.argmax(predictions, dim=1).item()
    return jsonify({"label": int(label), "confidence": float(predictions[0][label])})

if __name__ == '__main__':
    app.run(debug=True)


