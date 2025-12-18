# ml_service.py
from flask import Flask, request, jsonify
from joblib import load
import os

MODEL_FILE = 'model.joblib'
if not os.path.exists(MODEL_FILE):
    raise RuntimeError("Model not found. Run train_model.py first.")

model = load(MODEL_FILE)
app = Flask(__name__)

@app.route('/')
def home():
    return "ML service running"

@app.route('/predict', methods=['POST'])
def predict():
    data = request.get_json() or {}
    text = data.get('text', '')
    if not text:
        return jsonify({'success':False, 'message':'No text provided'}), 400
    pred = model.predict([text])[0]
    proba = model.predict_proba([text])[0]
    idx = list(model.classes_).index(pred)
    confidence = float(proba[idx])
    return jsonify({'success':True, 'category': pred, 'confidence': confidence})

if __name__ == '__main__':
    app.run(port=5000)
