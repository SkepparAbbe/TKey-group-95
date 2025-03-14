from flask import Flask, request, jsonify
import requests
import uuid
import time

app = Flask(__name__)
proxy_url = "http://localhost:8081/"
public_keys = []
login_challenge_received = []

@app.route('/login', methods=['POST'])
def receive_data():
    unique_id = uuid.uuid4().hex
    timestamp = int(time.time())
    challenge_data = f"{unique_id}-{timestamp}"
    
    # Send raw data (not JSON)
    response = requests.post("http://localhost:8081/login", data=challenge_data)
    go_response = response.json()
    
    with open("challenges.txt", "a") as f:
        f.write(f"Login - Original Challenge: {challenge_data}\n"
                "--------------------------------------------------\n"
                f"Login - Signature: {go_response['signature']}\n"
                "--------------------------------------------------\n")
    
    return jsonify({"status": "success"}), 200

@app.route('/registration', methods=['POST'])
def send_to_go():
    unique_id = uuid.uuid4().hex
    timestamp = int(time.time())
    challenge_data = f"{unique_id}-{timestamp}"
    
    # Send raw data (not JSON)
    response = requests.post("http://localhost:8081/registration", data=challenge_data)
    go_response = response.json()
    
    with open("challenges.txt", "a") as f:
        f.write(f"Registration Public Key: {go_response['publicKey']}\n"
                "--------------------------------------------------\n")
    
    return jsonify({"message": "Data received"}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)