from flask import Flask, request, jsonify, render_template
import oqs
import json
import base64
import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus

app = Flask(__name__)

# logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PQVPNClient:
    def __init__(self, server_url="http://localhost:5000"):
        self.server_url = server_url
        self.kyber_client = None
        self.client_id = None
        self.shared_secret = None
        self.server_dilithium_pk = None
        
    def base64_encode(self, data):
        """Helper function to base64 encode binary data"""
        return base64.b64encode(data).decode('utf-8')
    
    def base64_decode(self, data):
        """Helper function to base64 decode string to binary"""
        return base64.b64decode(data.encode('utf-8'))
    
    def initialize_connection(self):
        """Get server's public keys and initialize the connection"""
        try:
            logger.info(f"Initializing connection to server: {self.server_url}")
            response = requests.get(f"{self.server_url}/init")
            data = response.json()
            
            # server's public keys
            server_kyber_pk = self.base64_decode(data['kyber_public_key'])
            self.server_dilithium_pk = self.base64_decode(data['dilithium_public_key'])
            signature = self.base64_decode(data['signature'])
            
            # Verify the signature of the Kyber public key
            sig_verifier = oqs.Signature("Dilithium3")
            if not sig_verifier.verify(server_kyber_pk, signature, self.server_dilithium_pk):
                raise Exception("Server authentication failed: Invalid signature")
            
            logger.info("Server authentication successful")
            
            # Initialize key encapsulation mechanism
            self.kyber_client = oqs.KeyEncapsulation("Kyber768")
            
            # Generate ciphertext and shared secret
            ciphertext, self.shared_secret = self.kyber_client.encap_secret(server_kyber_pk)
            
            
            payload = {
                'ciphertext': self.base64_encode(ciphertext),
                'client_id': f"client_{int(time.time())}"
            }
            
            logger.info("Establishing secure connection...")
            response = requests.post(f"{self.server_url}/establish", json=payload)
            establish_data = response.json()
            
            
            self.client_id = establish_data['client_id']
            
            
            nonce = self.base64_decode(establish_data['nonce'])
            ciphertext = self.base64_decode(establish_data['ciphertext'])
            
            aes_key = self.shared_secret[:32]
            aesgcm = AESGCM(aes_key)
            
            try:
                plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                logger.info(f"Secure connection established! Server says: {plaintext.decode()}")
                return True
            except Exception as e:
                logger.error(f"Error decrypting confirmation: {str(e)}")
                return False
                
        except Exception as e:
            logger.error(f"Error initializing connection: {str(e)}")
            return False
    
    def send_encrypted_request(self, request_data):
        """Send encrypted request to server"""
        if not self.client_id or not self.shared_secret:
            logger.error("No active connection. Please initialize first.")
            return None
        
        try:
            # Encrypt the request
            aes_key = self.shared_secret[:32]
            aesgcm = AESGCM(aes_key)
            nonce = os.urandom(12)
            
            
            message = json.dumps(request_data).encode()
            ciphertext = aesgcm.encrypt(nonce, message, None)
            
            payload = {
                'client_id': self.client_id,
                'nonce': self.base64_encode(nonce),
                'ciphertext': self.base64_encode(ciphertext)
            }
            
            # Send the encrypted request
            logger.info(f"Sending encrypted request: {request_data['type']}")
            response = requests.post(f"{self.server_url}/vpn", json=payload)
            response_data = response.json()
            
            if 'error' in response_data:
                logger.error(f"Server error: {response_data['error']}")
                return None
            
            # Decrypt the response
            resp_nonce = self.base64_decode(response_data['nonce'])
            resp_ciphertext = self.base64_decode(response_data['ciphertext'])
            
            plaintext = aesgcm.decrypt(resp_nonce, resp_ciphertext, None)
            decrypted_response = json.loads(plaintext.decode())
            
            logger.info(f"Received encrypted response from server")
            return decrypted_response
            
        except Exception as e:
            logger.error(f"Error in encrypted communication: {str(e)}")
            return None
    
    def search(self, query):
        """Send a search query to the server"""
        request_data = {
            'type': 'search',
            'query': query,
            'timestamp': time.time()
        }
        
        return self.send_encrypted_request(request_data)
        
    def process_result_click(self, url):
        """Process when a user clicks on a search result"""
        request_data = {
            'type': 'click_result',
            'url': url,
            'timestamp': time.time()
        }
        
        return self.send_encrypted_request(request_data)
        
    def request_video(self, url):
        """Request YouTube video data from server"""
        request_data = {
            'type': 'video_request',
            'url': url,
            'timestamp': time.time()
        }
        
        return self.send_encrypted_request(request_data)

#IP OF TELSANG LAPTOP
#client = PQVPNClient("http://192.168.15.229:5000")

client = PQVPNClient()


@app.route('/')
def home():
    """Serve the main search interface"""
    return render_template('index.html')

@app.route('/init', methods=['GET'])
def init_connection():
    """Initialize the PQC connection"""
    if client.initialize_connection():
        return jsonify({'status': 'connected'})
    return jsonify({'error': 'Failed to establish connection'}), 500

@app.route('/vpn', methods=['POST'])
def handle_search():
    """Handle search requests from the web interface"""
    try:
        data = request.json
        query = data.get('query', '')
        
        if not query:
            return jsonify({'error': 'No query provided'}), 400
            
        logger.info(f"Processing search request for: '{query}'")
        
        # Use the PQC client to perform the search
        search_results = client.search(query)
        
        if not search_results:
            return jsonify({'error': 'Failed to perform search'}), 500
            
        return jsonify(search_results)
        
    except Exception as e:
        logger.error(f"Error in search: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/result', methods=['POST'])
def handle_result_click():
    """Handle when a user clicks on a search result"""
    try:
        data = request.json
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
            
        logger.info(f"Processing result click for URL: '{url}'")
        
        # Use the PQC client to process the click
        content_data = client.process_result_click(url)
        
        if not content_data:
            return jsonify({'error': 'Failed to process result click'}), 500
            
        return jsonify(content_data)
        
    except Exception as e:
        logger.error(f"Error processing result click: {str(e)}")
        return jsonify({'error': str(e)}), 500
        
@app.route('/video', methods=['POST'])
def handle_video_request():
    """Handle when a user requests a YouTube video"""
    try:
        data = request.json
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'No video URL provided'}), 400
            
        logger.info(f"Processing video request for URL: '{url}'")
        
        # Use the PQC client to request video data
        video_data = client.request_video(url)
        
        if not video_data:
            return jsonify({'error': 'Failed to process video request'}), 500
            
        return jsonify(video_data)
        
    except Exception as e:
        logger.error(f"Error processing video request: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Run on port 5001 
    app.run(host='0.0.0.0', port=5001, debug=True) 