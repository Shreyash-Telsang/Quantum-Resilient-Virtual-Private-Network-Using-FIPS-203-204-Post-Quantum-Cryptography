import oqs
import requests
import json
import base64
import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging

# Configure logging
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
            
            # Extract server's public keys
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
            
            # Establish secure connection
            payload = {
                'ciphertext': self.base64_encode(ciphertext),
                'client_id': f"client_{int(time.time())}"
            }
            
            logger.info("Establishing secure connection...")
            response = requests.post(f"{self.server_url}/establish", json=payload)
            establish_data = response.json()
            
            # Store client ID
            self.client_id = establish_data['client_id']
            
            # Decrypt confirmation message
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
            
            # Prepare request payload
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

def display_search_results(results):
    """Format and display search results in the terminal"""
    if not results:
        print("\nNo search results found.")
        return
    
    print(f"\n----- Search Results for: '{results['query']}' -----")
    print(f"Found {results['result_count']} results\n")
    
    for i, result in enumerate(results['results'], 1):
        print(f"{i}. {result['title']}")
        print(f"   URL: {result['url']}")
        print(f"   {result['snippet']}")
        print()
    
    print("-" * 50)

def run_search_client():
    """Run the client with interactive search capability"""
    client = PQVPNClient()
    
    # Initialize connection with server
    if client.initialize_connection():
        print("\n🔒 Secure connection established 🔒")
        print("Welcome to the PQ-VPN Search Client")
        print("Type your search queries below (or type 'exit' to quit)")
        
        while True:
            query = input("\nEnter search query: ")
            
            if query.lower() in ['exit', 'quit', 'q']:
                print("Exiting client. Goodbye!")
                break
            
            if not query.strip():
                print("Please enter a valid search query.")
                continue
            
            print("Searching...")
            search_results = client.search(query)
            
            if search_results and search_results['type'] == 'search_results':
                display_search_results(search_results)
            else:
                print("Error: Could not retrieve search results.")
    else:
        print("Failed to establish secure connection with server.")

if __name__ == "__main__":
    run_search_client()