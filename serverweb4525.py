from flask import Flask, request, jsonify
import oqs
import json
import base64
import os
import re
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
from yt_dlp import YoutubeDL

app = Flask(__name__)

# Configure simplified logging for demonstration purposes
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - [SERVER] - %(message)s')
logger = logging.getLogger(__name__)

# Server keys
kyber_server = None
dilithium_server = None
active_sessions = {}  # Store client sessions with their shared secrets

def generate_server_keys():
    """Generate and store server's Kyber and Dilithium keypairs"""
    global kyber_server, dilithium_server
    
    logger.info("📝 Generating server Post-Quantum Cryptography keys...")
    
    # Kyber keys for key exchange
    kyber_server = oqs.KeyEncapsulation("Kyber768")
    kyber_public_key = kyber_server.generate_keypair()
    logger.info("🔑 Kyber key pair generated (Key encapsulation for shared secret)")
    
    # Dilithium keys for signatures
    dilithium_server = oqs.Signature("Dilithium3")
    dilithium_public_key = dilithium_server.generate_keypair()
    logger.info("🔑 Dilithium key pair generated (Digital signatures for authentication)")
    
    logger.info("✅ Server PQC keys successfully generated")
    return kyber_public_key, dilithium_public_key

def base64_encode(data):
    """Helper function to base64 encode binary data"""
    return base64.b64encode(data).decode('utf-8')

def base64_decode(data):
    """Helper function to base64 decode string to binary"""
    return base64.b64decode(data.encode('utf-8'))

def extract_youtube_video_id(url):
    """Extract YouTube video ID from various YouTube URL formats"""
    youtube_regex = r'(?:youtube\.com\/(?:[^\/]+\/.+\/|(?:v|e(?:mbed)?)\/|.*[?&]v=)|youtu\.be\/)([^"&?\/\s]{11})'
    match = re.search(youtube_regex, url)
    return match.group(1) if match else None

def is_youtube_url(url):
    """Check if a URL is a YouTube video URL"""
    return bool(extract_youtube_video_id(url))

def search_web(query):
    """Perform a web search for the given query and return results"""
    try:
        
        formatted_query = quote_plus(query)
        
        
        search_url = f"https://html.duckduckgo.com/html/?q={formatted_query}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(search_url, headers=headers)
        
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        
        results = []
        for result in soup.select('.result'):
            title_element = result.select_one('.result__title')
            link_element = result.select_one('.result__url')
            snippet_element = result.select_one('.result__snippet')
            
            if title_element and link_element:
                title = title_element.get_text(strip=True)
                link = link_element.get_text(strip=True)
                
                
                if not link.startswith(('http://', 'https://')):
                    link = 'https://' + link
                
                snippet = snippet_element.get_text(strip=True) if snippet_element else "No description available"
                
                # Check if it's a YouTube link to add an indicator
                is_youtube = is_youtube_url(link)
                
                results.append({
                    'title': title,
                    'url': link,
                    'snippet': snippet,
                    'is_youtube': is_youtube
                })
        
        # Limit to top 10 results
        return results[:10]
        
    except Exception as e:
        logger.error(f"Error performing web search: {str(e)}")
        return [{'title': 'Error', 'url': '', 'snippet': f'Failed to perform search: {str(e)}'}]

def get_page_content(url):
    """Fetch and return content from a given URL"""
    try:
        # Check if it's a YouTube URL
        if is_youtube_url(url):
            video_id = extract_youtube_video_id(url)
            return {
                'title': f"YouTube Video (ID: {video_id})",
                'url': url,
                'html_content': f'<div class="youtube-placeholder" data-video-id="{video_id}">This is a YouTube video. Click "Load Video" to view it through the secure VPN.</div>',
                'full_html': f'<div class="youtube-placeholder" data-video-id="{video_id}">This is a YouTube video. Click "Load Video" to view it through the secure VPN.</div>',
                'is_youtube': True,
                'video_id': video_id,
                'status': 'success'
            }
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # Parse the content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract title
        title = soup.title.text if soup.title else "No title"
        
        # Extract base URL for handling relative links
        base_url = '/'.join(url.split('/')[:3])  # http(s)://domain.com
        path_base = '/'.join(url.split('/')[:-1]) + '/' if '/' in url[8:] else url
        
        # Process images: Convert all image URLs to absolute URLs
        for img in soup.find_all('img'):
            if img.get('src'):
                # Handle relative URLs
                img_src = img['src'].strip()
                if img_src.startswith('//'):
                    # Protocol-relative URL
                    img['src'] = 'https:' + img_src
                elif img_src.startswith('/'):
                    # Root-relative URL
                    img['src'] = base_url + img_src
                elif not img_src.startswith(('http://', 'https://')):
                    # Page-relative URL
                    img['src'] = path_base + img_src
                    
        # Process links: Make all links go through our proxy
        for a in soup.find_all('a'):
            if a.get('href'):
                href = a['href'].strip()
                
                # Skip javascript: links, anchors, and other non-HTTP links
                if href.startswith(('javascript:', '#', 'mailto:', 'tel:')) or not href:
                    continue
                    
                # Handle different URL types
                if href.startswith('//'):
                    # Protocol-relative URL
                    full_url = 'https:' + href
                elif href.startswith('/'):
                    # Root-relative URL
                    full_url = base_url + href
                elif not href.startswith(('http://', 'https://')):
                    # Page-relative URL
                    full_url = path_base + href
                else:
                    # Absolute URL
                    full_url = href
                
                # Check if it's a YouTube link
                if is_youtube_url(full_url):
                    a['data-youtube'] = 'true'
                    
                # Store original href as data attribute 
                a['data-original-href'] = full_url
                a['href'] = '#'
                a['onclick'] = f"return handleProxiedLink('{full_url}')"
                
        # Remove scripts to prevent unexpected behavior
        for script in soup.find_all('script'):
            script.decompose()
            
        # Handle forms - disable or redirect through proxy
        for form in soup.find_all('form'):
            form['onsubmit'] = "alert('Forms are disabled in secure browsing mode.'); return false;"
            
        # Find main content - try to extract meaningful section
        main_content = None
        for selector in ['article', 'main', '.content', '#content', '.main', '.article', '#main']:
            content_elem = soup.select_one(selector)
            if content_elem:
                main_content = content_elem
                break
        
        # If no main content found, use body
        if not main_content and soup.body:
            main_content = soup.body
            
        # Add our own script to handle proxied links
        proxy_script = soup.new_tag('script')
        proxy_script.string = """
        function handleProxiedLink(url) {
            if (window.parent && window.parent.handleProxiedLink) {
                return window.parent.handleProxiedLink(url);
            }
            return false;
        }
        
        document.addEventListener('click', function(e) {
            if (e.target.tagName === 'A' && !e.target.getAttribute('onclick')) {
                e.preventDefault();
                var href = e.target.href;
                if (href && href.startsWith('http')) {
                    handleProxiedLink(href);
                }
            }
        }, true);
        """
        
        if main_content:
            main_content.append(proxy_script)
        
        # Return JSON with the HTML content and metadata
        return {
            'title': title,
            'url': url,
            'html_content': str(main_content) if main_content else "<div>No content found</div>",
            'full_html': str(soup),
            'is_youtube': False,
            'status': 'success'
        }
    except Exception as e:
        logger.error(f"Error fetching content from {url}: {str(e)}")
        return {
            'title': 'Error',
            'url': url,
            'html_content': f'<div class="error">Failed to fetch content: {str(e)}</div>',
            'full_html': f'<div class="error">Failed to fetch content: {str(e)}</div>',
            'is_youtube': False,
            'status': 'error'
        }

def get_youtube_video_data(video_url):
    """Use yt-dlp to extract video information from YouTube"""
    try:
        video_id = extract_youtube_video_id(video_url)
        if not video_id:
            return {
                'status': 'error',
                'error': 'Not a valid YouTube URL'
            }
        
        # Use yt-dlp to extract video information
        ydl_opts = {
            'format': 'best[height<=720]',  # Limit quality to reduce server load
            'quiet': True,
            'no_warnings': True,
            'extract_flat': False,
        }
        
        with YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(video_url, download=False)
            
            # Get video details
            video_data = {
                'id': video_id,
                'title': info.get('title', 'Unknown Title'),
                'thumbnail': info.get('thumbnail', ''),
                'duration': info.get('duration', 0),
                'uploader': info.get('uploader', 'Unknown'),
                'view_count': info.get('view_count', 0),
                'formats': []
            }
            
            # Get available formats and their URLs
            for format in info.get('formats', []):
                # Skip formats without height or url
                if not format.get('url') or format.get('height') is None:
                    continue
                    
                # Only add valid formats with height
                if format.get('height', 0) > 0:
                    video_data['formats'].append({
                        'format_id': format.get('format_id', ''),
                        'url': format.get('url', ''),
                        'height': format.get('height', 0),
                        'width': format.get('width', 0),
                        'ext': format.get('ext', 'mp4'),
                        'filesize': format.get('filesize', 0)
                    })
            
            # If no valid formats were found, add at least one default
            if len(video_data['formats']) == 0 and info.get('url'):
                video_data['formats'].append({
                    'format_id': 'default',
                    'url': info.get('url'),
                    'height': 360,
                    'width': 640,
                    'ext': 'mp4',
                    'filesize': 0
                })
            
            return {
                'status': 'success',
                'video_data': video_data
            }
            
    except Exception as e:
        logger.error(f"Error extracting YouTube data: {str(e)}")
        return {
            'status': 'error',
            'error': str(e)
        }

@app.route('/')
def home():
    """Serve the main page - entry point for the web app"""
    logger.info("Serving home page")
    return app.send_static_file('index.html')

@app.route('/init', methods=['GET'])
def init_connection():
    """Initialize a new connection by sharing the server's public keys"""
    client_ip = request.remote_addr
    logger.info(f"👋 New connection request from client {client_ip}")
    
    # Generate keys if not already done
    if not kyber_server or not dilithium_server:
        logger.info("🔑 First client connection - initializing server keys")
        kyber_pk, dilithium_pk = generate_server_keys()
    else:
        logger.info("🔑 Using existing server keys for new client")
        kyber_pk = kyber_server.export_public_key()
        dilithium_pk = dilithium_server.export_public_key()
    
    # Sign the Kyber public key with Dilithium
    logger.info("🔏 Signing Kyber public key with Dilithium signature")
    signature = dilithium_server.sign(kyber_pk)
    
    # Encode everything in base64 for JSON transmission
    response_data = {
        'kyber_public_key': base64_encode(kyber_pk),
        'dilithium_public_key': base64_encode(dilithium_pk),
        'signature': base64_encode(signature)
    }
    
    logger.info(f"📤 Sending public keys to client {client_ip}")
    return jsonify(response_data)

@app.route('/establish', methods=['POST'])
def establish_connection():
    """Establish a secure connection using the client's encrypted key"""
    client_ip = request.remote_addr
    logger.info(f"🔒 Connection establishment request from {client_ip}")
    
    data = request.json
    client_id = data.get('client_id')
    ciphertext_b64 = data.get('ciphertext')
    
    # Decode the ciphertext
    ciphertext = base64_decode(ciphertext_b64)
    
    # Decrypt the ciphertext to get the shared secret
    try:
        logger.info("🔑 Decapsulating shared secret from client's ciphertext")
        shared_secret = kyber_server.decap_secret(ciphertext)
        logger.info(f"✅ Shared secret successfully generated with client {client_id}")
    except Exception as e:
        logger.error(f"❌ Error decapsulating secret: {str(e)}")
        return jsonify({'error': 'Failed to establish connection'}), 500
    
    # Store the client session
    active_sessions[client_id] = {
        'shared_secret': shared_secret,
        'created_at': time.time(),
        'client_ip': client_ip
    }
    logger.info(f"📝 New secure session created for client {client_id}")
    
    # Send an encrypted confirmation
    try:
        # Use first 32 bytes as AES-GCM key
        aes_key = shared_secret[:32]
        
        aesgcm = AESGCM(aes_key)
        nonce = os.urandom(12)
        
        # Create confirmation message
        message = f"PQC VPN connection established at {time.ctime()}".encode()
        
        # Encrypt
        logger.info("🔒 Encrypting confirmation message with AES-GCM")
        ciphertext = aesgcm.encrypt(nonce, message, None)
        
        # Send response
        response_data = {
            'client_id': client_id,
            'nonce': base64_encode(nonce),
            'ciphertext': base64_encode(ciphertext)
        }
        
        logger.info(f"🔐 Secure connection successfully established with {client_id}")
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"❌ Error creating encrypted response: {str(e)}")
        return jsonify({'error': 'Failed to establish connection'}), 500

@app.route('/vpn', methods=['POST'])
def vpn_communication():
    """Handle encrypted VPN communication"""
    client_ip = request.remote_addr
    
    try:
        data = request.json
        client_id = data.get('client_id')
        nonce_b64 = data.get('nonce')
        ciphertext_b64 = data.get('ciphertext')
        
        logger.info(f"📨 Received encrypted request from client {client_id}")
        
        # Check if the client has an active session
        if client_id not in active_sessions:
            logger.warning(f"❌ Client {client_id} not found in active sessions")
            return jsonify({'error': 'Invalid client ID or session expired'}), 403
        
        # Get the shared secret for this client
        session = active_sessions[client_id]
        shared_secret = session['shared_secret']
        
        # Decode the nonce and ciphertext
        nonce = base64_decode(nonce_b64)
        ciphertext = base64_decode(ciphertext_b64)
        
        # Decrypt the request
        logger.info("🔓 Decrypting client request with AES-GCM")
        aes_key = shared_secret[:32]
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        
        # Parse the request
        request_data = json.loads(plaintext.decode())
        request_type = request_data.get('type', '')
        logger.info(f"📋 Request type: {request_type}")
        
        # Process based on request type
        response_data = None
        if request_type == 'search':
            query = request_data.get('query', '')
            logger.info(f"🔍 Processing search request for: '{query}'")
            
            logger.info(f"🌐 Searching web for query: '{query}'")
            search_results = search_web(query)
            logger.info(f"✅ Search complete. Found {len(search_results)} results")
            
            response_data = {
                'type': 'search_results',
                'query': query,
                'results': search_results,
                'result_count': len(search_results),
                'timestamp': time.time()
            }
            
        elif request_type == 'click_result':
            url = request_data.get('url', '')
            logger.info(f"🔍 Processing URL request: '{url}'")
            
            logger.info(f"🌐 Fetching content from: {url}")
            page_content = get_page_content(url)
            logger.info(f"✅ Content retrieved for {url}")
            
            response_data = {
                'type': 'page_content',
                'url': url,
                'content': page_content,
                'timestamp': time.time()
            }
            
        elif request_type == 'video_request':
            url = request_data.get('url', '')
            logger.info(f"🎬 Processing YouTube video request: '{url}'")
            
            logger.info(f"🌐 Fetching video data from YouTube")
            video_data = get_youtube_video_data(url)
            logger.info(f"✅ Video data retrieved")
            
            response_data = {
                'type': 'video_data',
                'url': url,
                'video_data': video_data,
                'timestamp': time.time()
            }
            
        else:
            logger.warning(f"❓ Unknown request type: {request_type}")
            return jsonify({'error': 'Invalid request type'}), 400
        
        # Encrypt the response
        logger.info("🔒 Encrypting response with AES-GCM")
        resp_nonce = os.urandom(12)
        resp_plaintext = json.dumps(response_data).encode()
        resp_ciphertext = aesgcm.encrypt(resp_nonce, resp_plaintext, None)
        
        # Send the encrypted response
        encrypted_response = {
            'nonce': base64_encode(resp_nonce),
            'ciphertext': base64_encode(resp_ciphertext)
        }
        
        logger.info(f"📤 Sending encrypted response to client {client_id}")
        return jsonify(encrypted_response)
        
    except Exception as e:
        logger.error(f"❌ Error in VPN communication: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    logger.info("🚀 Starting Post-Quantum Cryptography VPN Server")
    app.run(host='0.0.0.0', port=5000, debug=True)