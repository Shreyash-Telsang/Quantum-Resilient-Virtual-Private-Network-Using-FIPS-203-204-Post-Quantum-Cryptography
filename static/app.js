class PQVPNSearch {
    constructor() {
        this.searchInput = document.getElementById('searchInput');
        this.searchButton = document.getElementById('searchButton');
        this.resultsContainer = document.getElementById('results');
        this.loadingElement = document.getElementById('loading');
        this.connectionStatus = document.getElementById('connectionStatus');
        this.lastSearchQuery = '';
        
        this.initializeEventListeners();
        this.initializeConnection();
        
        // Add event listener for proxied links
        window.handleProxiedLink = this.handleProxiedLink.bind(this);
        window.handleYouTubeVideo = this.handleYouTubeVideo.bind(this);
    }

    initializeEventListeners() {
        this.searchButton.addEventListener('click', () => this.performSearch());
        this.searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.performSearch();
            }
        });
    }

    async initializeConnection() {
        try {
            const response = await fetch('/init');
            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }

            this.connectionStatus.textContent = 'Connected';
            this.connectionStatus.classList.add('status-connected');
        } catch (error) {
            console.error('Connection error:', error);
            this.connectionStatus.textContent = 'Connection failed';
            this.connectionStatus.classList.add('status-error');
        }
    }

    async performSearch() {
        const query = this.searchInput.value.trim();
        
        if (!query) {
            return;
        }
        
        this.lastSearchQuery = query;
        this.showLoading();
        this.clearResults();

        try {
            const response = await fetch('/vpn', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    type: 'search',
                    query: query
                })
            });

            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }

            this.displayResults(data.results);
        } catch (error) {
            console.error('Search error:', error);
            this.showError('Failed to perform search. Please try again.');
        } finally {
            this.hideLoading();
        }
    }

    displayResults(results) {
        const resultsContainer = document.getElementById('results');
        resultsContainer.innerHTML = '';
        
        if (!results || results.length === 0) {
            resultsContainer.innerHTML = '<p class="no-results">No results found</p>';
            return;
        }
        
        // Create search header
        const searchHeader = document.createElement('div');
        searchHeader.className = 'search-header';
        searchHeader.innerHTML = `<h2>Results for: "${this.lastSearchQuery}"</h2>`;
        resultsContainer.appendChild(searchHeader);
        
        results.forEach(result => {
            const resultCard = document.createElement('div');
            resultCard.className = 'result-card';
            
            if (result.is_youtube) {
                resultCard.classList.add('youtube-result');
            }
            
            // Create title link
            const titleLink = document.createElement('a');
            titleLink.href = '#'; // Use # to prevent default navigation
            titleLink.textContent = result.title;
            titleLink.className = 'result-title';
            
            // Create URL display
            const urlDisplay = document.createElement('div');
            urlDisplay.className = 'result-url';
            urlDisplay.textContent = result.url;
            
            // Create snippet
            const snippet = document.createElement('p');
            snippet.className = 'result-snippet';
            snippet.textContent = result.snippet;
            
            // Add YouTube indicator if applicable
            if (result.is_youtube) {
                const youtubeIndicator = document.createElement('div');
                youtubeIndicator.className = 'youtube-indicator';
                youtubeIndicator.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M19.615 3.184c-3.604-.246-11.631-.245-15.23 0-3.897.266-4.356 2.62-4.385 8.816.029 6.185.484 8.549 4.385 8.816 3.6.245 11.626.246 15.23 0 3.897-.266 4.356-2.62 4.385-8.816-.029-6.185-.484-8.549-4.385-8.816zm-10.615 12.816v-8l8 3.993-8 4.007z"/></svg> YouTube Video';
                resultCard.appendChild(youtubeIndicator);
            }
            
            // Add click handler to process through the server
            titleLink.addEventListener('click', (e) => {
                e.preventDefault(); // Prevent default link behavior
                if (result.is_youtube) {
                    this.handleYouTubeVideo(result.url);
                } else {
                    this.handleResultClick(result.url);
                }
            });
            
            resultCard.appendChild(titleLink);
            resultCard.appendChild(urlDisplay);
            resultCard.appendChild(snippet);
            resultsContainer.appendChild(resultCard);
        });
    }
    
    async handleResultClick(url) {
        this.showLoading();
        
        try {
            const response = await fetch('/result', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    url: url
                })
            });

            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }

            this.displayPageContent(data);
        } catch (error) {
            console.error('Error processing result click:', error);
            this.showError('Failed to load content. Please try again.');
        } finally {
            this.hideLoading();
        }
    }
    
    // Handle proxied links (when a user clicks a link inside a proxied page)
    handleProxiedLink(url) {
        // Check if it's a YouTube URL (simplified check)
        if (url.includes('youtube.com/watch') || url.includes('youtu.be/')) {
            this.handleYouTubeVideo(url);
        } else {
            this.handleResultClick(url);
        }
        return false; // Prevent default link behavior
    }
    
    // Handle YouTube video requests
    async handleYouTubeVideo(url) {
        this.showLoading();
        
        try {
            const response = await fetch('/video', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    url: url
                })
            });

            const data = await response.json();
            
            if (data.error) {
                throw new Error(data.error);
            }

            this.displayVideoPlayer(data);
        } catch (error) {
            console.error('Error processing video:', error);
            this.showError('Failed to load video. Please try again.');
        } finally {
            this.hideLoading();
        }
    }
    
    displayVideoPlayer(data) {
        // Clear the results container
        this.clearResults();
        
        // Handle error in video data
        if (!data.video_data || data.video_data.status !== 'success') {
            const errorMessage = data.video_data && data.video_data.error 
                ? data.video_data.error 
                : 'Unknown error occurred while loading the video.';
                
            this.showError(`Failed to load video: ${errorMessage}`);
            
            // Add a button to try again
            const retryContainer = document.createElement('div');
            retryContainer.className = 'retry-container';
            
            const retryButton = document.createElement('button');
            retryButton.className = 'retry-button';
            retryButton.textContent = 'Try Again';
            retryButton.addEventListener('click', () => {
                this.handleYouTubeVideo(data.url);
            });
            
            // Add button to go back to search results
            const backButton = document.createElement('button');
            backButton.className = 'back-button';
            backButton.innerHTML = '&larr; Back to Results';
            backButton.addEventListener('click', () => {
                if (this.lastSearchQuery) {
                    this.searchInput.value = this.lastSearchQuery;
                    this.performSearch();
                } else {
                    this.clearResults();
                }
            });
            
            retryContainer.appendChild(retryButton);
            retryContainer.appendChild(backButton);
            this.resultsContainer.appendChild(retryContainer);
            return;
        }
        
        const videoData = data.video_data.video_data;
        
        // Create a container for the video player
        const videoContainer = document.createElement('div');
        videoContainer.className = 'video-container';
        
        // Create header with the title and back button
        const header = document.createElement('div');
        header.className = 'content-header';
        
        const backButton = document.createElement('button');
        backButton.className = 'back-button';
        backButton.innerHTML = '&larr; Back to Results';
        backButton.addEventListener('click', () => {
            if (this.lastSearchQuery) {
                this.searchInput.value = this.lastSearchQuery;
                this.performSearch(); // Return to search results
            } else {
                this.clearResults();
            }
        });
        
        const titleElement = document.createElement('h2');
        titleElement.textContent = videoData.title || 'YouTube Video';
        
        header.appendChild(backButton);
        header.appendChild(titleElement);
        
        // Create video details section
        const detailsSection = document.createElement('div');
        detailsSection.className = 'video-details';
        
        const uploaderInfo = document.createElement('div');
        uploaderInfo.className = 'video-uploader';
        uploaderInfo.innerHTML = `
            <span class="uploader-name">${videoData.uploader || 'Unknown'}</span>
            <span class="view-count">${this.formatViewCount(videoData.view_count || 0)} views</span>
        `;
        
        detailsSection.appendChild(uploaderInfo);
        
        // Check if we have formats
        if (!videoData.formats || videoData.formats.length === 0) {
            // No formats available, show error with retry option
            const errorMessage = document.createElement('div');
            errorMessage.className = 'error-message';
            errorMessage.textContent = 'No playable video formats found. The video may be restricted or unavailable.';
            
            const retryButton = document.createElement('button');
            retryButton.className = 'retry-button';
            retryButton.textContent = 'Try Again';
            retryButton.addEventListener('click', () => {
                this.handleYouTubeVideo(data.url);
            });
            
            videoContainer.appendChild(header);
            videoContainer.appendChild(errorMessage);
            videoContainer.appendChild(retryButton);
            
            this.resultsContainer.appendChild(videoContainer);
            return;
        }
        
        // Find the best format that's not too large
        let selectedFormat = null;
        
        // First try to find a 720p format
        for (const format of videoData.formats) {
            if (format.height === 720) {
                selectedFormat = format;
                break;
            }
        }
        
        // If no 720p, take the first format with height <= 720p
        if (!selectedFormat && videoData.formats.length > 0) {
            selectedFormat = videoData.formats.find(f => f.height <= 720) || videoData.formats[0];
        }
        
        // Create video player
        const videoElement = document.createElement('video');
        videoElement.controls = true;
        videoElement.autoplay = false;
        videoElement.className = 'video-player';
        videoElement.poster = videoData.thumbnail || '';
        
        const sourceElement = document.createElement('source');
        sourceElement.src = selectedFormat.url;
        sourceElement.type = `video/${selectedFormat.ext || 'mp4'}`;
        
        videoElement.appendChild(sourceElement);
        
        // Add quality selector if there are multiple formats
        let qualitySelector = null;
        if (videoData.formats.length > 1) {
            qualitySelector = document.createElement('div');
            qualitySelector.className = 'quality-selector';
            
            const label = document.createElement('span');
            label.textContent = 'Quality: ';
            qualitySelector.appendChild(label);
            
            const select = document.createElement('select');
            
            // Group formats by height
            const formatsByHeight = {};
            videoData.formats.forEach(format => {
                if (format.height > 0) {
                    formatsByHeight[format.height] = formatsByHeight[format.height] || [];
                    formatsByHeight[format.height].push(format);
                }
            });
            
            // Add options from highest to lowest quality
            Object.keys(formatsByHeight)
                .map(Number)
                .sort((a, b) => b - a)
                .forEach(height => {
                    const format = formatsByHeight[height][0]; // Take first format of this height
                    const option = document.createElement('option');
                    option.value = format.format_id;
                    option.textContent = `${height}p`;
                    option.selected = format.format_id === selectedFormat.format_id;
                    select.appendChild(option);
                });
                
            select.addEventListener('change', (e) => {
                const formatId = e.target.value;
                const newFormat = videoData.formats.find(f => f.format_id === formatId);
                if (newFormat) {
                    // Save current time
                    const currentTime = videoElement.currentTime;
                    const wasPlaying = !videoElement.paused;
                    
                    // Update source
                    sourceElement.src = newFormat.url;
                    sourceElement.type = `video/${newFormat.ext || 'mp4'}`;
                    
                    // Reload and restore state
                    videoElement.load();
                    videoElement.currentTime = currentTime;
                    if (wasPlaying) {
                        videoElement.play();
                    }
                }
            });
            
            qualitySelector.appendChild(select);
        }
        
        // Create toolbar with external link
        const toolbar = document.createElement('div');
        toolbar.className = 'video-toolbar';
        
        const externalLink = document.createElement('a');
        externalLink.href = data.url;
        externalLink.target = '_blank';
        externalLink.rel = 'noopener noreferrer';
        externalLink.className = 'external-link';
        externalLink.textContent = 'Watch on YouTube';
        
        toolbar.appendChild(externalLink);
        if (qualitySelector) {
            toolbar.appendChild(qualitySelector);
        }
        
        // Video error handling
        videoElement.addEventListener('error', (e) => {
            console.error('Video playback error:', e);
            
            // Create error message
            const errorMessage = document.createElement('div');
            errorMessage.className = 'video-error';
            errorMessage.innerHTML = `
                <p>Error playing video. This may be due to:</p>
                <ul>
                    <li>The video requires authentication</li>
                    <li>The video is age-restricted</li>
                    <li>The video is not available in your region</li>
                    <li>YouTube blocked the access</li>
                </ul>
                <p>Try opening it directly on YouTube instead.</p>
            `;
            
            // Replace video player with error message
            videoElement.parentNode.replaceChild(errorMessage, videoElement);
        });
        
        // Assemble the video player
        videoContainer.appendChild(header);
        videoContainer.appendChild(detailsSection);
        videoContainer.appendChild(videoElement);
        videoContainer.appendChild(toolbar);
        
        this.resultsContainer.appendChild(videoContainer);
    }
    
    formatViewCount(count) {
        if (!count) return '0';
        
        if (count < 1000) return count.toString();
        if (count < 1000000) return Math.floor(count/1000) + 'K';
        return Math.floor(count/1000000) + 'M';
    }
    
    displayPageContent(data) {
        // Clear the results container
        this.clearResults();
        
        const pageContent = data.content;
        
        // Create a container for the page content
        const contentContainer = document.createElement('div');
        contentContainer.className = 'page-content';
        
        // Create a header with the title and back button
        const header = document.createElement('div');
        header.className = 'content-header';
        
        const backButton = document.createElement('button');
        backButton.className = 'back-button';
        backButton.innerHTML = '&larr; Back to Results';
        backButton.addEventListener('click', () => {
            if (this.lastSearchQuery) {
                this.searchInput.value = this.lastSearchQuery;
                this.performSearch(); // Return to search results
            } else {
                this.clearResults();
            }
        });
        
        const titleElement = document.createElement('h2');
        titleElement.textContent = pageContent.title;
        
        const urlElement = document.createElement('div');
        urlElement.className = 'content-url';
        urlElement.textContent = data.url;
        
        header.appendChild(backButton);
        header.appendChild(titleElement);
        
        // Check if this is a YouTube video
        if (pageContent.is_youtube) {
            const videoContainer = document.createElement('div');
            videoContainer.className = 'content-youtube-placeholder';
            
            const loadButton = document.createElement('button');
            loadButton.className = 'load-video-button';
            loadButton.textContent = 'Load Video Through Secure VPN';
            loadButton.addEventListener('click', () => {
                this.handleYouTubeVideo(data.url);
            });
            
            // Add YouTube icon
            const youtubeIcon = document.createElement('div');
            youtubeIcon.className = 'youtube-icon';
            youtubeIcon.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="72" height="72" viewBox="0 0 24 24" fill="red"><path d="M19.615 3.184c-3.604-.246-11.631-.245-15.23 0-3.897.266-4.356 2.62-4.385 8.816.029 6.185.484 8.549 4.385 8.816 3.6.245 11.626.246 15.23 0 3.897-.266 4.356-2.62 4.385-8.816-.029-6.185-.484-8.549-4.385-8.816zm-10.615 12.816v-8l8 3.993-8 4.007z"/></svg>';
            
            const videoTitle = document.createElement('h3');
            videoTitle.textContent = pageContent.title;
            
            const videoId = pageContent.video_id;
            const thumbnailUrl = `https://img.youtube.com/vi/${videoId}/maxresdefault.jpg`;
            
            videoContainer.style.backgroundImage = `url(${thumbnailUrl})`;
            videoContainer.appendChild(youtubeIcon);
            videoContainer.appendChild(videoTitle);
            videoContainer.appendChild(loadButton);
            
            // Create the toolbar with external link
            const toolbar = document.createElement('div');
            toolbar.className = 'content-toolbar';
            
            const externalLink = document.createElement('a');
            externalLink.href = data.url;
            externalLink.target = '_blank';
            externalLink.rel = 'noopener noreferrer';
            externalLink.className = 'external-link';
            externalLink.textContent = 'Open in new tab';
            
            toolbar.appendChild(externalLink);
            
            // Assemble the content
            contentContainer.appendChild(header);
            contentContainer.appendChild(urlElement);
            contentContainer.appendChild(toolbar);
            contentContainer.appendChild(videoContainer);
            
            this.resultsContainer.appendChild(contentContainer);
            return;
        }
        
        // Create the toolbar
        const toolbar = document.createElement('div');
        toolbar.className = 'content-toolbar';
        
        const externalLink = document.createElement('a');
        externalLink.href = data.url;
        externalLink.target = '_blank';
        externalLink.rel = 'noopener noreferrer';
        externalLink.className = 'external-link';
        externalLink.textContent = 'Open in new tab';
        
        const viewModeToggle = document.createElement('button');
        viewModeToggle.className = 'view-mode-toggle';
        viewModeToggle.textContent = 'Toggle Full Page View';
        viewModeToggle.addEventListener('click', () => {
            const contentFrame = document.querySelector('.content-frame');
            if (contentFrame.classList.contains('content-frame-full')) {
                contentFrame.classList.remove('content-frame-full');
                viewModeToggle.textContent = 'Toggle Full Page View';
            } else {
                contentFrame.classList.add('content-frame-full');
                viewModeToggle.textContent = 'Toggle Normal View';
            }
        });
        
        toolbar.appendChild(viewModeToggle);
        toolbar.appendChild(externalLink);
        
        // Create the content frame (iframe-like container)
        const contentFrame = document.createElement('div');
        contentFrame.className = 'content-frame';
        
        if (pageContent.status === 'error') {
            contentFrame.innerHTML = `<div class="error-message">Error: ${pageContent.html_content}</div>`;
        } else {
            // Create a sandboxed environment for the content
            const frameContent = document.createElement('div');
            frameContent.className = 'frame-content';
            
            // Insert the HTML content
            frameContent.innerHTML = pageContent.html_content;
            
            // Inject a script to handle links
            const linkHandler = document.createElement('script');
            linkHandler.textContent = `
                function handleProxiedLink(url) {
                    if (window.parent && window.parent.handleProxiedLink) {
                        return window.parent.handleProxiedLink(url);
                    }
                    return false;
                }
                
                // Add click handlers to any links that don't have them
                document.addEventListener('click', function(e) {
                    if (e.target.tagName === 'A' && e.target.href && !e.target.onclick) {
                        e.preventDefault();
                        if (e.target.href.startsWith('http')) {
                            handleProxiedLink(e.target.href);
                        }
                    }
                }, true);
            `;
            
            contentFrame.appendChild(frameContent);
            contentFrame.appendChild(linkHandler);
        }
        
        // Assemble the content
        contentContainer.appendChild(header);
        contentContainer.appendChild(urlElement);
        contentContainer.appendChild(toolbar);
        contentContainer.appendChild(contentFrame);
        
        this.resultsContainer.appendChild(contentContainer);
    }

    showLoading() {
        this.loadingElement.classList.remove('hidden');
    }

    hideLoading() {
        this.loadingElement.classList.add('hidden');
    }

    clearResults() {
        this.resultsContainer.innerHTML = '';
    }

    showError(message) {
        const errorCard = document.createElement('div');
        errorCard.className = 'result-card';
        errorCard.innerHTML = `
            <div class="result-title" style="color: var(--error-color);">
                ${message}
            </div>
        `;
        this.resultsContainer.appendChild(errorCard);
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new PQVPNSearch();
}); 