// frontend/src/utils/api.js
import axios from 'axios';

// Set the base URL for the API - Pastikan ini sesuai dengan alamat server backend Anda
const API_URL = 'http://localhost:5000/api';

export const api = {
  // Check API status
  getStatus: async () => {
    try {
      console.log('Checking API status...');
      const response = await axios.get(`${API_URL}/status`);
      console.log('API Status:', response.data);
      return response.data;
    } catch (error) {
      console.error('Error fetching status:', error);
      throw error;
    }
  },
  
  // Get list of all available scanners
  getScanners: async () => {
    try {
      console.log('Fetching scanners from:', `${API_URL}/scanners`);
      const response = await axios.get(`${API_URL}/scanners`);
      console.log('Scanners response:', response.data);
      return response.data;
    } catch (error) {
      console.error('Error fetching scanners:', error);
      throw error;
    }
  },
  
  // Enhanced port scan methods
  getScanOptions: async () => {
    try {
      console.log('Fetching scan options...');
      const response = await axios.get(`${API_URL}/scan-options`);
      console.log('Scan options response:', response.data);
      return response.data.data;
    } catch (error) {
      console.error('Error fetching scan options:', error);
      // Return default options if API fails
      return {
        profiles: {
          quick_scan: {
            name: 'Quick scan',
            description: 'Scan top 100 ports quickly',
            estimated_time: '30-60 seconds'
          },
          intense: {
            name: 'Intense scan', 
            description: 'Comprehensive scan with OS detection, version detection, script scanning, and traceroute',
            estimated_time: '5-15 minutes'
          },
          regular_scan: {
            name: 'Regular scan',
            description: 'Basic port scan of top 1000 ports', 
            estimated_time: '1-5 minutes'
          }
        }
      };
    }
  },

  getScanProfiles: async () => {
    try {
      console.log('Fetching scan profiles...');
      const response = await axios.get(`${API_URL}/scan-profiles`);
      console.log('Scan profiles response:', response.data);
      return response.data.data;
    } catch (error) {
      console.error('Error fetching scan profiles:', error);
      throw error;
    }
  },
  
  // Enhanced port scan - New method
  runEnhancedPortScan: async (target, scanOptions = {}) => {
    try {
      console.log("Sending enhanced port scan request:", { target, scan_options: scanOptions });
      const response = await axios.post(`${API_URL}/port-scan`, {
        target: target,
        scan_options: scanOptions
      });
      console.log("Received enhanced port scan response:", response.data);
      return response.data;
    } catch (error) {
      console.error("Error during enhanced port scan:", error);
      throw error;
    }
  },
  
  // Legacy port scan - Keep for backward compatibility
  runPortScan: async (target, scan_options) => {
    try {
      console.log("Sending port scan request:", { target, scan_options });
      
      // Try new enhanced endpoint first
      try {
        const response = await axios.post(`${API_URL}/port-scan`, { 
          target, 
          scan_options 
        });
        console.log("Received port scan response (new endpoint):", response.data);
        return response.data;
      } catch (enhancedError) {
        console.log("New endpoint failed, trying legacy endpoint...");
        
        // Fallback to legacy endpoint
        const response = await axios.post(`${API_URL}/scan/port`, { 
          target, 
          scan_options 
        });
        console.log("Received port scan response (legacy endpoint):", response.data);
        return response.data;
      }
    } catch (error) {
      console.error("Error during port scan:", error);
      throw error;
    }
  },
  
  // Run SSL scan
  runSSLScan: async (target, scan_options) => {
    try {
      console.log("Sending SSL scan request:", { target, scan_options });
      const response = await axios.post(`${API_URL}/scan/ssl`, { 
        target, 
        scan_options 
      });
      console.log("Received SSL scan response:", response.data);
      return response.data;
    } catch (error) {
      console.error("Error during SSL scan:", error);
      throw error;
    }
  },
  
  // Run web vulnerability scan
  runWebScan: async (target, scan_options) => {
    try {
      console.log("Sending web scan request:", { target, scan_options });
      const response = await axios.post(`${API_URL}/scan/web/start`, { 
        target, 
        mode: scan_options?.mode || 'basic'
      });
      console.log("Received web scan response:", response.data);
      return response.data;
    } catch (error) {
      console.error("Error during web scan:", error);
      throw error;
    }
  },
  
  // Run subdomain scan
  runSubdomainScan: async (target, scan_options) => {
    try {
      console.log("Sending subdomain scan request:", { target, scan_options });
      const response = await axios.post(`${API_URL}/scan/subdomain`, { 
        target, 
        scan_options 
      });
      console.log("Received subdomain scan response:", response.data);
      return response.data;
    } catch (error) {
      console.error("Error during subdomain scan:", error);
      throw error;
    }
  },
  
  // Run defacement scan  
  runDefacementScan: async (target, scan_options) => {
    try {
      console.log("Sending defacement scan request:", { target, scan_options });
      const response = await axios.post(`${API_URL}/scan/defacement`, { 
        target, 
        scan_options 
      });
      console.log("Received defacement scan response:", response.data);
      return response.data;
    } catch (error) {
      console.error("Error during defacement scan:", error);
      throw error;
    }
  },

  // Run Google poisoning scan
  runPoisoningScan: async (target, scan_options) => {
    try {
      console.log("Sending poisoning scan request:", { target, scan_options });
      const response = await axios.post(`${API_URL}/scan/poisoning`, { 
        target, 
        scan_options 
      });
      console.log("Received poisoning scan response:", response.data);
      return response.data;
    } catch (error) {
      console.error("Error during poisoning scan:", error);
      throw error;
    }
  },
  
  // Run Google dorking scan
  runGoogleDorkingScan: async (target, scan_options) => {
    try {
      console.log("Sending Google dorking scan request:", { target, scan_options });
      const response = await axios.post(`${API_URL}/scan/google-dorking`, { 
        target, 
        scan_options 
      });
      console.log("Received Google dorking scan response:", response.data);
      return response.data;
    } catch (error) {
      console.error("Error during Google dorking scan:", error);
      throw error;
    }
  },
  
  // Run VirusTotal URL scan
  runVirusTotalUrlScan: async (target) => {
    try {
      console.log("Sending VirusTotal URL scan request:", { target });
      const response = await axios.post(`${API_URL}/virustotal/url`, { 
        target 
      });
      console.log("Received VirusTotal URL scan response:", response.data);
      return response.data;
    } catch (error) {
      console.error("Error during VirusTotal URL scan:", error);
      throw error;
    }
  },
  
  // Run VirusTotal File scan
  runVirusTotalFileScan: async (file) => {
    try {
      console.log("Sending VirusTotal File scan request");
      const formData = new FormData();
      formData.append('file', file);
      
      const response = await axios.post(`${API_URL}/virustotal/file`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        }
      });
      console.log("Received VirusTotal File scan response:", response.data);
      return response.data;
    } catch (error) {
      console.error("Error during VirusTotal File scan:", error);
      throw error;
    }
  },
  
  // Get VirusTotal scan status
  getVirusTotalScanStatus: async (scanId) => {
    try {
      console.log("Fetching VirusTotal scan status:", scanId);
      const response = await axios.get(`${API_URL}/virustotal/status/${scanId}`);
      console.log("Received VirusTotal scan status response:", response.data);
      return response.data;
    } catch (error) {
      console.error("Error fetching VirusTotal scan status:", error);
      throw error;
    }
  },
  
  // Get scan history from backend
  getScanHistory: async () => {
    try {
      const response = await axios.get(`${API_URL}/user/history`);
      return response.data;
    } catch (error) {
      console.error("Error fetching scan history:", error);
      throw error;
    }
  },
  
  // Get scan details by ID (if implemented)
  getScanDetails: async (scanId) => {
    try {
      const response = await axios.get(`${API_URL}/history/${scanId}`);
      return response.data;
    } catch (error) {
      console.error("Error fetching scan details:", error);
      throw error;
    }
  },
  
  // Delete scan from history (if implemented)
  deleteScan: async (scanId) => {
    try {
      const response = await axios.delete(`${API_URL}/history/${scanId}`);
      return response.data;
    } catch (error) {
      console.error("Error deleting scan:", error);
      throw error;
    }
  },
  
  // Export scan results (if implemented)
  exportScan: async (scanId, format = 'pdf') => {
    try {
      const response = await axios.get(`${API_URL}/export/${scanId}`, {
        params: { format },
        responseType: 'blob' // Important for file downloads
      });
      return response.data;
    } catch (error) {
      console.error("Error exporting scan:", error);
      throw error;
    }
  },
  
  // Get system statistics (if implemented)
  getStatistics: async () => {
    try {
      const response = await axios.get(`${API_URL}/statistics`);
      return response.data;
    } catch (error) {
      console.error("Error fetching statistics:", error);
      throw error;
    }
  },
  
  // Validate target helper
  validateTarget: async (target) => {
    try {
      console.log("Validating target:", target);
      const response = await axios.post(`${API_URL}/validate-target`, { target });
      console.log("Target validation response:", response.data);
      return response.data;
    } catch (error) {
      console.error("Error validating target:", error);
      // Return basic validation if API endpoint doesn't exist
      const isValidIP = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(target);
      const isValidDomain = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(target);
      const isValidURL = /^https?:\/\/.+/.test(target);
      
      return {
        valid: isValidIP || isValidDomain || isValidURL,
        type: isValidIP ? 'ip' : isValidDomain ? 'domain' : isValidURL ? 'url' : 'unknown'
      };
    }
  },
  
  // Test connection to backend
  testConnection: async () => {
    try {
      const endpoints = [
        `${API_URL}/status`,
        `${API_URL}/debug-test`,
        `${API_URL}/routes`,
        `${API_URL}/scan-options`,
        `${API_URL}/scan-profiles`
      ];
      
      const results = {};
      
      for (const endpoint of endpoints) {
        try {
          console.log(`Testing endpoint: ${endpoint}`);
          const response = await axios.get(endpoint);
          results[endpoint] = {
            success: true,
            status: response.status,
            data: response.data
          };
        } catch (error) {
          results[endpoint] = {
            success: false,
            status: error.response?.status || 'unknown',
            error: error.message
          };
        }
      }
      
      return {
        success: true,
        results
      };
    } catch (error) {
      console.error("Connection test failed:", error);
      return {
        success: false,
        error: error.message
      };
    }
  },

  // Utility method to get Nmap command preview
  getNmapCommandPreview: async (target, scanOptions) => {
    try {
      const response = await axios.post(`${API_URL}/nmap-preview`, {
        target,
        scan_options: scanOptions
      });
      return response.data;
    } catch (error) {
      console.error("Error getting Nmap command preview:", error);
      // Return basic preview if API fails
      return {
        command: `nmap ${target}`,
        estimated_time: 'varies'
      };
    }
  }
};

// Axios interceptors for global error handling
axios.interceptors.request.use(
  config => {
    // You can add auth headers here if needed
    // config.headers.Authorization = `Bearer ${token}`;
    
    // Add timestamp to prevent caching issues
    if (config.method === 'get') {
      config.params = {
        ...config.params,
        _t: Date.now()
      };
    }
    
    return config;
  },
  error => {
    return Promise.reject(error);
  }
);

axios.interceptors.response.use(
  response => {
    return response;
  },
  error => {
    if (error.response) {
      // Server responded with error status
      console.error('Server Error:', error.response.data);
      console.error('Status:', error.response.status);
      
      // Handle specific error codes
      if (error.response.status === 404) {
        console.warn('Endpoint not found, this might be expected for new features');
      } else if (error.response.status === 500) {
        console.error('Internal server error - check backend logs');
      }
    } else if (error.request) {
      // Request was made but no response
      console.error('Network Error:', error.request);
      console.error('Backend might be down or unreachable');
    } else {
      // Something else happened
      console.error('Error:', error.message);
    }
    return Promise.reject(error);
  }
);

// Export default
export default api;