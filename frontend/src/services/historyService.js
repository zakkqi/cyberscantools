// frontend/src/services/historyService.js
class HistoryService {
  constructor() {
    this.storageKey = 'scanHistory';
    this.maxHistoryItems = 1000;
    this.initialized = false;
    this.init();
  }

  init() {
    if (this.initialized) return;
    
    console.log('Initializing History Service...');
    
    // Check for existing data and migrate if needed
    this.migrateExistingData();
    
    // Set up event listeners for storage changes
    window.addEventListener('storage', this.handleStorageChange.bind(this));
    
    this.initialized = true;
    console.log('History Service initialized');
  }

  // Migrate existing scanner data to unified history
  migrateExistingData() {
    const existingHistory = this.getStoredHistory();
    let migrationNeeded = false;
    
    // Define scanner storage patterns
    const scannerStorageKeys = [
      'portScanResults',
      'sslScanResults', 
      'webVulnResults',
      'subdomainResults',
      'defacementResults',
      'poisoningResults',
      'dorkingResults',
      'virusTotalResults'
    ];
    
    scannerStorageKeys.forEach(key => {
      const data = localStorage.getItem(key);
      if (data) {
        try {
          const parsed = JSON.parse(data);
          console.log(`Found legacy data in ${key}:`, parsed);
          
          // Convert legacy format
          const converted = this.convertLegacyData(parsed, key);
          if (converted.length > 0) {
            existingHistory.push(...converted);
            migrationNeeded = true;
          }
          
          // Optionally remove old data after migration
          // localStorage.removeItem(key);
        } catch (error) {
          console.warn(`Error migrating data from ${key}:`, error);
        }
      }
    });
    
    if (migrationNeeded) {
      console.log(`Migrated data. New total: ${existingHistory.length} items`);
      this.saveHistory(existingHistory);
    }
  }

  // Convert legacy data format to standardized format
  convertLegacyData(data, sourceKey) {
    const scannerTypeMap = {
      'portScanResults': 'port_scanner',
      'sslScanResults': 'ssl_scanner',
      'webVulnResults': 'web_vulnerability',
      'subdomainResults': 'subdomain_finder',
      'defacementResults': 'defacement_scanner',
      'poisoningResults': 'google_poisoning',
      'dorkingResults': 'google_dorking',
      'virusTotalResults': 'virustotal_scanner'
    };
    
    const converted = [];
    const items = Array.isArray(data) ? data : [data];
    
    items.forEach(item => {
      if (item && typeof item === 'object') {
        const standardized = {
          id: this.generateId(),
          timestamp: item.timestamp || new Date().toISOString(),
          scannerType: scannerTypeMap[sourceKey] || 'unknown',
          target: this.extractTarget(item),
          status: item.status || 'completed',
          duration: item.duration || 0,
          results: item.results || item.data || item,
          vulnerabilities: this.extractVulnerabilities(item),
          summary: this.generateSummary(item),
          metadata: {
            migrated: true,
            originalSource: sourceKey,
            migrationDate: new Date().toISOString()
          }
        };
        converted.push(standardized);
      }
    });
    
    return converted;
  }

  // Extract target from various data formats
  extractTarget(data) {
    return data.target || 
           data.url || 
           data.domain || 
           data.host || 
           data.ip || 
           data.hostname ||
           'Unknown Target';
  }

  // Extract vulnerabilities from scan data
  extractVulnerabilities(data) {
    if (data.vulnerabilities && Array.isArray(data.vulnerabilities)) {
      return data.vulnerabilities;
    }
    
    if (data.results && Array.isArray(data.results)) {
      return data.results.filter(result => 
        result.severity || 
        result.vulnerability || 
        result.risk || 
        result.issue ||
        result.alert
      );
    }
    
    return [];
  }

  // Generate summary statistics
  generateSummary(data) {
    const vulnerabilities = this.extractVulnerabilities(data);
    
    const summary = {
      total_found: 0,
      high_severity: 0,
      medium_severity: 0,
      low_severity: 0,
      info_severity: 0
    };
    
    if (data.results && Array.isArray(data.results)) {
      summary.total_found = data.results.length;
    }
    
    vulnerabilities.forEach(vuln => {
      const severity = (vuln.severity || vuln.risk || '').toLowerCase();
      switch (severity) {
        case 'high':
        case 'critical':
          summary.high_severity++;
          break;
        case 'medium':
        case 'moderate':
          summary.medium_severity++;
          break;
        case 'low':
          summary.low_severity++;
          break;
        case 'info':
        case 'informational':
          summary.info_severity++;
          break;
      }
    });
    
    return summary;
  }

  // Main method to save scan results - FIXED method name
  saveScanResult(scanData) {
    try {
      console.log('Saving scan result:', scanData);
      
      const history = this.getStoredHistory();
      
      // Create standardized record
      const record = {
        id: this.generateId(),
        timestamp: new Date().toISOString(),
        scannerType: scanData.scannerType || 'unknown',
        target: this.extractTarget(scanData),
        status: scanData.status || 'completed',
        duration: scanData.duration || 0,
        results: scanData.results || scanData.data || [],
        vulnerabilities: this.extractVulnerabilities(scanData),
        summary: this.generateSummary(scanData),
        metadata: {
          userAgent: navigator.userAgent,
          sessionId: this.getSessionId(),
          version: '1.0',
          ...scanData.metadata
        },
        // Preserve any additional data
        ...scanData
      };
      
      // Add to beginning (newest first)
      history.unshift(record);
      
      // Limit history size
      if (history.length > this.maxHistoryItems) {
        history.splice(this.maxHistoryItems);
      }
      
      // Save to storage
      this.saveHistory(history);
      
      console.log(`Scan saved. Total history: ${history.length} items`);
      return record;
      
    } catch (error) {
      console.error('Error saving scan result:', error);
      throw error;
    }
  }

  // Alias method for backward compatibility - ADDED this method
  saveScan(scanData) {
    return this.saveScanResult(scanData);
  }

  // Get all history
  getAllHistory() {
    return this.getStoredHistory();
  }

  // Get stored history from localStorage
  getStoredHistory() {
    try {
      const stored = localStorage.getItem(this.storageKey);
      if (stored) {
        const parsed = JSON.parse(stored);
        return Array.isArray(parsed) ? parsed : [];
      }
      return [];
    } catch (error) {
      console.error('Error retrieving history:', error);
      return [];
    }
  }

  // Save history to localStorage
  saveHistory(history) {
    try {
      localStorage.setItem(this.storageKey, JSON.stringify(history));
      return true;
    } catch (error) {
      console.error('Error saving history:', error);
      return false;
    }
  }

  // Filter history
  filterHistory(filters, historyData = null) {
    const history = historyData || this.getAllHistory();
    
    if (!filters || Object.keys(filters).length === 0) {
      return history;
    }
    
    return history.filter(scan => {
      // Date range filter
      if (filters.dateFrom || filters.dateTo) {
        const scanDate = new Date(scan.timestamp);
        if (filters.dateFrom && scanDate < new Date(filters.dateFrom)) return false;
        if (filters.dateTo && scanDate > new Date(filters.dateTo + 'T23:59:59')) return false;
      }
      
      // Scanner type filter
      if (filters.scannerType && filters.scannerType !== 'all') {
        if (scan.scannerType !== filters.scannerType) return false;
      }
      
      // Status filter
      if (filters.status && filters.status !== 'all') {
        if (scan.status !== filters.status) return false;
      }
      
      // Target filter
      if (filters.target) {
        const target = (scan.target || '').toLowerCase();
        const searchTerm = filters.target.toLowerCase();
        if (!target.includes(searchTerm)) return false;
      }
      
      // Severity filter
      if (filters.severity && filters.severity !== 'all') {
        const summary = scan.summary || {};
        switch (filters.severity) {
          case 'high':
            return summary.high_severity > 0;
          case 'medium':
            return summary.medium_severity > 0;
          case 'low':
            return summary.low_severity > 0;
          case 'info':
            return summary.info_severity > 0;
          default:
            return true;
        }
      }
      
      return true;
    });
  }

  // Sort history
  sortHistory(history, sortBy = 'timestamp', sortOrder = 'desc') {
    return [...history].sort((a, b) => {
      let aVal, bVal;
      
      switch (sortBy) {
        case 'timestamp':
          aVal = new Date(a.timestamp);
          bVal = new Date(b.timestamp);
          break;
        case 'scannerType':
          aVal = a.scannerType || '';
          bVal = b.scannerType || '';
          break;
        case 'target':
          aVal = a.target || '';
          bVal = b.target || '';
          break;
        case 'status':
          aVal = a.status || '';
          bVal = b.status || '';
          break;
        case 'duration':
          aVal = a.duration || 0;
          bVal = b.duration || 0;
          break;
        case 'vulnerabilities':
          aVal = (a.vulnerabilities || []).length;
          bVal = (b.vulnerabilities || []).length;
          break;
        default:
          aVal = a[sortBy] || '';
          bVal = b[sortBy] || '';
      }
      
      if (aVal < bVal) return sortOrder === 'asc' ? -1 : 1;
      if (aVal > bVal) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });
  }

  // Delete specific scan
  deleteScan(id) {
    try {
      const history = this.getAllHistory();
      const filtered = history.filter(scan => scan.id !== id);
      this.saveHistory(filtered);
      console.log(`Deleted scan ${id}`);
      return true;
    } catch (error) {
      console.error('Error deleting scan:', error);
      return false;
    }
  }

  // Clear all history
  clearHistory() {
    try {
      localStorage.removeItem(this.storageKey);
      console.log('History cleared');
      return true;
    } catch (error) {
      console.error('Error clearing history:', error);
      return false;
    }
  }

  // Get statistics
  getStats() {
    const history = this.getAllHistory();
    const stats = {
      total: history.length,
      byScanner: {},
      byStatus: {},
      totalVulnerabilities: 0,
      recentScans: 0,
      avgDuration: 0
    };
    
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
    let totalDuration = 0;
    
    history.forEach(scan => {
      // Count by scanner
      const type = scan.scannerType || 'unknown';
      stats.byScanner[type] = (stats.byScanner[type] || 0) + 1;
      
      // Count by status
      const status = scan.status || 'unknown';
      stats.byStatus[status] = (stats.byStatus[status] || 0) + 1;
      
      // Count vulnerabilities
      stats.totalVulnerabilities += (scan.vulnerabilities || []).length;
      
      // Count recent scans
      if (new Date(scan.timestamp) > yesterday) {
        stats.recentScans++;
      }
      
      // Calculate average duration
      totalDuration += scan.duration || 0;
    });
    
    stats.avgDuration = history.length > 0 ? Math.round(totalDuration / history.length) : 0;
    
    return stats;
  }

  // Utility methods
  generateId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
  }
  
  getSessionId() {
    let sessionId = sessionStorage.getItem('sessionId');
    if (!sessionId) {
      sessionId = this.generateId();
      sessionStorage.setItem('sessionId', sessionId);
    }
    return sessionId;
  }

  // Handle storage changes from other tabs
  handleStorageChange(event) {
    if (event.key === this.storageKey) {
      console.log('History updated in another tab');
      // Could emit event here for React components to update
    }
  }

  // Export/Import functionality
  exportHistory() {
    const history = this.getAllHistory();
    const dataStr = JSON.stringify(history, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `cyberscan_history_${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  importHistory(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        try {
          const data = JSON.parse(e.target.result);
          if (!Array.isArray(data)) {
            throw new Error('Invalid format: expected array');
          }
          
          const current = this.getAllHistory();
          const merged = [...current, ...data];
          
          // Remove duplicates
          const unique = merged.filter((scan, index, self) => 
            index === self.findIndex(s => 
              s.timestamp === scan.timestamp && 
              s.target === scan.target &&
              s.scannerType === scan.scannerType
            )
          );
          
          this.saveHistory(unique);
          resolve(unique.length - current.length);
        } catch (error) {
          reject(error);
        }
      };
      reader.readAsText(file);
    });
  }
}

// Create singleton instance
export const historyService = new HistoryService();

// Export for debugging
if (typeof window !== 'undefined') {
  window.historyService = historyService;
}