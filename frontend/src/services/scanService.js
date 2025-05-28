// frontend/src/services/scanService.js
import { startScan, updateScanProgress, completeScan, scanError } from '../store/scanSlice';

class ScanService {
  constructor(store) {
    this.store = store;
    this.pollingIntervals = {};
  }

  startScanning = async (target, scannerType, scanMode) => {
    try {
      const response = await fetch('http://localhost:5000/api/scan/web/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target, mode: scanMode })
      });
      
      const data = await response.json();
      
      if (data.status === 'started') {
        const scanId = data.scan_id;
        
        // Dispatch to store
        this.store.dispatch(startScan({
          scanId, 
          target,
          scanner: scannerType,
        }));
        
        // Start background polling
        this.startPolling(scanId);
        
        return scanId;
      }
      
      throw new Error(data.message || 'Failed to start scan');
    } catch (error) {
      console.error('Error starting scan:', error);
      throw error;
    }
  }
  
  startPolling = (scanId) => {
    // Poll every second
    this.pollingIntervals[scanId] = setInterval(async () => {
      try {
        const response = await fetch(`http://localhost:5000/api/scan/web/progress/${scanId}`);
        const data = await response.json();
        
        if (data.status === 'not_found') {
          this.stopPolling(scanId);
          this.store.dispatch(scanError({ scanId, error: 'Scan not found' }));
          return;
        }
        
        // Update progress
        this.store.dispatch(updateScanProgress({
          scanId,
          progress: data.progress,
          phase: data.phase
        }));
        
        // Check if complete
        if (data.status === 'completed') {
          this.stopPolling(scanId);
          this.store.dispatch(completeScan({ 
            scanId, 
            results: {
              vulnerabilities: data.alerts,
              total: data.total_alerts,
              target: data.target,
              mode: data.mode
            }
          }));
          
          // Save to localStorage for history
          this.saveToHistory(scanId, data);
        } else if (data.status === 'error') {
          this.stopPolling(scanId);
          this.store.dispatch(scanError({ scanId, error: data.error }));
        }
      } catch (error) {
        console.error('Polling error:', error);
      }
    }, 1000);
  }
  
  stopPolling = (scanId) => {
    if (this.pollingIntervals[scanId]) {
      clearInterval(this.pollingIntervals[scanId]);
      delete this.pollingIntervals[scanId];
    }
  }
  
  saveToHistory = (scanId, data) => {
    try {
      // Count by severity
      const severityCounts = { High: 0, Medium: 0, Low: 0, Informational: 0 };
      
      data.alerts.forEach(alert => {
        const risk = alert.risk || 'Informational';
        if (risk in severityCounts) {
          severityCounts[risk]++;
        }
      });
      
      // Format history item
      const historyItem = {
        id: scanId,
        timestamp: new Date().toISOString(),
        target: data.target,
        type: 'web',
        vulnerabilities: data.alerts,
        total: data.total_alerts,
        mode: data.mode,
        ...severityCounts,
        highestRisk: this.getHighestRisk(severityCounts)
      };
      
      // Get existing history
      const history = JSON.parse(localStorage.getItem('scanHistory') || '[]');
      
      // Add new item
      history.unshift(historyItem);
      
      // Limit to 50 items
      if (history.length > 50) {
        history.pop();
      }
      
      // Save back
      localStorage.setItem('scanHistory', JSON.stringify(history));
    } catch (error) {
      console.error('Error saving to history:', error);
    }
  }
  
  getHighestRisk = (counts) => {
    if (counts.High > 0) return 'High';
    if (counts.Medium > 0) return 'Medium';
    if (counts.Low > 0) return 'Low';
    return 'Informational';
  }
}

export default ScanService;