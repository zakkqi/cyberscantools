// frontend/src/hooks/useScannerIntegration.js
import { useCallback, useEffect } from 'react';
import { historyService } from '../services/historyService';

export const useScannerIntegration = () => {
  
  // Generic scan completion handler
  const handleScanComplete = useCallback((scanData, scannerType) => {
    try {
      console.log(`Scan completed for ${scannerType}:`, scanData);
      
      // Ensure we have required fields
      const standardizedData = {
        scannerType: scannerType,
        target: extractTarget(scanData),
        status: scanData.status || 'completed',
        duration: scanData.duration || 0,
        results: scanData.results || scanData.data || [],
        vulnerabilities: scanData.vulnerabilities || [],
        timestamp: scanData.timestamp || new Date().toISOString(),
        ...scanData // Preserve any additional data
      };
      
      // Save to history
      const savedRecord = historyService.saveScanResult(standardizedData);
      console.log('✅ Scan saved to history:', savedRecord.id);
      
      return savedRecord;
      
    } catch (error) {
      console.error('❌ Error saving scan to history:', error);
      // Return original data even if saving fails
      return scanData;
    }
  }, []);

  // Extract target from various scan data formats
  const extractTarget = (scanData) => {
    return scanData.target || 
           scanData.url || 
           scanData.domain || 
           scanData.host || 
           scanData.ip || 
           scanData.hostname ||
           'Unknown Target';
  };

  // Specific handlers for each scanner type
  const handlePortScanComplete = useCallback((data) => {
    console.log('🔍 Port Scanner completed');
    return handleScanComplete(data, 'port_scanner');
  }, [handleScanComplete]);

  const handleSSLScanComplete = useCallback((data) => {
    console.log('🔒 SSL Scanner completed');
    return handleScanComplete(data, 'ssl_scanner');
  }, [handleScanComplete]);

  const handleWebVulnScanComplete = useCallback((data) => {
    console.log('🌐 Web Vulnerability Scanner completed');
    return handleScanComplete(data, 'web_vulnerability');
  }, [handleScanComplete]);

  const handleSubdomainScanComplete = useCallback((data) => {
    console.log('🔎 Subdomain Scanner completed');
    return handleScanComplete(data, 'subdomain_finder');
  }, [handleScanComplete]);

  const handleDefacementScanComplete = useCallback((data) => {
    console.log('🚨 Defacement Scanner completed');
    return handleScanComplete(data, 'defacement_scanner');
  }, [handleScanComplete]);

  const handleGooglePoisoningScanComplete = useCallback((data) => {
    console.log('☣️ Google Poisoning Scanner completed');
    return handleScanComplete(data, 'google_poisoning');
  }, [handleScanComplete]);

  const handleGoogleDorkingScanComplete = useCallback((data) => {
    console.log('🔍 Google Dorking Scanner completed');
    return handleScanComplete(data, 'google_dorking');
  }, [handleScanComplete]);

  const handleVirusTotalScanComplete = useCallback((data) => {
    console.log('🦠 VirusTotal Scanner completed');
    return handleScanComplete(data, 'virustotal_scanner');
  }, [handleScanComplete]);

  // Auto-integration effect
  useEffect(() => {
    console.log('🔧 Scanner integration hook initialized');
    
    // Expose handlers to window for debugging
    if (typeof window !== 'undefined') {
      window.scannerHandlers = {
        handlePortScanComplete,
        handleSSLScanComplete,
        handleWebVulnScanComplete,
        handleSubdomainScanComplete,
        handleDefacementScanComplete,
        handleGooglePoisoningScanComplete,
        handleGoogleDorkingScanComplete,
        handleVirusTotalScanComplete
      };
    }
    
    return () => {
      if (typeof window !== 'undefined' && window.scannerHandlers) {
        delete window.scannerHandlers;
      }
    };
  }, [
    handlePortScanComplete,
    handleSSLScanComplete,
    handleWebVulnScanComplete,
    handleSubdomainScanComplete,
    handleDefacementScanComplete,
    handleGooglePoisoningScanComplete,
    handleGoogleDorkingScanComplete,
    handleVirusTotalScanComplete
  ]);

  return {
    // Generic handler
    handleScanComplete,
    
    // Specific handlers
    handlePortScanComplete,
    handleSSLScanComplete,
    handleWebVulnScanComplete,
    handleSubdomainScanComplete,
    handleDefacementScanComplete,
    handleGooglePoisoningScanComplete,
    handleGoogleDorkingScanComplete,
    handleVirusTotalScanComplete,
    
    // Utility functions
    extractTarget
  };
};

// HOC to automatically integrate scanner components
export const withScannerIntegration = (ScannerComponent, scannerType) => {
  return function IntegratedScanner(props) {
    const { handleScanComplete } = useScannerIntegration();
    
    // Get the appropriate handler
    const getHandler = () => {
      switch (scannerType) {
        case 'port_scanner': return (data) => handleScanComplete(data, 'port_scanner');
        case 'ssl_scanner': return (data) => handleScanComplete(data, 'ssl_scanner');
        case 'web_vulnerability': return (data) => handleScanComplete(data, 'web_vulnerability');
        case 'subdomain_finder': return (data) => handleScanComplete(data, 'subdomain_finder');
        case 'defacement_scanner': return (data) => handleScanComplete(data, 'defacement_scanner');
        case 'google_poisoning': return (data) => handleScanComplete(data, 'google_poisoning');
        case 'google_dorking': return (data) => handleScanComplete(data, 'google_dorking');
        case 'virustotal_scanner': return (data) => handleScanComplete(data, 'virustotal_scanner');
        default: return (data) => handleScanComplete(data, scannerType);
      }
    };
    
    const enhancedProps = {
      ...props,
      onScanComplete: getHandler(),
      scannerType: scannerType,
      // Pass original onScanComplete as onScanCompleteOriginal if it exists
      ...(props.onScanComplete && { onScanCompleteOriginal: props.onScanComplete })
    };
    
    return <ScannerComponent {...enhancedProps} />;
  };
};

// Utility function to wrap async scanner functions
export const wrapScannerFunction = (originalFunction, scannerType) => {
  return async (...args) => {
    const startTime = Date.now();
    
    try {
      console.log(`🚀 Starting ${scannerType} scan...`);
      
      // Call original function
      const result = await originalFunction(...args);
      
      // Calculate duration
      const duration = Date.now() - startTime;
      
      // Enhance result with metadata
      const enhancedResult = {
        ...result,
        duration,
        status: 'completed',
        timestamp: new Date().toISOString(),
        scannerType
      };
      
      // Save to history
      historyService.saveScanResult(enhancedResult);
      console.log(`✅ ${scannerType} scan completed in ${duration}ms`);
      
      return enhancedResult;
      
    } catch (error) {
      const duration = Date.now() - startTime;
      
      // Save failed scan to history
      const failedResult = {
        target: args[0] || 'Unknown',
        status: 'failed',
        error: error.message || 'Unknown error',
        duration,
        timestamp: new Date().toISOString(),
        scannerType,
        results: []
      };
      
      historyService.saveScanResult(failedResult);
      console.error(`❌ ${scannerType} scan failed after ${duration}ms:`, error);
      
      throw error;
    }
  };
};

// Debugging utilities
export const debugScannerIntegration = () => {
  console.group('🔍 Scanner Integration Debug');
  
  const history = historyService.getAllHistory();
  console.log('Total history items:', history.length);
  
  // Group by scanner type
  const byType = {};
  history.forEach(scan => {
    const type = scan.scannerType || 'unknown';
    byType[type] = (byType[type] || 0) + 1;
  });
  console.log('Scans by type:', byType);
  
  // Check recent scans
  const recent = history.slice(0, 5);
  console.log('Recent scans:', recent);
  
  // Check localStorage keys
  const allKeys = Object.keys(localStorage);
  const scanKeys = allKeys.filter(key => 
    key.includes('scan') || key.includes('result') || key.includes('history')
  );
  console.log('Scan-related localStorage keys:', scanKeys);
  
  console.groupEnd();
  
  return { history: history.length, byType, recent, scanKeys };
};

// Export debug function to window
if (typeof window !== 'undefined') {
  window.debugScannerIntegration = debugScannerIntegration;
}