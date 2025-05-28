// frontend/src/components/scanners/SSLScanner.jsx
import React, { useState } from 'react';
import { FaLock, FaSpinner, FaArrowLeft, FaCheckCircle, FaExclamationTriangle } from 'react-icons/fa';
import { api } from '../../utils/api';
import { historyService } from '../../services/historyService';
import SSLResults from './SSLResults';
import '../../styles/SSLScanner.css';

const SSLScanner = ({ onBack }) => {
  const [target, setTarget] = useState('');
  const [port, setPort] = useState('443');
  const [options, setOptions] = useState({
    checkVulnerabilities: true,
    checkCiphers: true,
    checkChain: true
  });
  
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  
  const handleOptionChange = (name) => {
    setOptions(prev => ({
      ...prev,
      [name]: !prev[name]
    }));
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResults(null);
    const startTime = Date.now();
    
    const scanOptions = {
      port: parseInt(port),
      ...options
    };
    
    try {
      console.log("Sending SSL scan request:", { target, scan_options: scanOptions });
      const response = await api.runSSLScan(target, scanOptions);
      console.log("Received SSL scan response:", response);
      
      const endTime = Date.now();
      const duration = `${Math.round((endTime - startTime) / 1000)}s`;
      
      if (response && response.status === 'success') {
        setResults(response.results);
        
        // Save to history
        historyService.saveScan({
          scanType: 'ssl',
          target: target,
          scanOptions: scanOptions,
          results: response.results,
          status: 'completed',
          duration: duration
        });
      } else if (response && response.status === 'error') {
        setError(response.message);
        
        // Save failed scan to history
        historyService.saveScan({
          scanType: 'ssl',
          target: target,
          scanOptions: scanOptions,
          error: response.message,
          status: 'failed',
          duration: duration
        });
      }
    } catch (err) {
      console.error("SSL scan error:", err);
      const errorMessage = err.response?.data?.message || err.message || 'An error occurred during the SSL scan';
      setError(errorMessage);
      
      // Save failed scan to history
      historyService.saveScan({
        scanType: 'ssl',
        target: target,
        scanOptions: scanOptions,
        error: errorMessage,
        status: 'failed',
        duration: `${Math.round((Date.now() - startTime) / 1000)}s`
      });
    } finally {
      setLoading(false);
    }
  };
  
  return (
    <div className="ssl-scanner-container">
      <button onClick={onBack} className="back-button">
        <FaArrowLeft /> Back to scanner selection
      </button>
      
      <div className="card">
        <div className="scanner-header">
          <div className="scanner-icon ssl">
            <FaLock />
          </div>
          <h2>SSL/TLS Scanner</h2>
        </div>
        <p className="scanner-description">
          Scan SSL/TLS configuration, check certificate validity, supported protocols, and known vulnerabilities.
        </p>
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label" htmlFor="target">
              Target Domain/IP
            </label>
            <input
              id="target"
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g., example.com or 192.168.1.1"
              className="form-input"
              required
            />
            <p className="form-help">
              Enter domain name or IP address to scan SSL/TLS configuration
            </p>
          </div>
          
          <div className="form-group">
            <label className="form-label" htmlFor="port">
              Port (Optional)
            </label>
            <input
              id="port"
              type="number"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder="443"
              className="form-input"
              min="1"
              max="65535"
            />
            <p className="form-help">
              Default is 443. Change for non-standard HTTPS ports.
            </p>
          </div>
          
          <div className="scan-options">
            <h3 className="scan-options-title">Scan Options</h3>
            
            <div className="checkbox-group">
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.checkVulnerabilities}
                    onChange={() => handleOptionChange('checkVulnerabilities')}
                    className="form-checkbox"
                  />
                  <span>Check for Vulnerabilities</span>
                </label>
                <p className="form-help">
                  Test for known SSL/TLS vulnerabilities (Heartbleed, POODLE, etc.)
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.checkCiphers}
                    onChange={() => handleOptionChange('checkCiphers')}
                    className="form-checkbox"
                  />
                  <span>Analyze Cipher Suites</span>
                </label>
                <p className="form-help">
                  Check supported cipher suites and their strength
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.checkChain}
                    onChange={() => handleOptionChange('checkChain')}
                    className="form-checkbox"
                  />
                  <span>Verify Certificate Chain</span>
                </label>
                <p className="form-help">
                  Validate the complete certificate chain
                </p>
              </div>
            </div>
          </div>
          
          <button
            type="submit"
            className="btn btn-primary btn-scan"
            disabled={loading}
          >
            {loading ? (
              <span className="loading-text">
                <FaSpinner className="icon-spin" /> Scanning...
              </span>
            ) : (
              'Start SSL Scan'
            )}
          </button>
        </form>
      </div>
      
      {loading && (
        <div className="card scan-progress">
          <div className="progress-content">
            <FaSpinner className="icon-spin large-spinner" />
            <h3>SSL/TLS Scan in Progress...</h3>
            <p>
              Checking certificate, protocols, cipher suites, and vulnerabilities...
            </p>
            <div className="progress-tips">
              <h4>What we're checking:</h4>
              <ul>
                <li>Certificate validity and expiration</li>
                <li>Supported SSL/TLS protocols</li>
                <li>Cipher suite strength</li>
                <li>Known vulnerabilities</li>
                <li>Certificate chain validation</li>
                <li>Security configuration issues</li>
              </ul>
            </div>
          </div>
        </div>
      )}
      
      {error && (
        <div className="alert alert-error">
          <div className="alert-title">Error</div>
          <p>{error}</p>
        </div>
      )}
      
      {results && <SSLResults results={results} />}
    </div>
  );
};

export default SSLScanner;