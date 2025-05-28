// frontend/src/components/scanners/PoisoningScanner.jsx
import React, { useState } from 'react';
import { FaExclamationTriangle, FaSpinner, FaArrowLeft } from 'react-icons/fa';
import { api } from '../../utils/api';
import { historyService } from '../../services/historyService';
import PoisoningResults from './PoisoningResults';
import '../../styles/PoisoningScanner.css';

const PoisoningScanner = ({ onBack }) => {
  const [target, setTarget] = useState('');
  const [options, setOptions] = useState({
    checkSERP: true,
    checkBlacklist: true,
    checkPhishing: true,
    checkMaliciousSEO: true,
    checkRedirects: true
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
      ...options
    };
    
    try {
      console.log("Sending poisoning scan request:", { target, scan_options: scanOptions });
      const response = await api.runPoisoningScan(target, scanOptions);
      console.log("Received poisoning scan response:", response);
      
      const endTime = Date.now();
      const duration = `${Math.round((endTime - startTime) / 1000)}s`;
      
      if (response && response.status === 'success') {
        setResults(response.results);
        
        // Save to history
        historyService.saveScan({
          scanType: 'poisoning',
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
          scanType: 'poisoning',
          target: target,
          scanOptions: scanOptions,
          error: response.message,
          status: 'failed',
          duration: duration
        });
      }
    } catch (err) {
      console.error("Poisoning scan error:", err);
      const errorMessage = err.response?.data?.message || err.message || 'An error occurred during the poisoning scan';
      setError(errorMessage);
      
      // Save failed scan to history
      historyService.saveScan({
        scanType: 'poisoning',
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
    <div className="poisoning-scanner-container">
      <button onClick={onBack} className="back-button">
        <FaArrowLeft /> Back to scanner selection
      </button>
      
      <div className="card">
        <div className="scanner-header">
          <div className="scanner-icon poisoning">
            <FaExclamationTriangle />
          </div>
          <h2>Google Poisoning Scanner</h2>
        </div>
        <p className="scanner-description">
          Detect search engine poisoning, malicious SEO activities, and Google blacklisting issues.
        </p>
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label" htmlFor="target">
              Target Domain
            </label>
            <input
              id="target"
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g., example.com"
              className="form-input"
              required
            />
            <p className="form-help">
              Enter the domain to check for search engine poisoning
            </p>
          </div>
          
          <div className="scan-options">
            <h3 className="scan-options-title">Scan Options</h3>
            
            <div className="checkbox-group">
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.checkSERP}
                    onChange={() => handleOptionChange('checkSERP')}
                    className="form-checkbox"
                  />
                  <span>Check Search Results</span>
                </label>
                <p className="form-help">
                  Analyze search engine results for poisoning indicators
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.checkBlacklist}
                    onChange={() => handleOptionChange('checkBlacklist')}
                    className="form-checkbox"
                  />
                  <span>Blacklist Check</span>
                </label>
                <p className="form-help">
                  Check if domain is blacklisted by Google Safe Browsing
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.checkPhishing}
                    onChange={() => handleOptionChange('checkPhishing')}
                    className="form-checkbox"
                  />
                  <span>Phishing Detection</span>
                </label>
                <p className="form-help">
                  Check for phishing attempts and malicious content
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.checkMaliciousSEO}
                    onChange={() => handleOptionChange('checkMaliciousSEO')}
                    className="form-checkbox"
                  />
                  <span>Malicious SEO Check</span>
                </label>
                <p className="form-help">
                  Detect black hat SEO techniques and cloaking
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.checkRedirects}
                    onChange={() => handleOptionChange('checkRedirects')}
                    className="form-checkbox"
                  />
                  <span>Check Malicious Redirects</span>
                </label>
                <p className="form-help">
                  Detect suspicious redirects and URL manipulations
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
              'Start Poisoning Scan'
            )}
          </button>
        </form>
      </div>
      
      {loading && (
        <div className="card scan-progress">
          <div className="progress-content">
            <FaSpinner className="icon-spin large-spinner" />
            <h3>Google Poisoning Scan in Progress...</h3>
            <p>
              Analyzing search engine results and SEO indicators...
            </p>
            <div className="progress-tips">
              <h4>What we're checking:</h4>
              <ul>
                <li>Search engine result poisoning</li>
                <li>Google Safe Browsing status</li>
                <li>Malicious SEO techniques</li>
                <li>Phishing attempts</li>
                <li>Cloaking and redirects</li>
                <li>Blacklist status</li>
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
      
      {results && <PoisoningResults results={results} />}
    </div>
  );
};

export default PoisoningScanner;