// frontend/src/components/scanners/SubdomainScanner.jsx
import React, { useState } from 'react';
import { FaSearch, FaSpinner, FaArrowLeft, FaCog } from 'react-icons/fa';
import { api } from '../../utils/api';
import { historyService } from '../../services/historyService';
import SubdomainResults from './SubdomainResults';
import '../../styles/SubdomainScanner.css';

const SubdomainScanner = ({ onBack }) => {
  const [target, setTarget] = useState('');
  const [wordlistOption, setWordlistOption] = useState('standard');
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
  const [options, setOptions] = useState({
    dns_enumeration: true,
    certificate_transparency: true,
    dns_records: true,
    whois_info: false,
    check_http: false,
    include_unresolved: true
  });
  
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState('');
  const [currentStep, setCurrentStep] = useState(0);
  
  const handleOptionChange = (name) => {
    setOptions(prev => ({
      ...prev,
      [name]: !prev[name]
    }));
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!target.trim()) return;
    
    setLoading(true);
    setError(null);
    setResults(null);
    setProgress('Initializing scan...');
    setCurrentStep(0);
    
    const startTime = Date.now();
    const scanOptions = {
      ...options,
      wordlist: wordlistOption
    };
    
    try {
      // Simulate progress updates with steps
      const progressSteps = [
        { step: 0, text: 'Performing DNS enumeration...' },
        { step: 1, text: 'Searching Certificate Transparency logs...' },
        { step: 2, text: 'Processing DNS records...' },
        { step: 2, text: 'Resolving subdomains...' },
        { step: 2, text: 'Finalizing results...' }
      ];
      
      let stepIndex = 0;
      const progressInterval = setInterval(() => {
        if (stepIndex < progressSteps.length) {
          setProgress(progressSteps[stepIndex].text);
          setCurrentStep(progressSteps[stepIndex].step);
          stepIndex++;
        }
      }, 1500);
      
      const response = await api.runSubdomainScan(target, scanOptions);
      clearInterval(progressInterval);
      
      const endTime = Date.now();
      const duration = `${Math.round((endTime - startTime) / 1000)}s`;
      
      if (response && response.status === 'success') {
        setResults(response.results);
        
        // Save to history
        historyService.saveScan({
          scanType: 'subdomain',
          target: target,
          scanOptions: scanOptions,
          results: response.results,
          status: 'completed',
          duration: duration
        });
      } else {
        throw new Error(response?.message || 'Scan failed');
      }
    } catch (err) {
      const errorMessage = err.response?.data?.message || err.message || 'An error occurred during the subdomain scan';
      setError(errorMessage);
      
      // Save failed scan to history
      historyService.saveScan({
        scanType: 'subdomain',
        target: target,
        scanOptions: scanOptions,
        error: errorMessage,
        status: 'failed',
        duration: `${Math.round((Date.now() - startTime) / 1000)}s`
      });
    } finally {
      setLoading(false);
      setProgress('');
      setCurrentStep(0);
    }
  };
  
  return (
    <div className="subdomain-scanner-container">
      <button onClick={onBack} className="back-button">
        <FaArrowLeft /> Back to scanner selection
      </button>
      
      <div className="card">
        <div className="scanner-header">
          <div className="scanner-icon subdomain">
            <FaSearch />
          </div>
          <div>
            <h2>Subdomain Scanner</h2>
            <p className="scanner-description">
              Discover subdomains using DNS enumeration and Certificate Transparency logs
            </p>
          </div>
        </div>
        
        <form onSubmit={handleSubmit} className="scanner-form">
          {/* Target Input */}
          <div className="form-group">
            <label className="form-label" htmlFor="target">
              Target Domain *
            </label>
            <input
              id="target"
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="example.com"
              className="form-input"
              required
            />
          </div>
          
          {/* Wordlist Selection */}
          <div className="form-group">
            <label className="form-label">Wordlist Size</label>
            <div className="radio-group">
              <label className="radio-option">
                <input
                  type="radio"
                  name="wordlist"
                  value="quick"
                  checked={wordlistOption === 'quick'}
                  onChange={(e) => setWordlistOption(e.target.value)}
                />
                <span>Quick (9 words) - Fast scan</span>
              </label>
              <label className="radio-option">
                <input
                  type="radio"
                  name="wordlist"
                  value="standard"
                  checked={wordlistOption === 'standard'}
                  onChange={(e) => setWordlistOption(e.target.value)}
                />
                <span>Standard (35 words) - Balanced</span>
              </label>
              <label className="radio-option">
                <input
                  type="radio"
                  name="wordlist"
                  value="comprehensive"
                  checked={wordlistOption === 'comprehensive'}
                  onChange={(e) => setWordlistOption(e.target.value)}
                />
                <span>Comprehensive (100+ words) - Thorough</span>
              </label>
            </div>
          </div>
          
          {/* Advanced Options Toggle */}
          <div className="form-group">
            <button
              type="button"
              className="advanced-toggle"
              onClick={() => setShowAdvancedOptions(!showAdvancedOptions)}
            >
              <FaCog /> Advanced Options
              <span className={`arrow ${showAdvancedOptions ? 'open' : ''}`}>▼</span>
            </button>
          </div>
          
          {/* Advanced Options */}
          {showAdvancedOptions && (
            <div className="advanced-options">
              <div className="options-grid">
                <label className="checkbox-option">
                  <input
                    type="checkbox"
                    checked={options.dns_enumeration}
                    onChange={() => handleOptionChange('dns_enumeration')}
                  />
                  <span>DNS Enumeration</span>
                  <small>Use wordlist to find subdomains</small>
                </label>
                
                <label className="checkbox-option">
                  <input
                    type="checkbox"
                    checked={options.certificate_transparency}
                    onChange={() => handleOptionChange('certificate_transparency')}
                  />
                  <span>Certificate Transparency</span>
                  <small>Search CT logs for subdomains</small>
                </label>
                
                <label className="checkbox-option">
                  <input
                    type="checkbox"
                    checked={options.dns_records}
                    onChange={() => handleOptionChange('dns_records')}
                  />
                  <span>DNS Records</span>
                  <small>Query A, MX, NS, TXT records</small>
                </label>
                
                <label className="checkbox-option">
                  <input
                    type="checkbox"
                    checked={options.whois_info}
                    onChange={() => handleOptionChange('whois_info')}
                  />
                  <span>WHOIS Information</span>
                  <small>Get domain registration details</small>
                </label>
                
                <label className="checkbox-option">
                  <input
                    type="checkbox"
                    checked={options.check_http}
                    onChange={() => handleOptionChange('check_http')}
                  />
                  <span>HTTP Status Check</span>
                  <small>Check if subdomains are web accessible</small>
                </label>
                
                <label className="checkbox-option">
                  <input
                    type="checkbox"
                    checked={options.include_unresolved}
                    onChange={() => handleOptionChange('include_unresolved')}
                  />
                  <span>Include Unresolved</span>
                  <small>Show subdomains without IP addresses</small>
                </label>
              </div>
            </div>
          )}
          
          {/* Submit Button */}
          <button
            type="submit"
            className="btn btn-primary btn-scan"
            disabled={loading || !target.trim()}
          >
            {loading ? (
              <span className="loading-content">
                <FaSpinner className="icon-spin" />
                Scanning...
              </span>
            ) : (
              <>
                <FaSearch />
                Start Subdomain Scan
              </>
            )}
          </button>
        </form>
      </div>
      
      {/* Progress */}
      {loading && (
        <div className="card scan-progress">
          <div className="progress-container">
            <div className="progress-icon">
              <FaSpinner className="icon-spin" />
            </div>
            <div className="progress-content">
              <h3 className="progress-title">Subdomain Discovery in Progress</h3>
              <p className="progress-text">{progress || 'Starting scan...'}</p>
              
              <div className="progress-bar-container">
                <div className="progress-bar">
                  <div className="progress-bar-fill"></div>
                </div>
              </div>
              
              <div className="progress-steps">
                {['DNS Enumeration', 'Certificate Transparency', 'Processing Results'].map((stepName, index) => (
                  <div key={index} className={`step-item ${index <= currentStep ? 'active' : ''}`}>
                    <div className="step-dot"></div>
                    <span>{stepName}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
      
      {/* Error */}
      {error && (
        <div className="alert alert-error">
          <strong>Scan Failed</strong>
          <p>{error}</p>
        </div>
      )}
      
      {/* Results */}
      {results && <SubdomainResults results={results} />}
    </div>
  );
};

export default SubdomainScanner;