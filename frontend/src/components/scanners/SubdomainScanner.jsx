// frontend/src/components/scanners/SubdomainScanner.jsx
import React, { useState } from 'react';
import { FaSearch, FaSpinner, FaArrowLeft } from 'react-icons/fa';
import { api } from '../../utils/api';
import { historyService } from '../../services/historyService';
import SubdomainResults from './SubdomainResults';
import '../../styles/SubdomainScanner.css';

const SubdomainScanner = ({ onBack }) => {
  const [target, setTarget] = useState('');
  const [wordlistOption, setWordlistOption] = useState('default');
  const [customWordlist, setCustomWordlist] = useState('');
  const [options, setOptions] = useState({
    includeWhois: true,
    detectTechnologies: true,
    includeUnresolved: false,
    searchHistorical: true,
    interrogateDNS: true,
    useExternalAPIs: true,
    certificateTransparency: true,
    searchEngineQueries: true,
    checkSSLCertificates: true,
    reverseDNS: false,
    generatePermutations: true,
    cnameLookup: true
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
      ...options,
      wordlist: wordlistOption === 'custom' ? customWordlist : wordlistOption
    };
    
    try {
      console.log("Sending subdomain scan request:", { target, scan_options: scanOptions });
      const response = await api.runSubdomainScan(target, scanOptions);
      console.log("Received subdomain scan response:", response);
      
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
      } else if (response && response.status === 'error') {
        setError(response.message);
        
        // Save failed scan to history
        historyService.saveScan({
          scanType: 'subdomain',
          target: target,
          scanOptions: scanOptions,
          error: response.message,
          status: 'failed',
          duration: duration
        });
      }
    } catch (err) {
      console.error("Subdomain scan error:", err);
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
          <h2>Subdomain Finder</h2>
        </div>
        <p className="scanner-description">
          Discover subdomains of a target domain using various enumeration techniques.
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
              Enter the domain name to discover its subdomains
            </p>
          </div>
          
          <div className="form-group">
            <label className="form-label">DNS Enumeration Wordlist</label>
            <div className="radio-group">
              <label className="radio-label">
                <input
                  type="radio"
                  name="wordlist"
                  value="default"
                  checked={wordlistOption === 'default'}
                  onChange={(e) => setWordlistOption(e.target.value)}
                />
                <span>Default Wordlist</span>
              </label>
              <label className="radio-label">
                <input
                  type="radio"
                  name="wordlist"
                  value="small"
                  checked={wordlistOption === 'small'}
                  onChange={(e) => setWordlistOption(e.target.value)}
                />
                <span>Small (Quick Scan)</span>
              </label>
              <label className="radio-label">
                <input
                  type="radio"
                  name="wordlist"
                  value="large"
                  checked={wordlistOption === 'large'}
                  onChange={(e) => setWordlistOption(e.target.value)}
                />
                <span>Large (Comprehensive)</span>
              </label>
              <label className="radio-label">
                <input
                  type="radio"
                  name="wordlist"
                  value="custom"
                  checked={wordlistOption === 'custom'}
                  onChange={(e) => setWordlistOption(e.target.value)}
                />
                <span>Custom Wordlist</span>
              </label>
            </div>
            {wordlistOption === 'custom' && (
              <textarea
                value={customWordlist}
                onChange={(e) => setCustomWordlist(e.target.value)}
                placeholder="Enter words separated by newlines"
                className="form-textarea"
                rows="4"
              />
            )}
          </div>
          
          <div className="scan-options">
            <h3 className="scan-options-title">Scan Options</h3>
            
            <div className="checkbox-group">
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.includeWhois}
                    onChange={() => handleOptionChange('includeWhois')}
                    className="form-checkbox"
                  />
                  <span>Include WHOIS Information</span>
                </label>
                <p className="form-help">
                  Do WHOIS queries to determine network owners and country for each IP
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.detectTechnologies}
                    onChange={() => handleOptionChange('detectTechnologies')}
                    className="form-checkbox"
                  />
                  <span>Detect Web Technologies</span>
                </label>
                <p className="form-help">
                  Find details about each subdomain: OS, Server, Technology, Web Platform
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.includeUnresolved}
                    onChange={() => handleOptionChange('includeUnresolved')}
                    className="form-checkbox"
                  />
                  <span>Include Unresolved Subdomains</span>
                </label>
                <p className="form-help">
                  Keep unresolved subdomains in results without IP addresses
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.searchHistorical}
                    onChange={() => handleOptionChange('searchHistorical')}
                    className="form-checkbox"
                  />
                  <span>Search Historical Subdomains</span>
                </label>
                <p className="form-help">
                  Search in our database of cached historical subdomains
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.interrogateDNS}
                    onChange={() => handleOptionChange('interrogateDNS')}
                    className="form-checkbox"
                  />
                  <span>Interrogate DNS Records</span>
                </label>
                <p className="form-help">
                  Query various DNS records (NS, MX, TXT, AXFR)
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.useExternalAPIs}
                    onChange={() => handleOptionChange('useExternalAPIs')}
                    className="form-checkbox"
                  />
                  <span>Use External APIs</span>
                </label>
                <p className="form-help">
                  Request domain information from external API services
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.certificateTransparency}
                    onChange={() => handleOptionChange('certificateTransparency')}
                    className="form-checkbox"
                  />
                  <span>Certificate Transparency Logs</span>
                </label>
                <p className="form-help">
                  Retrieve and analyze logs from the Certificate Transparency framework
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.searchEngineQueries}
                    onChange={() => handleOptionChange('searchEngineQueries')}
                    className="form-checkbox"
                  />
                  <span>Search Engine Queries</span>
                </label>
                <p className="form-help">
                  Conduct public search queries on Google and Bing
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.checkSSLCertificates}
                    onChange={() => handleOptionChange('checkSSLCertificates')}
                    className="form-checkbox"
                  />
                  <span>Check SSL Certificates</span>
                </label>
                <p className="form-help">
                  Search SSL certificates for CN and alternative names
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.reverseDNS}
                    onChange={() => handleOptionChange('reverseDNS')}
                    className="form-checkbox"
                  />
                  <span>Reverse DNS Lookup</span>
                </label>
                <p className="form-help">
                  Conduct reverse DNS on target IP ranges
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.generatePermutations}
                    onChange={() => handleOptionChange('generatePermutations')}
                    className="form-checkbox"
                  />
                  <span>Generate Permutations</span>
                </label>
                <p className="form-help">
                  Generate permutations and alterations of found subdomain names
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.cnameLookup}
                    onChange={() => handleOptionChange('cnameLookup')}
                    className="form-checkbox"
                  />
                  <span>CNAME Lookup</span>
                </label>
                <p className="form-help">
                  Execute CNAME lookup and search its records
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
              'Start Subdomain Scan'
            )}
          </button>
        </form>
      </div>
      
      {loading && (
        <div className="card scan-progress">
          <div className="progress-content">
            <FaSpinner className="icon-spin large-spinner" />
            <h3>Subdomain Discovery in Progress...</h3>
            <p>
              Discovering subdomains using multiple enumeration techniques...
            </p>
            <div className="progress-tips">
              <h4>What we're doing:</h4>
              <ul>
                <li>DNS enumeration with wordlists</li>
                <li>Searching certificate transparency logs</li>
                <li>Querying external APIs</li>
                <li>Conducting search engine queries</li>
                <li>Checking SSL certificates</li>
                <li>Performing DNS record interrogation</li>
                <li>Generating subdomain permutations</li>
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
      
      {results && <SubdomainResults results={results} />}
    </div>
  );
};

export default SubdomainScanner;