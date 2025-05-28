// frontend/src/components/scanners/DefacementScanner.jsx
import React, { useState } from 'react';
import { FaShieldAlt, FaSpinner, FaArrowLeft } from 'react-icons/fa';
import { api } from '../../utils/api';
import { historyService } from '../../services/historyService';
import DefacementResults from './DefacementResults';
import '../../styles/DefacementScanner.css';

const DefacementScanner = ({ onBack }) => {
  const [target, setTarget] = useState('');
  const [options, setOptions] = useState({
    checkBaseline: false,
    monitorChanges: true,
    checkScripts: true,
    checkMalware: true,
    checkLinks: true,
    checkGambling: true,
    checkSensitiveFiles: true,
    checkLoginPages: true,
    checkVulnerabilities: true,
    customDorks: false,
    includeParentDomain: true
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
    
    // Placeholder - backend akan diimplementasi nanti
    setTimeout(() => {
      setError("Defacement scanner backend is not implemented yet.");
      setLoading(false);
    }, 1000);
  };
  
  return (
    <div className="defacement-scanner-container">
      <button onClick={onBack} className="back-button">
        <FaArrowLeft /> Back to scanner selection
      </button>
      
      <div className="card">
        <div className="scanner-header">
          <div className="scanner-icon defacement">
            <FaShieldAlt />
          </div>
          <h2>Web Defacement Scanner</h2>
        </div>
        <p className="scanner-description">
          Monitor and detect website defacement activities, unauthorized changes, and malicious modifications.
        </p>
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label" htmlFor="target">
              Target Website URL
            </label>
            <input
              id="target"
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g., https://example.com"
              className="form-input"
              required
            />
            <p className="form-help">
              Enter the full URL of the website to monitor for defacement
            </p>
          </div>
          
          <div className="scan-options">
            <h3 className="scan-options-title">Scan Options</h3>
            
            <div className="checkbox-group">
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.checkBaseline}
                    onChange={() => handleOptionChange('checkBaseline')}
                    className="form-checkbox"
                  />
                  <span>Create/Check Baseline</span>
                </label>
                <p className="form-help">
                  Create or compare against a baseline snapshot of the website
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.monitorChanges}
                    onChange={() => handleOptionChange('monitorChanges')}
                    className="form-checkbox"
                  />
                  <span>Monitor Content Changes</span>
                </label>
                <p className="form-help">
                  Detect unauthorized changes to website content
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.checkScripts}
                    onChange={() => handleOptionChange('checkScripts')}
                    className="form-checkbox"
                  />
                  <span>Check for Malicious Scripts</span>
                </label>
                <p className="form-help">
                  Scan for injected malicious JavaScript or scripts
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.checkMalware}
                    onChange={() => handleOptionChange('checkMalware')}
                    className="form-checkbox"
                  />
                  <span>Malware Detection</span>
                </label>
                <p className="form-help">
                  Check for known malware signatures and patterns
                </p>
              </div>
              
              <div className="form-group checkbox-item">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={options.checkLinks}
                    onChange={() => handleOptionChange('checkLinks')}
                    className="form-checkbox"
                  />
                  <span>Check Suspicious Links</span>
                </label>
                <p className="form-help">
                  Detect suspicious or malicious external links
                </p>
              </div>
              <div className="form-group checkbox-item">
            <label className="checkbox-label">
                <input
                type="checkbox"
                checked={options.includeParentDomain !== false}
                onChange={() => handleOptionChange('includeParentDomain')}
                className="form-checkbox"
                />
                <span>Include Parent Domain</span>
            </label>
            <p className="form-help">
                Also search the parent domain (e.g., search kemendagri.go.id when scanning bpsdm.kemendagri.go.id)
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
              'Start Defacement Scan'
            )}
          </button>
        </form>
      </div>
      
      {loading && (
        <div className="card scan-progress">
          <div className="progress-content">
            <FaSpinner className="icon-spin large-spinner" />
            <h3>Defacement Scan in Progress...</h3>
            <p>
              Analyzing website for signs of defacement...
            </p>
            <div className="progress-tips">
              <h4>What we're checking:</h4>
              <ul>
                <li>Content integrity and changes</li>
                <li>Malicious script injections</li>
                <li>Unauthorized modifications</li>
                <li>Suspicious links and redirects</li>
                <li>Malware signatures</li>
                <li>Visual changes detection</li>
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
      
      {results && <DefacementResults results={results} />}
    </div>
  );
};

export default DefacementScanner;