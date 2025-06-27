// frontend/src/components/scanners/DefacementScanner.jsx
import React, { useState, useEffect } from 'react';
import { 
  FaShieldAlt, 
  FaSpinner, 
  FaArrowLeft, 
  FaEye, 
  FaCode, 
  FaPlay,
  FaCog,
  FaExclamationTriangle,
  FaCheckCircle,
  FaClock,
  FaHistory
} from 'react-icons/fa';
import { api } from '../../utils/api';
import { historyService } from '../../services/historyService';
import DefacementResults from './DefacementResults';
import '../../styles/DefacementScanner.css';

const DefacementScanner = ({ onBack }) => {
  const [target, setTarget] = useState('');
  const [monitorName, setMonitorName] = useState('');
  const [monitoring, setMonitoring] = useState(false);
  const [scanType, setScanType] = useState('manual'); // manual, continuous
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false);
  
  const [options, setOptions] = useState({
    interval: 60, // minutes
    screenshot_threshold: 5.0, // percentage
    html_threshold: 10.0, // percentage
    monitor_full_page: true,
    monitor_specific_elements: false,
    ignore_dynamic_content: true,
    keyword_detection: true,
    alert_email: '',
    alert_webhook: ''
  });
  
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [progress, setProgress] = useState('');
  const [currentMonitor, setCurrentMonitor] = useState(null);
  const [monitorHistory, setMonitorHistory] = useState([]);
  
  const handleOptionChange = (name, value) => {
    setOptions(prev => ({
      ...prev,
      [name]: value
    }));
  };
  
  const handleManualScan = async (e) => {
    e.preventDefault();
    if (!target.trim()) return;
    
    setLoading(true);
    setError(null);
    setResults(null);
    setProgress('Capturing website snapshot...');
    
    const startTime = Date.now();
    const monitorId = `manual_${Date.now()}`;
    
    try {
      setProgress('Taking screenshot and HTML snapshot...');
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setProgress('Comparing with previous version...');
      await new Promise(resolve => setTimeout(resolve, 1500));
      
      setProgress('Analyzing changes and detecting threats...');
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      const response = await api.runDefacementScan(monitorId, {
        url: target,
        screenshot_threshold: options.screenshot_threshold,
        html_threshold: options.html_threshold
      });
      
      const endTime = Date.now();
      const duration = `${Math.round((endTime - startTime) / 1000)}s`;
      
      if (response && response.status === 'success') {
        setResults(response.results);
        
        // Save to history
        historyService.saveScan({
          scanType: 'defacement',
          target: target,
          scanOptions: options,
          results: response.results,
          status: 'completed',
          duration: duration
        });
      } else {
        throw new Error(response?.message || 'Scan failed');
      }
    } catch (err) {
      const errorMessage = err.response?.data?.message || err.message || 'An error occurred during the defacement scan';
      setError(errorMessage);
      
      // Save failed scan to history
      historyService.saveScan({
        scanType: 'defacement',
        target: target,
        scanOptions: options,
        error: errorMessage,
        status: 'failed',
        duration: `${Math.round((Date.now() - startTime) / 1000)}s`
      });
    } finally {
      setLoading(false);
      setProgress('');
    }
  };
  
  const handleStartMonitoring = async (e) => {
    e.preventDefault();
    if (!target.trim()) return;
    
    setLoading(true);
    setError(null);
    
    try {
      const monitorConfig = {
        url: target,
        name: monitorName || target,
        interval: options.interval,
        screenshot_threshold: options.screenshot_threshold,
        html_threshold: options.html_threshold,
        alert_email: options.alert_email,
        alert_webhook: options.alert_webhook
      };
      
      const response = await api.createDefacementMonitor(monitorConfig);
      
      if (response && response.status === 'success') {
        setCurrentMonitor(response.monitor);
        setMonitoring(true);
        
        // Load monitor history
        loadMonitorHistory(response.monitor.id);
      } else {
        throw new Error(response?.message || 'Failed to start monitoring');
      }
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Failed to start monitoring');
    } finally {
      setLoading(false);
    }
  };
  
  const handleStopMonitoring = async () => {
    if (!currentMonitor) return;
    
    try {
      await api.deleteDefacementMonitor(currentMonitor.id);
      setCurrentMonitor(null);
      setMonitoring(false);
      setMonitorHistory([]);
    } catch (err) {
      setError('Failed to stop monitoring');
    }
  };
  
  const loadMonitorHistory = async (monitorId) => {
    try {
      const response = await api.getDefacementMonitorHistory(monitorId, 7);
      if (response && response.status === 'success') {
        setMonitorHistory(response.history);
      }
    } catch (err) {
      console.error('Failed to load monitor history:', err);
    }
  };
  
  const getIntervalDisplay = (minutes) => {
    if (minutes < 60) return `${minutes} minutes`;
    if (minutes < 1440) return `${Math.round(minutes / 60)} hours`;
    return `${Math.round(minutes / 1440)} days`;
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
          <div>
            <h2>Web Defacement Scanner</h2>
            <p className="scanner-description">
              Monitor website changes and detect unauthorized modifications in real-time
            </p>
          </div>
        </div>
        
        <div className="scan-mode-tabs">
          <button 
            className={`tab-button ${scanType === 'manual' ? 'active' : ''}`}
            onClick={() => setScanType('manual')}
          >
            <FaPlay /> Manual Scan
          </button>
          <button 
            className={`tab-button ${scanType === 'continuous' ? 'active' : ''}`}
            onClick={() => setScanType('continuous')}
          >
            <FaEye /> Continuous Monitoring
          </button>
        </div>
        
        <form onSubmit={scanType === 'manual' ? handleManualScan : handleStartMonitoring} className="scanner-form">
          {/* Target Input */}
          <div className="form-group">
            <label className="form-label" htmlFor="target">
              Target Website URL *
            </label>
            <input
              id="target"
              type="url"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="https://example.com"
              className="form-input"
              required
            />
          </div>
          
          {/* Monitor Name (only for continuous monitoring) */}
          {scanType === 'continuous' && (
            <div className="form-group">
              <label className="form-label" htmlFor="monitor-name">
                Monitor Name
              </label>
              <input
                id="monitor-name"
                type="text"
                value={monitorName}
                onChange={(e) => setMonitorName(e.target.value)}
                placeholder="My Website Monitor"
                className="form-input"
              />
            </div>
          )}
          
          {/* Monitoring Interval (only for continuous monitoring) */}
          {scanType === 'continuous' && (
            <div className="form-group">
              <label className="form-label">Monitoring Interval</label>
              <div className="interval-options">
                {[5, 15, 30, 60, 180, 360, 720, 1440].map(minutes => (
                  <label key={minutes} className="radio-option">
                    <input
                      type="radio"
                      name="interval"
                      value={minutes}
                      checked={options.interval === minutes}
                      onChange={(e) => handleOptionChange('interval', parseInt(e.target.value))}
                    />
                    <span>{getIntervalDisplay(minutes)}</span>
                  </label>
                ))}
              </div>
            </div>
          )}
          
          {/* Advanced Options */}
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
          
          {showAdvancedOptions && (
            <div className="advanced-options">
              <h4>Detection Sensitivity</h4>
              <div className="sensitivity-controls">
                <div className="form-group">
                  <label className="form-label">
                    Visual Change Threshold: {options.screenshot_threshold}%
                  </label>
                  <input
                    type="range"
                    min="1"
                    max="30"
                    step="1"
                    value={options.html_threshold}
                    onChange={(e) => handleOptionChange('html_threshold', parseFloat(e.target.value))}
                    className="threshold-slider"
                  />
                  <small>Higher values = less sensitive to content modifications</small>
                </div>
              </div>
              
              <h4>Monitoring Options</h4>
              <div className="options-grid">
                <label className="checkbox-option">
                  <input
                    type="checkbox"
                    checked={options.monitor_full_page}
                    onChange={(e) => handleOptionChange('monitor_full_page', e.target.checked)}
                  />
                  <span>Monitor Full Page</span>
                  <small>Capture and analyze entire webpage</small>
                </label>
                
                <label className="checkbox-option">
                  <input
                    type="checkbox"
                    checked={options.ignore_dynamic_content}
                    onChange={(e) => handleOptionChange('ignore_dynamic_content', e.target.checked)}
                  />
                  <span>Ignore Dynamic Content</span>
                  <small>Skip ads, live feeds, and changing elements</small>
                </label>
                
                <label className="checkbox-option">
                  <input
                    type="checkbox"
                    checked={options.keyword_detection}
                    onChange={(e) => handleOptionChange('keyword_detection', e.target.checked)}
                  />
                  <span>Defacement Keyword Detection</span>
                  <small>Alert on suspicious phrases and terms</small>
                </label>
              </div>
              
              {scanType === 'continuous' && (
                <>
                  <h4>Alert Settings</h4>
                  <div className="form-group">
                    <label className="form-label">Email Alerts</label>
                    <input
                      type="email"
                      value={options.alert_email}
                      onChange={(e) => handleOptionChange('alert_email', e.target.value)}
                      placeholder="your@email.com"
                      className="form-input"
                    />
                  </div>
                  
                  <div className="form-group">
                    <label className="form-label">Webhook URL</label>
                    <input
                      type="url"
                      value={options.alert_webhook}
                      onChange={(e) => handleOptionChange('alert_webhook', e.target.value)}
                      placeholder="https://your-webhook.com/endpoint"
                      className="form-input"
                    />
                  </div>
                </>
              )}
            </div>
          )}
          
          {/* Submit Buttons */}
          {!monitoring ? (
            <button
              type="submit"
              className="btn btn-primary btn-scan"
              disabled={loading || !target.trim()}
            >
              {loading ? (
                <span className="loading-content">
                  <FaSpinner className="icon-spin" />
                  {scanType === 'manual' ? 'Scanning...' : 'Starting Monitor...'}
                </span>
              ) : (
                <>
                  {scanType === 'manual' ? <FaPlay /> : <FaEye />}
                  {scanType === 'manual' ? 'Start Manual Scan' : 'Start Monitoring'}
                </>
              )}
            </button>
          ) : (
            <button
              type="button"
              onClick={handleStopMonitoring}
              className="btn btn-danger btn-scan"
            >
              Stop Monitoring
            </button>
          )}
        </form>
      </div>
      
      {/* Active Monitor Status */}
      {monitoring && currentMonitor && (
        <div className="card monitor-status">
          <div className="status-header">
            <div className="status-indicator">
              <div className="status-dot active"></div>
              <h3>Active Monitor</h3>
            </div>
            <div className="monitor-info">
              <span className="monitor-name">{currentMonitor.name}</span>
              <span className="monitor-interval">Every {getIntervalDisplay(currentMonitor.interval)}</span>
            </div>
          </div>
          
          <div className="monitor-details">
            <div className="detail-item">
              <FaClock />
              <span>Started: {new Date(currentMonitor.created_at).toLocaleString()}</span>
            </div>
            <div className="detail-item">
              <FaEye />
              <span>URL: {currentMonitor.url}</span>
            </div>
          </div>
          
          {monitorHistory.length > 0 && (
            <div className="recent-changes">
              <h4><FaHistory /> Recent Activity</h4>
              <div className="changes-list">
                {monitorHistory.slice(0, 5).map((report, index) => (
                  <div key={index} className={`change-item ${report.change_detected ? 'change-detected' : 'no-change'}`}>
                    <div className="change-status">
                      {report.change_detected ? (
                        <FaExclamationTriangle className="status-icon warning" />
                      ) : (
                        <FaCheckCircle className="status-icon success" />
                      )}
                    </div>
                    <div className="change-details">
                      <div className="change-time">
                        {new Date(report.timestamp).toLocaleString()}
                      </div>
                      <div className="change-summary">
                        {report.change_detected ? (
                          <>
                            <span className={`severity-badge ${report.severity}`}>
                              {report.severity.toUpperCase()}
                            </span>
                            {report.alerts.map((alert, i) => (
                              <span key={i} className="alert-message">{alert.message}</span>
                            ))}
                          </>
                        ) : (
                          <span className="no-changes">No changes detected</span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
      
      {/* Progress */}
      {loading && (
        <div className="card scan-progress">
          <div className="progress-container">
            <div className="progress-icon">
              <FaSpinner className="icon-spin" />
            </div>
            <div className="progress-content">
              <h3 className="progress-title">
                {scanType === 'manual' ? 'Scanning Website for Changes' : 'Setting Up Monitor'}
              </h3>
              <p className="progress-text">{progress || 'Initializing...'}</p>
              
              <div className="progress-bar-container">
                <div className="progress-bar">
                  <div className="progress-bar-fill"></div>
                </div>
              </div>
              
              <div className="scan-info">
                <div className="scan-feature">
                  <FaEye />
                  <span>Visual Screenshot Comparison</span>
                </div>
                <div className="scan-feature">
                  <FaCode />
                  <span>HTML Content Analysis</span>
                </div>
                <div className="scan-feature">
                  <FaShieldAlt />
                  <span>Defacement Keyword Detection</span>
                </div>
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
      {results && <DefacementResults results={results} />}
    </div>
  );
};

export default DefacementScanner;