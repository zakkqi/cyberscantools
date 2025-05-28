// frontend/src/components/scanners/PortScanner.jsx
import React, { useState, useEffect } from 'react';
import { FaServer, FaSpinner, FaArrowLeft, FaInfoCircle, FaCog, FaRocket, FaTerminal, FaCopy } from 'react-icons/fa';
import { api } from '../../utils/api';
import { historyService } from '../../services/historyService';

import '../../styles/Scanner.css';


const PortScanner = ({ onBack }) => {
  const [target, setTarget] = useState('');
  const [scanMode, setScanMode] = useState('profile'); // 'profile' or 'custom'
  const [selectedProfile, setSelectedProfile] = useState('quick_scan');
  const [scanProfiles, setScanProfiles] = useState({});
  
  // Custom scan options
  const [customOptions, setCustomOptions] = useState({
    technique: 'tcp_connect',
    port_option: 'common',
    top_ports: '1000',
    port_range: '1-1000',
    port_list: '80,443,22,21,25,3306,3389',
    timing: 'normal',
    host_discovery: 'ping_disable',
    detect_service: false,
    detect_os: false,
    aggressive: false,
    script_category: '',
    custom_scripts: '',
    traceroute: false,
    verbose: false,
    reason: false
  });
  
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [scanStartTime, setScanStartTime] = useState(null);
  const [commandPreview, setCommandPreview] = useState('');
  
  // Load scan profiles on component mount
  useEffect(() => {
    const loadProfiles = async () => {
      try {
        const response = await api.getScanOptions();
        if (response && response.profiles) {
          setScanProfiles(response.profiles);
        }
      } catch (err) {
        console.error('Failed to load scan profiles:', err);
        // Set default profiles if API fails
        setScanProfiles({
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
          intense_plus_udp: {
            name: 'Intense scan plus UDP',
            description: 'Same as intense but includes top UDP ports',
            estimated_time: '10-30 minutes'
          },
          intense_all_tcp: {
            name: 'Intense scan, all TCP ports',
            description: 'Scans all 65535 TCP ports with intensive options',
            estimated_time: '20-60 minutes'
          },
          intense_no_ping: {
            name: 'Intense scan, no ping',
            description: 'Intense scan without host discovery (good for firewalled hosts)',
            estimated_time: '5-15 minutes'
          },
          ping_scan: {
            name: 'Ping scan',
            description: 'Only discover online hosts, no port scanning',
            estimated_time: '10-30 seconds'
          },
          quick_scan_plus: {
            name: 'Quick scan plus',
            description: 'Quick scan with service version detection',
            estimated_time: '1-3 minutes'
          },
          quick_traceroute: {
            name: 'Quick traceroute',
            description: 'Quick scan with traceroute',
            estimated_time: '1-2 minutes'
          },
          regular_scan: {
            name: 'Regular scan',
            description: 'Basic port scan of top 1000 ports',
            estimated_time: '1-5 minutes'
          },
          slow_comprehensive: {
            name: 'Slow comprehensive scan',
            description: 'Comprehensive scan with stealth and evasion techniques',
            estimated_time: '30-60 minutes'
          }
        });
      }
    };
    
    loadProfiles();
  }, []);
  
  // Update command preview when options change
  useEffect(() => {
    const updateCommandPreview = async () => {
      if (target) {
        try {
          let scanOptions = {};
          
          if (scanMode === 'profile') {
            scanOptions = { profile: selectedProfile };
          } else {
            scanOptions = { ...customOptions, scan_type: 'custom' };
          }
          
          const preview = await api.getNmapCommandPreview(target, scanOptions);
          setCommandPreview(preview.command || `nmap ${target}`);
        } catch (err) {
          // Fallback to basic preview
          setCommandPreview(`nmap ${target}`);
        }
      } else {
        setCommandPreview('nmap [target]');
      }
    };
    
    const debounceTimer = setTimeout(updateCommandPreview, 500);
    return () => clearTimeout(debounceTimer);
  }, [target, scanMode, selectedProfile, customOptions]);
  
  const handleCustomOptionChange = (name, value) => {
    setCustomOptions(prev => ({
      ...prev,
      [name]: value
    }));
  };
  
  const copyCommandToClipboard = () => {
    navigator.clipboard.writeText(commandPreview);
    // You could add a toast notification here
  };
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResults(null);
    const startTime = Date.now();
    setScanStartTime(startTime);
    
    // Build scan options
    let scanOptions = {};
    
    if (scanMode === 'profile') {
      scanOptions = {
        profile: selectedProfile
      };
    } else {
      scanOptions = {
        ...customOptions,
        scan_type: 'custom'
      };
    }
    
    try {
      console.log("Sending scan request with options:", scanOptions);
      const response = await api.runPortScan(target, scanOptions);
      console.log("Received scan response:", response);
      
      const endTime = Date.now();
      const duration = Math.round((endTime - startTime) / 1000);
      
      if (response && response.status === 'success') {
        setResults(response);
        
        // Fixed: Use saveScanResult instead of saveScan
        historyService.saveScanResult({
          scannerType: 'port_scanner',
          target: target,
          status: 'completed',
          duration: duration,
          results: response.results,
          vulnerabilities: [],
          data: response,
          metadata: {
            scanOptions: scanOptions,
            scanMode: scanMode,
            profile: scanMode === 'profile' ? selectedProfile : null
          }
        });
      } else if (response && response.status === 'warning') {
        setResults(response);
        setError(response.message);
        
        historyService.saveScanResult({
          scannerType: 'port_scanner',
          target: target,
          status: 'completed',
          duration: duration,
          results: response.results,
          vulnerabilities: [],
          data: response,
          metadata: {
            scanOptions: scanOptions,
            warning: response.message
          }
        });
      } else if (response && response.status === 'error') {
        setError(response.message);
        
        historyService.saveScanResult({
          scannerType: 'port_scanner',
          target: target,
          status: 'failed',
          duration: duration,
          results: [],
          vulnerabilities: [],
          data: { error: response.message },
          metadata: {
            scanOptions: scanOptions,
            error: response.message
          }
        });
      } else {
        setError("Unexpected response format from server");
      }
    } catch (err) {
      console.error("Scan error:", err);
      const errorMessage = err.response?.data?.message || err.message || 'An error occurred during the scan';
      setError(errorMessage);
      
      historyService.saveScanResult({
        scannerType: 'port_scanner',
        target: target,
        status: 'failed',
        duration: Math.round((Date.now() - startTime) / 1000),
        results: [],
        vulnerabilities: [],
        data: { error: errorMessage },
        metadata: {
          scanOptions: scanOptions,
          error: errorMessage
        }
      });
    } finally {
      setLoading(false);
      setScanStartTime(null);
    }
  };
  
  const getEstimatedTime = () => {
    if (scanMode === 'profile' && scanProfiles[selectedProfile]) {
      return scanProfiles[selectedProfile].estimated_time;
    }
    
    // Estimate for custom scan
    let estimate = "1-5 minutes";
    if (customOptions.port_option === 'all') {
      estimate = "20-60 minutes";
    } else if (customOptions.timing === 'paranoid') {
      estimate = "10-30 minutes";
    } else if (customOptions.timing === 'insane') {
      estimate = "30 seconds - 2 minutes";
    }
    
    if (customOptions.detect_os) estimate += " (+30-60s for OS detection)";
    if (customOptions.traceroute) estimate += " (+1-2min for traceroute)";
    
    return estimate;
  };
  
  return (
    <div className="port-scanner-container">
      <button onClick={onBack} className="back-button">
        <FaArrowLeft /> Back to scanner selection
      </button>
      
      <div className="card">
        <div className="scanner-header">
          <div className="scanner-icon">
            <FaServer />
          </div>
          <h2>Enhanced Nmap Port Scanner</h2>
        </div>
        <p className="scanner-description">
          Professional-grade port scanning with full Nmap integration. Choose from predefined profiles or create custom scans with granular control.
        </p>
        
        {/* Command Preview */}
        <div className="command-preview">
          <div className="command-header">
            <FaTerminal className="terminal-icon" />
            <span>Command Preview</span>
            <button 
              type="button" 
              className="copy-btn" 
              onClick={copyCommandToClipboard}
              title="Copy command to clipboard"
            >
              <FaCopy />
            </button>
          </div>
          <code className="command-text">{commandPreview}</code>
        </div>
        
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label" htmlFor="target">
              Target Host/IP/Network
            </label>
            <input
              id="target"
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="e.g., scanme.nmap.org, 192.168.1.1, 192.168.1.0/24"
              className="form-input"
              required
            />
            <p className="form-help">
              Supports single hosts, IP ranges, and CIDR notation (e.g., 192.168.1.0/24)
            </p>
          </div>
          
          <div className="form-group">
            <label className="form-label">Scan Mode</label>
            <div className="scan-mode-selector">
              <button
                type="button"
                className={`mode-button ${scanMode === 'profile' ? 'active' : ''}`}
                onClick={() => setScanMode('profile')}
              >
                <FaRocket /> Profile Scan
              </button>
              <button
                type="button"
                className={`mode-button ${scanMode === 'custom' ? 'active' : ''}`}
                onClick={() => setScanMode('custom')}
              >
                <FaCog /> Custom Scan
              </button>
            </div>
          </div>
          
          {scanMode === 'profile' && (
            <div className="profile-selection">
              <div className="form-group">
                <label className="form-label" htmlFor="scan-profile">
                  Scan Profile
                </label>
                <select
                  id="scan-profile"
                  value={selectedProfile}
                  onChange={(e) => setSelectedProfile(e.target.value)}
                  className="form-select"
                >
                  {Object.entries(scanProfiles).map(([key, profile]) => (
                    <option key={key} value={key}>
                      {profile.name}
                    </option>
                  ))}
                </select>
                {scanProfiles[selectedProfile] && (
                  <div className="profile-info">
                    <p className="form-help">
                      {scanProfiles[selectedProfile].description}
                    </p>
                    <div className="scan-estimate">
                      <FaInfoCircle className="info-icon" />
                      Estimated time: {scanProfiles[selectedProfile].estimated_time}
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}
          
          {scanMode === 'custom' && (
            <div className="custom-options">
              <h3 className="scan-options-title">Custom Scan Configuration</h3>
              
              <div className="options-grid">
                <div className="form-group">
                  <label className="form-label" htmlFor="technique">Scan Technique</label>
                  <select
                    id="technique"
                    value={customOptions.technique}
                    onChange={(e) => handleCustomOptionChange('technique', e.target.value)}
                    className="form-select"
                  >
                    <option value="tcp_connect">TCP Connect (Most Compatible)</option>
                    <option value="tcp_syn">SYN Stealth (Requires Admin)</option>
                    <option value="tcp_ack">ACK Scan</option>
                    <option value="tcp_window">Window Scan</option>
                    <option value="tcp_maimon">Maimon Scan</option>
                    <option value="udp">UDP Scan</option>
                    <option value="tcp_null">NULL Scan</option>
                    <option value="tcp_fin">FIN Scan</option>
                    <option value="tcp_xmas">Xmas Scan</option>
                  </select>
                </div>
                
                <div className="form-group">
                  <label className="form-label" htmlFor="timing">Timing Template</label>
                  <select
                    id="timing"
                    value={customOptions.timing}
                    onChange={(e) => handleCustomOptionChange('timing', e.target.value)}
                    className="form-select"
                  >
                    <option value="paranoid">Paranoid (T0) - Very Slow</option>
                    <option value="sneaky">Sneaky (T1) - Slow</option>
                    <option value="polite">Polite (T2) - Slower</option>
                    <option value="normal">Normal (T3) - Default</option>
                    <option value="aggressive">Aggressive (T4) - Fast</option>
                    <option value="insane">Insane (T5) - Very Fast</option>
                  </select>
                </div>
              </div>
              
              <div className="form-group">
                <label className="form-label" htmlFor="port-option">Ports to Scan</label>
                <select
                  id="port-option"
                  value={customOptions.port_option}
                  onChange={(e) => handleCustomOptionChange('port_option', e.target.value)}
                  className="form-select"
                >
                  <option value="common">Top Common Ports</option>
                  <option value="range">Port Range</option>
                  <option value="list">Specific Ports</option>
                  <option value="all">All Ports (1-65535)</option>
                </select>
              </div>
              
              {customOptions.port_option === 'common' && (
                <div className="form-group">
                  <label className="form-label" htmlFor="top-ports">Number of Top Ports</label>
                  <select
                    id="top-ports"
                    value={customOptions.top_ports}
                    onChange={(e) => handleCustomOptionChange('top_ports', e.target.value)}
                    className="form-select"
                  >
                    <option value="10">Top 10</option>
                    <option value="100">Top 100</option>
                    <option value="1000">Top 1000</option>
                    <option value="5000">Top 5000</option>
                  </select>
                </div>
              )}
              
              {customOptions.port_option === 'range' && (
                <div className="form-group">
                  <label className="form-label" htmlFor="port-range">Port Range</label>
                  <input
                    id="port-range"
                    type="text"
                    value={customOptions.port_range}
                    onChange={(e) => handleCustomOptionChange('port_range', e.target.value)}
                    placeholder="e.g., 1-1000, 80-443"
                    className="form-input"
                  />
                  <p className="form-help">
                    Use format like "1-1000" or "22,80-443,8080"
                  </p>
                </div>
              )}
              
              {customOptions.port_option === 'list' && (
                <div className="form-group">
                  <label className="form-label" htmlFor="port-list">Port List</label>
                  <input
                    id="port-list"
                    type="text"
                    value={customOptions.port_list}
                    onChange={(e) => handleCustomOptionChange('port_list', e.target.value)}
                    placeholder="e.g., 80,443,22,21,25"
                    className="form-input"
                  />
                  <p className="form-help">
                    Common ports: 80 (HTTP), 443 (HTTPS), 22 (SSH), 21 (FTP), 25 (SMTP), 3306 (MySQL), 3389 (RDP)
                  </p>
                </div>
              )}
              
              <div className="form-group">
                <label className="form-label" htmlFor="host-discovery">Host Discovery</label>
                <select
                  id="host-discovery"
                  value={customOptions.host_discovery}
                  onChange={(e) => handleCustomOptionChange('host_discovery', e.target.value)}
                  className="form-select"
                >
                  <option value="ping_disable">No Ping (Skip Host Discovery)</option>
                  <option value="ping_icmp">ICMP Echo Ping</option>
                  <option value="ping_timestamp">ICMP Timestamp Ping</option>
                  <option value="ping_netmask">ICMP Netmask Ping</option>
                  <option value="ping_tcp_syn">TCP SYN Ping</option>
                  <option value="ping_tcp_ack">TCP ACK Ping</option>
                  <option value="ping_udp">UDP Ping</option>
                  <option value="arp_ping">ARP Ping (Local Network)</option>
                </select>
              </div>
              
              <div className="form-group">
                <label className="form-label" htmlFor="script-category">Script Scanning</label>
                <select
                  id="script-category"
                  value={customOptions.script_category}
                  onChange={(e) => handleCustomOptionChange('script_category', e.target.value)}
                  className="form-select"
                >
                  <option value="">No Scripts</option>
                  <option value="default">Default Scripts</option>
                  <option value="safe">Safe Scripts</option>
                  <option value="discovery">Discovery Scripts</option>
                  <option value="version">Version Detection Scripts</option>
                  <option value="vuln">Vulnerability Scripts</option>
                  <option value="auth">Authentication Scripts</option>
                  <option value="brute">Brute Force Scripts</option>
                  <option value="malware">Malware Detection</option>
                  <option value="intrusive">Intrusive Scripts</option>
                </select>
              </div>
              
              {customOptions.script_category === '' && (
                <div className="form-group">
                  <label className="form-label" htmlFor="custom-scripts">Custom Scripts</label>
                  <input
                    id="custom-scripts"
                    type="text"
                    value={customOptions.custom_scripts}
                    onChange={(e) => handleCustomOptionChange('custom_scripts', e.target.value)}
                    placeholder="e.g., http-title,ssl-cert,ssh-hostkey"
                    className="form-input"
                  />
                  <p className="form-help">
                    Comma-separated list of specific NSE scripts to run
                  </p>
                </div>
              )}
              
              <div className="checkbox-group">
                <h4>Detection Options</h4>
                
                <div className="checkbox-item">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={customOptions.detect_service}
                      onChange={(e) => handleCustomOptionChange('detect_service', e.target.checked)}
                      className="form-checkbox"
                    />
                    <span>Service Version Detection (-sV)</span>
                  </label>
                  <p className="form-help">Probe open ports to determine service/version info</p>
                </div>
                
                <div className="checkbox-item">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={customOptions.detect_os}
                      onChange={(e) => handleCustomOptionChange('detect_os', e.target.checked)}
                      className="form-checkbox"
                    />
                    <span>OS Detection (-O)</span>
                  </label>
                  <p className="form-help">Enable OS detection (requires admin privileges)</p>
                </div>
                
                <div className="checkbox-item">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={customOptions.aggressive}
                      onChange={(e) => handleCustomOptionChange('aggressive', e.target.checked)}
                      className="form-checkbox"
                    />
                    <span>Aggressive Scan (-A)</span>
                  </label>
                  <p className="form-help">Enable OS detection, version detection, script scanning, and traceroute</p>
                </div>
                
                <div className="checkbox-item">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={customOptions.traceroute}
                      onChange={(e) => handleCustomOptionChange('traceroute', e.target.checked)}
                      className="form-checkbox"
                    />
                    <span>Traceroute (--traceroute)</span>
                  </label>
                  <p className="form-help">Trace hop path to each host</p>
                </div>
                
                <div className="checkbox-item">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={customOptions.verbose}
                      onChange={(e) => handleCustomOptionChange('verbose', e.target.checked)}
                      className="form-checkbox"
                    />
                    <span>Verbose Output (-v)</span>
                  </label>
                  <p className="form-help">Increase verbosity level</p>
                </div>
                
                <div className="checkbox-item">
                  <label className="checkbox-label">
                    <input
                      type="checkbox"
                      checked={customOptions.reason}
                      onChange={(e) => handleCustomOptionChange('reason', e.target.checked)}
                      className="form-checkbox"
                    />
                    <span>Show Reason (--reason)</span>
                  </label>
                  <p className="form-help">Display the reason a port is in a particular state</p>
                </div>
              </div>
              
              <div className="scan-estimate">
                <FaInfoCircle className="info-icon" />
                Estimated scan time: {getEstimatedTime()}
              </div>
            </div>
          )}
          
          <button
            type="submit"
            className="btn btn-primary btn-scan"
            disabled={loading}
          >
            {loading ? 'Scanning...' : 'Start Nmap Scan'}
          </button>
        </form>
      </div>
      
      {loading && (
        <div className="card scan-progress">
          <div className="progress-content">
            <FaSpinner className="icon-spin large-spinner" />
            <h3>Nmap Scan in Progress...</h3>
            <p>
              {scanMode === 'profile' && scanProfiles[selectedProfile] && (
                <>
                  Running <strong>{scanProfiles[selectedProfile].name.toLowerCase()}</strong>...<br/>
                  {scanProfiles[selectedProfile].description}<br/>
                  Expected duration: <strong>{scanProfiles[selectedProfile].estimated_time}</strong>
                </>
              )}
              {scanMode === 'custom' && (
                <>
                  Running custom scan with your selected parameters...<br/>
                  Technique: <strong>{customOptions.technique.replace('_', ' ').toUpperCase()}</strong><br/>
                  Timing: <strong>{customOptions.timing.charAt(0).toUpperCase() + customOptions.timing.slice(1)}</strong>
                </>
              )}
            </p>
            {scanStartTime && (
              <p className="elapsed-time">
                Elapsed: <strong>{Math.floor((Date.now() - scanStartTime) / 1000)}s</strong>
              </p>
            )}
            <div className="progress-tips">
              <h4>Nmap is working:</h4>
              <ul>
                <li>🔍 Host discovery and reachability testing</li>
                <li>🔌 Port scanning and state detection</li>
                {(scanMode === 'profile' && selectedProfile !== 'ping_scan') || 
                 (scanMode === 'custom' && customOptions.detect_service) ? 
                  <li>🔬 Service version detection</li> : null}
                {(scanMode === 'custom' && customOptions.detect_os) || 
                 (scanMode === 'profile' && ['intense', 'intense_plus_udp', 'intense_all_tcp', 'intense_no_ping'].includes(selectedProfile)) ? 
                  <li>💻 OS fingerprinting</li> : null}
                {customOptions.script_category || 
                 (scanMode === 'profile' && ['intense', 'intense_plus_udp', 'intense_all_tcp', 'intense_no_ping'].includes(selectedProfile)) ? 
                  <li>📜 Script execution and vulnerability checking</li> : null}
                <li>📊 Generating comprehensive results</li>
              </ul>
            </div>
          </div>
        </div>
      )}
      
      {error && (
        <div className="alert alert-error">
          <div className="alert-title">Scan Error</div>
          <p>{error}</p>
          <div className="error-suggestions">
            <h4>Troubleshooting Tips:</h4>
            <ul>
              <li><strong>Permission Issues:</strong> For SYN scans, try running as administrator or use TCP Connect scan</li>
              <li><strong>Host Unreachable:</strong> Try disabling ping (No Ping option) for firewalled hosts</li>
              <li><strong>Network Issues:</strong> Test with scanme.nmap.org first to verify connectivity</li>
              <li><strong>Firewall Blocking:</strong> Use TCP Connect scan technique for better compatibility</li>
              <li><strong>Installation Issues:</strong> Ensure Nmap is properly installed and in system PATH</li>
            </ul>
          </div>
        </div>
      )}
      
      {results && results.status === 'success' && (
        <div className="card scan-results">
          <h3 className="scan-results-title">
            🎯 Nmap Scan Results
          </h3>
          
          {results.scan_info && (
            <div className="scan-info">
              <h4>📋 Scan Information</h4>
              <div className="scan-info-grid">
                <div>
                  <strong>Profile Used:</strong> {results.scan_info.profile_used}
                </div>
                <div>
                  <strong>Command:</strong>
                  <code>{results.scan_info.command}</code>
                </div>
                <div>
                  <strong>Elapsed Time:</strong> {results.scan_info.elapsed_time}
                </div>
                <div>
                  <strong>Hosts Up:</strong> {results.scan_info.hosts_up}
                </div>
                <div>
                  <strong>Hosts Down:</strong> {results.scan_info.hosts_down}
                </div>
                <div>
                  <strong>Total Hosts:</strong> {results.scan_info.hosts_total}
                </div>
              </div>
              {results.scan_info.profile_description && (
                <p className="profile-description">
                  <strong>Profile Description:</strong> {results.scan_info.profile_description}
                </p>
              )}
            </div>
          )}
          
          {results.results.length === 0 ? (
            <div className="no-results">
              <p>No hosts found or all hosts are down.</p>
              <div className="no-results-suggestions">
                <h4>Possible reasons:</h4>
                <ul>
                  <li>Target is behind a firewall that blocks ping/port scans</li>
                  <li>Target is actually down or unreachable</li>
                  <li>Network filtering is blocking the scan packets</li>
                  <li>Try using "No Ping" host discovery option</li>
                </ul>
              </div>
            </div>
          ) : (
            results.results.map((host, index) => (
              <div key={index} className="host-card">
                <div className="host-header">
                  <span className="host-title">🖥️ Host: {host.host}</span>
                  <span className={`host-status ${host.status === 'up' ? 'up' : 'down'}`}>
                    {host.status === 'up' ? '✅' : '❌'} {host.status}
                  </span>
                </div>
                
                {host.hostnames && host.hostnames.length > 0 && (
                  <div className="host-info">
                    <span className="info-label">🏷️ Hostnames: </span>
                    {host.hostnames.map((hostname, i) => (
                      <span key={i} className="info-value">
                        {hostname.name} ({hostname.type}){i < host.hostnames.length - 1 ? ', ' : ''}
                      </span>
                    ))}
                  </div>
                )}
                
                {host.os && host.os.length > 0 && (
                  <div className="host-info">
                    <span className="info-label">💻 Operating System: </span>
                    <div className="os-matches">
                      {host.os.map((os, i) => (
                        <div key={i} className="os-match">
                          <strong>{os.name}</strong> (Accuracy: {os.accuracy}%)
                          {os.osclass && os.osclass.length > 0 && (
                            <div className="os-details">
                              {os.osclass.map((osclass, j) => (
                                <span key={j} className="os-class">
                                  {osclass.vendor} {osclass.osfamily} {osclass.osgen}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                {host.summary && (
                  <div className="host-summary">
                    <div className="summary-stats">
                      <span className="stat open">
                        <strong>{host.summary.open_ports}</strong> Open
                      </span>
                      <span className="stat closed">
                        <strong>{host.summary.closed_ports}</strong> Closed
                      </span>
                      <span className="stat filtered">
                        <strong>{host.summary.filtered_ports}</strong> Filtered
                      </span>
                      <span className="stat total">
                        <strong>{host.summary.total_ports_scanned}</strong> Total
                      </span>
                    </div>
                  </div>
                )}
                
                {host.ports && host.ports.length > 0 ? (
                  <div className="port-results">
                    <h5>🔌 Port Scan Results</h5>
                    <div className="port-table-container">
                      <table className="port-table">
                        <thead>
                          <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>Reason</th>
                          </tr>
                        </thead>
                        <tbody>
                          {host.ports
                            .filter(port => port.state === 'open' || port.state === 'filtered')
                            .map((port, idx) => (
                            <tr key={idx}>
                              <td className="port-number">{port.port}</td>
                              <td className="protocol">{port.protocol.toUpperCase()}</td>
                              <td>
                                <span className={`port-status ${port.state}`}>
                                  {port.state === 'open' ? '🟢' : 
                                   port.state === 'closed' ? '🔴' : 
                                   port.state === 'filtered' ? '🟡' : '⚪'} {port.state}
                                </span>
                              </td>
                              <td className="service">{port.service || '-'}</td>
                              <td className="version">
                                {port.product || port.version ? 
                                  `${port.product || ''} ${port.version || ''} ${port.extrainfo || ''}`.trim() : 
                                  '-'
                                }
                              </td>
                              <td className="reason">{port.reason || '-'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      
                      {/* Show closed ports in a collapsed section */}
                      {host.ports.filter(port => port.state === 'closed').length > 0 && (
                        <details className="closed-ports-section">
                          <summary>
                            Show {host.ports.filter(port => port.state === 'closed').length} closed ports
                          </summary>
                          <div className="closed-ports-list">
                            {host.ports
                              .filter(port => port.state === 'closed')
                              .slice(0, 20) // Limit to first 20 closed ports
                              .map((port, idx) => (
                                <span key={idx} className="closed-port">
                                  {port.port}/{port.protocol}
                                </span>
                              ))}
                            {host.ports.filter(port => port.state === 'closed').length > 20 && (
                              <span className="more-ports">
                                ... and {host.ports.filter(port => port.state === 'closed').length - 20} more
                              </span>
                            )}
                          </div>
                        </details>
                      )}
                    </div>
                    
                    {/* Show script results if any */}
                    {host.ports.some(port => port.scripts) && (
                      <div className="script-results">
                        <h5>📜 NSE Script Results</h5>
                        {host.ports
                          .filter(port => port.scripts)
                          .map((port, idx) => (
                            <div key={idx} className="port-scripts">
                              <h6>Port {port.port}/{port.protocol}</h6>
                              {Object.entries(port.scripts).map(([scriptName, scriptOutput]) => (
                                <div key={scriptName} className="script-output">
                                  <strong>{scriptName}:</strong>
                                  <pre>{scriptOutput}</pre>
                                </div>
                              ))}
                            </div>
                          ))}
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="no-ports-message">
                    <p>❌ No open or filtered ports found on this host.</p>
                    <div className="no-ports-suggestions">
                      <h5>Possible reasons:</h5>
                      <ul>
                        <li>All scanned ports are closed</li>
                        <li>Host is behind a strict firewall</li>
                        <li>Port range scanned might not include active services</li>
                        <li>Try scanning more ports or use different scan technique</li>
                      </ul>
                    </div>
                  </div>
                )}
                
                {host.traceroute && host.traceroute.hops && host.traceroute.hops.length > 0 && (
                  <div className="traceroute-results">
                    <h5>🛤️ Traceroute Results</h5>
                    <div className="traceroute-hops">
                      {host.traceroute.hops.map((hop, idx) => (
                        <div key={idx} className="hop">
                          <span className="hop-number">{hop.ttl}</span>
                          <span className="hop-ip">{hop.ipaddr}</span>
                          <span className="hop-time">{hop.rtt}ms</span>
                          {hop.host && <span className="hop-host">({hop.host})</span>}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
          
          {/* Additional scan insights */}
          <div className="scan-insights">
            <h4>💡 Scan Insights</h4>
            <div className="insights-grid">
              {results.results.some(host => host.ports && host.ports.filter(p => p.state === 'open').length > 0) && (
                <div className="insight-card">
                  <h5>🔓 Open Ports Found</h5>
                  <p>
                    {results.results.reduce((total, host) => 
                      total + (host.ports ? host.ports.filter(p => p.state === 'open').length : 0), 0
                    )} open ports discovered across all hosts.
                  </p>
                </div>
              )}
              
              {results.results.some(host => host.os && host.os.length > 0) && (
                <div className="insight-card">
                  <h5>💻 OS Detection</h5>
                  <p>Operating system identified for {results.results.filter(host => host.os && host.os.length > 0).length} host(s).</p>
                </div>
              )}
              
              {results.results.some(host => host.ports && host.ports.some(p => p.scripts)) && (
                <div className="insight-card">
                  <h5>📜 Script Results</h5>
                  <p>NSE scripts provided additional information about services and potential vulnerabilities.</p>
                </div>
              )}
              
              {results.results.some(host => host.traceroute && host.traceroute.hops) && (
                <div className="insight-card">
                  <h5>🛤️ Network Path</h5>
                  <p>Traceroute information shows the network path to target hosts.</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
      
      {results && results.status === 'warning' && (
        <div className="card scan-results">
          <h3 className="scan-results-title">⚠️ Scan Results (Warning)</h3>
          <div className="alert alert-warning">
            <p>{results.message}</p>
          </div>
          
          {results.results && results.results.length > 0 && 
            results.results.map((host, index) => (
              <div key={index} className="host-card">
                <div className="host-header">
                  <span className="host-title">🖥️ Host: {host.host}</span>
                  <span className={`host-status ${host.status}`}>
                    {host.status}
                  </span>
                </div>
                
                {host.scan_info && host.scan_info.note && (
                  <div className="host-info">
                    <span className="info-label">📝 Note: </span>
                    <span className="info-value">{host.scan_info.note}</span>
                  </div>
                )}
                
                {host.ports && host.ports.length > 0 ? (
                  <div className="port-table-container">
                    <table className="port-table">
                      <thead>
                        <tr>
                          <th>Port</th>
                          <th>Protocol</th>
                          <th>State</th>
                          <th>Service</th>
                          <th>Notes</th>
                        </tr>
                      </thead>
                      <tbody>
                        {host.ports.map((port, idx) => (
                          <tr key={idx}>
                            <td>{port.port}</td>
                            <td>{port.protocol.toUpperCase()}</td>
                            <td>
                              <span className={`port-status ${port.state}`}>
                                {port.state}
                              </span>
                            </td>
                            <td>{port.service || '-'}</td>
                            <td>{port.extrainfo || '-'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="no-ports-message">
                    ❓ Unable to determine port states. The target appears to be heavily filtered or blocking scans.
                  </p>
                )}
              </div>
            ))
          }
        </div>
      )}
    </div>
  );
};

export default PortScanner;