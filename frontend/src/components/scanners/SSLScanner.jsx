// frontend/src/components/scanners/SSLScanner.jsx - FIXED VERSION
import React, { useState, useEffect } from 'react';
import { 
  FaLock, 
  FaSpinner, 
  FaArrowLeft, 
  FaCheckCircle, 
  FaExclamationTriangle,
  FaCog,
  FaHistory,
  FaInfoCircle,
  FaBolt,
  FaShieldAlt,
  FaGlobe,
  FaCertificate,
  FaChartLine,
  FaBookmark,
  FaClock
} from 'react-icons/fa';
import { api } from '../../utils/api';
import { historyService } from '../../services/historyService';
import SSLResults from './SSLResults';
import '../../styles/SSLScanner.css';

const SSLScanner = ({ onBack }) => {
  const [target, setTarget] = useState('');
  const [port, setPort] = useState('443');
  const [scanProfile, setScanProfile] = useState('comprehensive');
  const [options, setOptions] = useState({
    checkVulnerabilities: true,
    checkCiphers: true,
    checkChain: true,
    checkSecurityHeaders: true,
    checkOCSP: true,
    checkCT: true,
    checkHSTS: true,
    checkCompliance: true,
    checkPerformance: true
  });
  
  const [advancedMode, setAdvancedMode] = useState(false);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [scanProgress, setScanProgress] = useState({
    step: 0,
    totalSteps: 12,
    currentTask: 'Initializing...',
    percentage: 0
  });
  const [recentScans, setRecentScans] = useState([]);
  const [favorites, setFavorites] = useState([]);

  // Scan profiles
  const scanProfiles = {
    quick: {
      name: 'Quick Scan',
      description: 'Basic SSL/TLS configuration check',
      icon: FaBolt,
      options: {
        checkVulnerabilities: false,
        checkCiphers: true,
        checkChain: false,
        checkSecurityHeaders: false,
        checkOCSP: false,
        checkCT: false,
        checkHSTS: false,
        checkCompliance: false,
        checkPerformance: false
      }
    },
    standard: {
      name: 'Standard Scan',
      description: 'Comprehensive security analysis',
      icon: FaShieldAlt,
      options: {
        checkVulnerabilities: true,
        checkCiphers: true,
        checkChain: true,
        checkSecurityHeaders: true,
        checkOCSP: false,
        checkCT: false,
        checkHSTS: true,
        checkCompliance: false,
        checkPerformance: true
      }
    },
    comprehensive: {
      name: 'Comprehensive Scan',
      description: 'Complete security audit with compliance checks',
      icon: FaChartLine,
      options: {
        checkVulnerabilities: true,
        checkCiphers: true,
        checkChain: true,
        checkSecurityHeaders: true,
        checkOCSP: true,
        checkCT: true,
        checkHSTS: true,
        checkCompliance: true,
        checkPerformance: true
      }
    }
  };

  useEffect(() => {
    // Load recent scans and favorites from localStorage with error handling
    try {
      // Get recent SSL scans from historyService
      const allHistory = historyService.getAllHistory();
      const sslScans = allHistory
        .filter(scan => scan.scannerType === 'ssl' || scan.scanType === 'ssl')
        .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
        .slice(0, 5);
      setRecentScans(sslScans);
      
      const storedFavorites = JSON.parse(localStorage.getItem('ssl_favorites') || '[]');
      setFavorites(storedFavorites);
    } catch (error) {
      console.warn('Error loading scan history:', error);
      setRecentScans([]);
      setFavorites([]);
    }
  }, []);

  useEffect(() => {
    // Update options when scan profile changes
    if (scanProfiles[scanProfile]) {
      setOptions(scanProfiles[scanProfile].options);
    }
  }, [scanProfile]);

  const handleProfileChange = (profile) => {
    setScanProfile(profile);
    setOptions(scanProfiles[profile].options);
  };

  const handleOptionChange = (name) => {
    setOptions(prev => ({
      ...prev,
      [name]: !prev[name]
    }));
    setScanProfile('custom'); // Switch to custom when manually changing options
  };

  const addToFavorites = () => {
    if (target && !favorites.find(f => f.target === target && f.port === port)) {
      const newFavorite = {
        target,
        port,
        name: target,
        added: new Date().toISOString()
      };
      const updatedFavorites = [...favorites, newFavorite];
      setFavorites(updatedFavorites);
      localStorage.setItem('ssl_favorites', JSON.stringify(updatedFavorites));
    }
  };

  const loadFromFavorite = (favorite) => {
    setTarget(favorite.target);
    setPort(favorite.port);
  };

  const loadFromRecent = (scan) => {
    setTarget(scan.target);
    setPort(scan.scanOptions?.port || 443);
    if (scan.scanOptions) {
      setOptions(scan.scanOptions);
      setScanProfile('custom');
    }
  };

  const simulateProgress = () => {
    const steps = [
      'Resolusi DNS',
      'Konektivitas Dasar',
      'Analisis Sertifikat',
      'Testing Protocol',
      'Analisis Cipher Suite',
      'Pemindaian Vulnerability',
      'Security Headers',
      'Validasi OCSP',
      'Verifikasi CT Log',
      'Pemeriksaan Compliance',
      'Analisis Performance',
      'Grading Akhir'
    ];

    let currentStep = 0;
    const progressInterval = setInterval(() => {
      if (currentStep < steps.length) {
        setScanProgress({
          step: currentStep,
          totalSteps: steps.length,
          currentTask: steps[currentStep],
          percentage: Math.round((currentStep / steps.length) * 100)
        });
        currentStep++;
      } else {
        clearInterval(progressInterval);
      }
    }, 1500); // Update every 1.5 seconds

    return progressInterval;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setResults(null);
    setScanProgress({
      step: 0,
      totalSteps: 12,
      currentTask: 'Memulai scan SSL...',
      percentage: 0
    });

    const progressInterval = simulateProgress();
    const startTime = Date.now();
    
    const scanOptions = {
      port: parseInt(port),
      ...options
    };
    
    try {
      console.log("🔍 Mengirim SSL scan request:", { target, scan_options: scanOptions });
      const response = await api.runSSLScan(target, scanOptions);
      console.log("✅ Menerima SSL scan response:", response);
      
      const endTime = Date.now();
      const duration = `${Math.round((endTime - startTime) / 1000)}s`;
      
      if (response && response.status === 'success') {
        setResults(response.results);
        
        // Save to history using historyService
        try {
          historyService.saveScan({
            scannerType: 'ssl',
            scanType: 'ssl', // Keep both for compatibility
            target: target,
            scanOptions: scanOptions,
            results: response.results,
            status: 'completed',
            duration: duration,
            profile: scanProfile,
            data: response.results // Additional data field
          });
          
          // Update recent scans
          const allHistory = historyService.getAllHistory();
          const sslScans = allHistory
            .filter(scan => scan.scannerType === 'ssl' || scan.scanType === 'ssl')
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
            .slice(0, 5);
          setRecentScans(sslScans);
        } catch (error) {
          console.warn('Error saving scan history:', error);
        }
      } else if (response && response.status === 'error') {
        setError(response.message);
        
        // Save failed scan to history
        try {
          historyService.saveScan({
            scannerType: 'ssl',
            scanType: 'ssl',
            target: target,
            scanOptions: scanOptions,
            error: response.message,
            status: 'failed',
            duration: duration,
            profile: scanProfile
          });
        } catch (error) {
          console.warn('Error saving failed scan:', error);
        }
      }
    } catch (err) {
      console.error("❌ SSL scan error:", err);
      const errorMessage = err.response?.data?.message || err.message || 'Terjadi error saat melakukan SSL scan';
      setError(errorMessage);
      
      // Save failed scan to history
      try {
        historyService.saveScan({
          scannerType: 'ssl',
          scanType: 'ssl',
          target: target,
          scanOptions: scanOptions,
          error: errorMessage,
          status: 'failed',
          duration: `${Math.round((Date.now() - startTime) / 1000)}s`,
          profile: scanProfile
        });
      } catch (saveError) {
        console.warn('Error saving failed scan:', saveError);
      }
    } finally {
      clearInterval(progressInterval);
      setLoading(false);
      setScanProgress({
        step: 12,
        totalSteps: 12,
        currentTask: 'Scan selesai',
        percentage: 100
      });
    }
  };

  const getProfileIcon = (profile) => {
    const IconComponent = scanProfiles[profile]?.icon || FaCog;
    return <IconComponent />;
  };

  return (
    <div className="ssl-scanner-enhanced">
      <button onClick={onBack} className="back-button">
        <FaArrowLeft /> Back to Scanner
      </button>
      
      <div className="scanner-layout">
        {/* Main Scanner Form */}
        <div className="scanner-main">
          <div className="card">
            <div className="scanner-header">
              <div className="scanner-icon ssl">
                <FaLock />
              </div>
              <div className="scanner-title">
                <h2>SSL/TLS Security Scanner</h2>
                <p className="scanner-subtitle">
                  Analisis konfigurasi SSL/TLS yang komprehensif dengan penilaian vulnerability
                </p>
              </div>
            </div>
            
            <form onSubmit={handleSubmit}>
              {/* Target Configuration */}
              <div className="form-section">
                <h3 className="section-title">
                  <FaGlobe /> Konfigurasi Target
                </h3>
                
                <div className="form-row">
                  <div className="form-group flex-grow">
                    <label className="form-label" htmlFor="target">
                      Domain/IP Address Target
                    </label>
                    <input
                      id="target"
                      type="text"
                      value={target}
                      onChange={(e) => setTarget(e.target.value)}
                      placeholder="e.g., example.com, google.com, 192.168.1.1"
                      className="form-input"
                      required
                    />
                    <p className="form-help">
                      Masukkan nama domain atau IP address untuk analisis konfigurasi SSL/TLS
                    </p>
                  </div>
                  
                  <div className="form-group">
                    <label className="form-label" htmlFor="port">
                      Port
                    </label>
                    <input
                      id="port"
                      type="number"
                      value={port}
                      onChange={(e) => setPort(e.target.value)}
                      placeholder="443"
                      className="form-input port-input"
                      min="1"
                      max="65535"
                    />
                  </div>

                  <div className="form-group">
                    <label className="form-label">&nbsp;</label>
                    <button
                      type="button"
                      onClick={addToFavorites}
                      className="btn btn-secondary add-favorite"
                      disabled={!target}
                    >
                      <FaBookmark /> Simpan
                    </button>
                  </div>
                </div>
              </div>

              {/* Scan Profile Selection */}
              <div className="form-section">
                <h3 className="section-title">
                  <FaCog /> Konfigurasi Scan
                </h3>
                
                <div className="profile-selection">
                  <div className="profile-tabs">
                    {Object.entries(scanProfiles).map(([key, profile]) => (
                      <button
                        key={key}
                        type="button"
                        className={`profile-tab ${scanProfile === key ? 'active' : ''}`}
                        onClick={() => handleProfileChange(key)}
                      >
                        {getProfileIcon(key)}
                        <div className="profile-info">
                          <span className="profile-name">{profile.name}</span>
                          <span className="profile-desc">{profile.description}</span>
                        </div>
                      </button>
                    ))}
                    
                    <button
                      type="button"
                      className={`profile-tab ${scanProfile === 'custom' ? 'active' : ''}`}
                      onClick={() => setAdvancedMode(!advancedMode)}
                    >
                      <FaCog />
                      <div className="profile-info">
                        <span className="profile-name">Custom</span>
                        <span className="profile-desc">Konfigurasi advanced</span>
                      </div>
                    </button>
                  </div>
                </div>

                {/* Advanced Options */}
                {(advancedMode || scanProfile === 'custom') && (
                  <div className="advanced-options">
                    <h4 className="options-title">
                      <FaCog /> Opsi Scan Advanced
                    </h4>
                    
                    <div className="options-grid">
                      <div className="option-category">
                        <h5><FaCertificate /> Analisis Sertifikat</h5>
                        <label className="checkbox-label">
                          <input
                            type="checkbox"
                            checked={options.checkChain}
                            onChange={() => handleOptionChange('checkChain')}
                            className="form-checkbox"
                          />
                          <span>Validasi Certificate Chain</span>
                        </label>
                        <label className="checkbox-label">
                          <input
                            type="checkbox"
                            checked={options.checkOCSP}
                            onChange={() => handleOptionChange('checkOCSP')}
                            className="form-checkbox"
                          />
                          <span>Pemeriksaan OCSP Stapling</span>
                        </label>
                        <label className="checkbox-label">
                          <input
                            type="checkbox"
                            checked={options.checkCT}
                            onChange={() => handleOptionChange('checkCT')}
                            className="form-checkbox"
                          />
                          <span>Certificate Transparency</span>
                        </label>
                      </div>

                      <div className="option-category">
                        <h5><FaShieldAlt /> Analisis Keamanan</h5>
                        <label className="checkbox-label">
                          <input
                            type="checkbox"
                            checked={options.checkVulnerabilities}
                            onChange={() => handleOptionChange('checkVulnerabilities')}
                            className="form-checkbox"
                          />
                          <span>Vulnerability Scanning</span>
                        </label>
                        <label className="checkbox-label">
                          <input
                            type="checkbox"
                            checked={options.checkCiphers}
                            onChange={() => handleOptionChange('checkCiphers')}
                            className="form-checkbox"
                          />
                          <span>Analisis Cipher Suite</span>
                        </label>
                        <label className="checkbox-label">
                          <input
                            type="checkbox"
                            checked={options.checkSecurityHeaders}
                            onChange={() => handleOptionChange('checkSecurityHeaders')}
                            className="form-checkbox"
                          />
                          <span>Pemeriksaan Security Headers</span>
                        </label>
                        <label className="checkbox-label">
                          <input
                            type="checkbox"
                            checked={options.checkHSTS}
                            onChange={() => handleOptionChange('checkHSTS')}
                            className="form-checkbox"
                          />
                          <span>Konfigurasi HSTS</span>
                        </label>
                      </div>

                      <div className="option-category">
                        <h5><FaChartLine /> Performance & Compliance</h5>
                        <label className="checkbox-label">
                          <input
                            type="checkbox"
                            checked={options.checkPerformance}
                            onChange={() => handleOptionChange('checkPerformance')}
                            className="form-checkbox"
                          />
                          <span>Metrik Performance</span>
                        </label>
                        <label className="checkbox-label">
                          <input
                            type="checkbox"
                            checked={options.checkCompliance}
                            onChange={() => handleOptionChange('checkCompliance')}
                            className="form-checkbox"
                          />
                          <span>Standar Compliance</span>
                        </label>
                      </div>
                    </div>
                  </div>
                )}
              </div>
              
              <button
                type="submit"
                className="btn btn-primary btn-scan"
                disabled={loading || !target}
              >
                {loading ? (
                  <span className="loading-text">
                    <FaSpinner className="icon-spin" /> Sedang Scanning...
                  </span>
                ) : (
                  <>
                    <FaLock /> Mulai {scanProfiles[scanProfile]?.name || 'SSL'} Scan
                  </>
                )}
              </button>
            </form>
          </div>
        </div>

        {/* Sidebar with Quick Access */}
        <div className="scanner-sidebar">
          {/* Favorites */}
          {favorites.length > 0 && (
            <div className="sidebar-section">
              <h4 className="sidebar-title">
                <FaBookmark /> Favorit
              </h4>
              <div className="quick-access-list">
                {favorites.map((favorite, index) => (
                  <button
                    key={index}
                    className="quick-access-item"
                    onClick={() => loadFromFavorite(favorite)}
                  >
                    <FaGlobe />
                    <div className="item-info">
                      <span className="item-name">{favorite.name}</span>
                      <span className="item-details">{favorite.target}:{favorite.port}</span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Recent Scans */}
          {recentScans.length > 0 && (
            <div className="sidebar-section">
              <h4 className="sidebar-title">
                <FaHistory /> Scan Terbaru
              </h4>
              <div className="quick-access-list">
                {recentScans.map((scan, index) => (
                  <button
                    key={index}
                    className="quick-access-item"
                    onClick={() => loadFromRecent(scan)}
                  >
                    <div className={`status-indicator ${scan.status}`}></div>
                    <div className="item-info">
                      <span className="item-name">{scan.target}</span>
                      <span className="item-details">
                        {new Date(scan.timestamp).toLocaleDateString()} - {scan.duration}
                      </span>
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Security Tips */}
          <div className="sidebar-section">
            <h4 className="sidebar-title">
              <FaInfoCircle /> Tips Keamanan
            </h4>
            <div className="security-tips">
              <div className="tip-item">
                <FaCheckCircle className="tip-icon good" />
                <span>Gunakan TLS 1.2 atau lebih tinggi</span>
              </div>
              <div className="tip-item">
                <FaCheckCircle className="tip-icon good" />
                <span>Aktifkan HSTS headers</span>
              </div>
              <div className="tip-item">
                <FaExclamationTriangle className="tip-icon warning" />
                <span>Nonaktifkan SSLv2 dan SSLv3</span>
              </div>
              <div className="tip-item">
                <FaExclamationTriangle className="tip-icon warning" />
                <span>Hindari cipher suite yang lemah</span>
              </div>
              <div className="tip-item">
                <FaCheckCircle className="tip-icon good" />
                <span>Gunakan RSA key minimal 2048-bit</span>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      {loading && (
        <div className="scan-progress-overlay">
          <div className="card scan-progress">
            <div className="progress-header">
              <h3>
                <FaSpinner className="icon-spin" />
                SSL/TLS Security Scan Sedang Berlangsung
              </h3>
              <p className="progress-subtitle">
                Melakukan analisis komprehensif pada {target}:{port}
              </p>
            </div>
            
            <div className="progress-content">
              <div className="progress-bar-container">
                <div className="progress-info">
                  <span className="current-task">{scanProgress.currentTask}</span>
                  <span className="progress-percentage">{scanProgress.percentage}%</span>
                </div>
                <div className="progress-bar">
                  <div 
                    className="progress-fill"
                    style={{ width: `${scanProgress.percentage}%` }}
                  ></div>
                </div>
                <div className="progress-steps">
                  Langkah {scanProgress.step + 1} dari {scanProgress.totalSteps}
                </div>
              </div>
              
              <div className="scan-details">
                <h4>Yang sedang dianalisis:</h4>
                <div className="analysis-grid">
                  <div className="analysis-item">
                    <FaCertificate />
                    <span>Validitas & chain sertifikat</span>
                  </div>
                  <div className="analysis-item">
                    <FaLock />
                    <span>Versi protocol & cipher</span>
                  </div>
                  <div className="analysis-item">
                    <FaShieldAlt />
                    <span>Vulnerability keamanan</span>
                  </div>
                  <div className="analysis-item">
                    <FaChartLine />
                    <span>Standar compliance</span>
                  </div>
                  <div className="analysis-item">
                    <FaClock />
                    <span>Metrik performance</span>
                  </div>
                  <div className="analysis-item">
                    <FaGlobe />
                    <span>Security headers</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
      
      {error && (
        <div className="alert alert-error">
          <div className="alert-title">
            <FaExclamationTriangle /> Error Scan
          </div>
          <p>{error}</p>
          <div className="alert-actions">
            <button 
              className="btn btn-secondary"
              onClick={() => setError(null)}
            >
              Tutup
            </button>
          </div>
        </div>
      )}
      
      {results && <SSLResults results={results} />}
    </div>
  );
};

export default SSLScanner;