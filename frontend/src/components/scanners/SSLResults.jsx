// frontend/src/components/scanners/SSLResults.jsx
import React, { useState, useEffect } from 'react';
import { 
  FaCheckCircle, 
  FaExclamationTriangle, 
  FaTimesCircle,
  FaCertificate,
  FaShieldAlt,
  FaKey,
  FaDownload,
  FaEye,
  FaHistory,
  FaClock,
  FaGlobe,
  FaLock,
  FaUnlock,
  FaExclamationCircle,
  FaInfoCircle,
  FaChartLine,
  FaTachometerAlt,
  FaFileExport
} from 'react-icons/fa';

const SSLResults = ({ results }) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [showDetails, setShowDetails] = useState({});
  const [exportFormat, setExportFormat] = useState('json');

  // Safety checks
  if (!results || !results.certificate) {
    return (
      <div className="alert alert-error">
        <div className="alert-title">Error</div>
        <p>Invalid SSL scan results</p>
      </div>
    );
  }

  const getGradeColor = (grade) => {
    const colors = {
      'A+': '#00c853',
      'A': '#2e7d32',
      'B': '#558b2f',
      'C': '#f57c00',
      'D': '#e65100',
      'F': '#b71c1c'
    };
    return colors[grade] || '#757575';
  };

  // Custom chart components to replace Chart.js
  const CircularProgress = ({ percentage, size = 100, strokeWidth = 8, color = '#4caf50' }) => {
    const radius = (size - strokeWidth) / 2;
    const circumference = radius * 2 * Math.PI;
    const offset = circumference - (percentage / 100) * circumference;

    return (
      <div className="circular-progress" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="circular-progress-svg">
          <circle
            className="circular-progress-background"
            stroke="#e0e0e0"
            fill="transparent"
            strokeWidth={strokeWidth}
            r={radius}
            cx={size / 2}
            cy={size / 2}
          />
          <circle
            className="circular-progress-bar"
            stroke={color}
            fill="transparent"
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            r={radius}
            cx={size / 2}
            cy={size / 2}
            style={{
              transition: 'stroke-dashoffset 0.5s ease-in-out',
              transform: 'rotate(-90deg)',
              transformOrigin: '50% 50%'
            }}
          />
        </svg>
        <div className="circular-progress-text">
          <span className="score-number">{percentage}</span>
          <span className="score-label">/ 100</span>
        </div>
      </div>
    );
  };

  const BarChart = ({ data, labels, colors }) => {
    const maxValue = Math.max(...data);
    
    return (
      <div className="custom-bar-chart">
        {labels.map((label, index) => {
          const height = maxValue > 0 ? (data[index] / maxValue) * 100 : 0;
          return (
            <div key={index} className="bar-item">
              <div className="bar-container">
                <div 
                  className="bar-fill"
                  style={{
                    height: `${height}%`,
                    backgroundColor: colors[index] || '#4caf50'
                  }}
                ></div>
              </div>
              <span className="bar-label">{label}</span>
            </div>
          );
        })}
      </div>
    );
  };

  // Helper for security score color
  const getSecurityScoreColor = (score) => {
    if (score >= 90) return '#00c853';
    if (score >= 80) return '#2e7d32';
    if (score >= 70) return '#558b2f';
    if (score >= 60) return '#f57c00';
    if (score >= 50) return '#e65100';
    return '#b71c1c';
  };

  const getRiskLevelColor = (riskLevel) => {
    const colors = {
      'MINIMAL': '#00c853',
      'LOW': '#2e7d32',
      'MEDIUM': '#f57c00',
      'HIGH': '#e65100',
      'CRITICAL': '#b71c1c'
    };
    return colors[riskLevel] || '#757575';
  };

  const getSeverityIcon = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return <FaExclamationCircle className="severity-icon critical" />;
      case 'high':
        return <FaExclamationTriangle className="severity-icon high" />;
      case 'medium':
        return <FaInfoCircle className="severity-icon medium" />;
      case 'low':
        return <FaCheckCircle className="severity-icon low" />;
      default:
        return <FaInfoCircle className="severity-icon unknown" />;
    }
  };

  const getVulnerabilityIcon = (status) => {
    switch (status) {
      case 'not_vulnerable':
        return <FaCheckCircle className="vuln-icon safe" />;
      case 'vulnerable':
        return <FaTimesCircle className="vuln-icon danger" />;
      default:
        return <FaExclamationTriangle className="vuln-icon warning" />;
    }
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString();
  };

  const formatDuration = (seconds) => {
    if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
    return `${seconds}s`;
  };

  const getCertificateStatus = (cert) => {
    if (!cert || typeof cert.isValid === 'undefined') return 'unknown';
    if (!cert.isValid) return 'invalid';
    if (cert.daysRemaining < 0) return 'expired';
    if (cert.daysRemaining < 30) return 'expiring';
    return 'valid';
  };

  const getSubjectName = (cert) => {
    if (!cert || !cert.subject) return 'Unknown';
    if (typeof cert.subject === 'string') return cert.subject;
    return cert.subject.commonName || cert.subject.CN || cert.subject.O || cert.subject.OU || 'Unknown';
  };

  const getIssuerName = (cert) => {
    if (!cert || !cert.issuer) return 'Unknown';
    if (typeof cert.issuer === 'string') return cert.issuer;
    return cert.issuer.organizationName || cert.issuer.O || cert.issuer.CN || cert.issuer.OU || 'Unknown';
  };

  const exportResults = (format) => {
    const timestamp = new Date().toISOString().split('T')[0];
    const filename = `ssl-scan-${results.target}-${timestamp}`;
    
    if (format === 'json') {
      const blob = new Blob([JSON.stringify(results, null, 2)], 
        { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${filename}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } else if (format === 'pdf') {
      // Implement PDF export functionality
      alert('PDF export feature coming soon!');
    }
  };

  const toggleDetails = (section) => {
    setShowDetails(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  // Protocol data for custom bar chart
  const getProtocolChartData = () => {
    if (!results.protocols) return { labels: [], data: [], colors: [] };
    
    const labels = Object.keys(results.protocols);
    const data = Object.values(results.protocols).map(p => p.supported ? 1 : 0);
    const colors = Object.values(results.protocols).map(p => 
      p.supported ? '#4caf50' : '#f44336'
    );
    
    return { labels, data, colors };
  };

  // Timeline data for certificate validity
  const getCertificateTimeline = () => {
    const cert = results.certificate;
    if (!cert) return null;

    const now = new Date();
    const notBefore = new Date(cert.notBefore);
    const notAfter = new Date(cert.notAfter);
    const totalDuration = notAfter - notBefore;
    const elapsed = now - notBefore;
    const remaining = notAfter - now;

    return {
      totalDays: Math.floor(totalDuration / (1000 * 60 * 60 * 24)),
      elapsedDays: Math.floor(elapsed / (1000 * 60 * 60 * 24)),
      remainingDays: Math.floor(remaining / (1000 * 60 * 60 * 24)),
      percentElapsed: (elapsed / totalDuration) * 100
    };
  };

  const renderOverviewTab = () => (
    <div className="overview-content">
      {/* Security Dashboard */}
      <div className="security-dashboard">
        <div className="dashboard-cards">
          {/* Overall Grade */}
          <div className="dashboard-card grade-card">
            <div className="card-icon" style={{ backgroundColor: getGradeColor(results.grade?.grade || results.grade) }}>
              <FaTachometerAlt />
            </div>
            <div className="card-content">
              <h3>Overall Grade</h3>
              <div className="grade-display" style={{ color: getGradeColor(results.grade?.grade || results.grade) }}>
                {results.grade?.grade || results.grade || 'N/A'}
              </div>
              {results.grade?.score && (
                <p className="score-text">Score: {results.grade.score}/100</p>
              )}
            </div>
          </div>

          {/* Security Score */}
          <div className="dashboard-card score-card">
            <div className="card-content">
              <h3>Security Score</h3>
              <div className="score-chart">
                <CircularProgress 
                  percentage={results.security_score || 0}
                  size={100}
                  color={getSecurityScoreColor(results.security_score || 0)}
                />
              </div>
            </div>
          </div>

          {/* Risk Assessment */}
          <div className="dashboard-card risk-card">
            <div className="card-icon" style={{ backgroundColor: getRiskLevelColor(results.risk_assessment?.risk_level) }}>
              <FaShieldAlt />
            </div>
            <div className="card-content">
              <h3>Risk Level</h3>
              <div className="risk-display" style={{ color: getRiskLevelColor(results.risk_assessment?.risk_level) }}>
                {results.risk_assessment?.risk_level || 'UNKNOWN'}
              </div>
              {results.risk_assessment?.risk_score && (
                <p className="risk-score">Risk Score: {results.risk_assessment.risk_score}</p>
              )}
            </div>
          </div>

          {/* Performance */}
          <div className="dashboard-card performance-card">
            <div className="card-icon">
              <FaClock />
            </div>
            <div className="card-content">
              <h3>Handshake Time</h3>
              <div className="performance-display">
                {results.performance_metrics?.handshake_time || results.connectivity?.ssl_handshake_time || 'N/A'}
                {(results.performance_metrics?.handshake_time || results.connectivity?.ssl_handshake_time) && 'ms'}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Issues Summary */}
      {results.securityStatus?.issues && results.securityStatus.issues.length > 0 && (
        <div className="issues-summary">
          <h3>
            <FaExclamationTriangle /> 
            Security Issues Found ({results.securityStatus.issues.length})
          </h3>
          <div className="issues-grid">
            {results.securityStatus.issues.slice(0, 4).map((issue, index) => (
              <div key={index} className={`issue-card ${issue.severity.toLowerCase()}`}>
                {getSeverityIcon(issue.severity)}
                <div className="issue-content">
                  <h4>{issue.type.replace(/_/g, ' ')}</h4>
                  <p>{issue.description}</p>
                </div>
              </div>
            ))}
          </div>
          {results.securityStatus.issues.length > 4 && (
            <p className="more-issues">
              +{results.securityStatus.issues.length - 4} more issues found
            </p>
          )}
        </div>
      )}

      {/* Certificate Status */}
      <div className="certificate-overview">
        <h3><FaCertificate /> Certificate Overview</h3>
        <div className="cert-status-grid">
          <div className="cert-status-item">
            <label>Status:</label>
            <span className={`cert-status ${getCertificateStatus(results.certificate)}`}>
              {getCertificateStatus(results.certificate).toUpperCase()}
            </span>
          </div>
          <div className="cert-status-item">
            <label>Subject:</label>
            <span>{getSubjectName(results.certificate)}</span>
          </div>
          <div className="cert-status-item">
            <label>Issuer:</label>
            <span>{getIssuerName(results.certificate)}</span>
          </div>
          <div className="cert-status-item">
            <label>Days Remaining:</label>
            <span className={results.certificate.daysRemaining < 30 ? 'expiring' : ''}>
              {results.certificate.daysRemaining || 0} days
            </span>
          </div>
        </div>

        {/* Certificate Timeline */}
        {getCertificateTimeline() && (
          <div className="certificate-timeline">
            <div className="timeline-header">
              <span>Certificate Validity Period</span>
              <span>{getCertificateTimeline().remainingDays} days remaining</span>
            </div>
            <div className="timeline-bar">
              <div 
                className="timeline-progress"
                style={{ width: `${getCertificateTimeline().percentElapsed}%` }}
              ></div>
            </div>
            <div className="timeline-labels">
              <span>{formatDate(results.certificate.notBefore)}</span>
              <span>{formatDate(results.certificate.notAfter)}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );

  const renderCertificateTab = () => (
    <div className="certificate-content">
      {/* Certificate Details */}
      <div className="card ssl-section">
        <div className="section-header">
          <h3><FaCertificate /> Certificate Details</h3>
          <button 
            className="btn btn-secondary btn-sm"
            onClick={() => toggleDetails('cert-details')}
          >
            <FaEye /> {showDetails['cert-details'] ? 'Hide' : 'Show'} Details
          </button>
        </div>

        <div className="cert-info">
          <div className={`cert-status-banner cert-status-${getCertificateStatus(results.certificate)}`}>
            {getCertificateStatus(results.certificate) === 'valid' ? (
              <><FaCheckCircle /> Valid Certificate</>
            ) : getCertificateStatus(results.certificate) === 'expiring' ? (
              <><FaExclamationTriangle /> Certificate Expiring Soon</>
            ) : (
              <><FaTimesCircle /> Invalid Certificate</>
            )}
          </div>
          
          <div className="cert-details">
            <div className="cert-detail-item">
              <label>Subject:</label>
              <span>{getSubjectName(results.certificate)}</span>
            </div>
            <div className="cert-detail-item">
              <label>Issuer:</label>
              <span>{getIssuerName(results.certificate)}</span>
            </div>
            <div className="cert-detail-item">
              <label>Valid From:</label>
              <span>{results.certificate.notBefore ? formatDate(results.certificate.notBefore) : 'Unknown'}</span>
            </div>
            <div className="cert-detail-item">
              <label>Valid Until:</label>
              <span>{results.certificate.notAfter ? formatDate(results.certificate.notAfter) : 'Unknown'}</span>
            </div>
            <div className="cert-detail-item">
              <label>Days Remaining:</label>
              <span className={results.certificate.daysRemaining < 30 ? 'text-warning' : ''}>
                {results.certificate.daysRemaining || 0} days
              </span>
            </div>
            <div className="cert-detail-item">
              <label>Serial Number:</label>
              <span className="monospace">{results.certificate.serialNumber || 'Unknown'}</span>
            </div>
          </div>

          {showDetails['cert-details'] && (
            <div className="cert-extended-details">
              <div className="cert-detail-item">
                <label>Signature Algorithm:</label>
                <span>{results.certificate.signatureAlgorithm || 'Unknown'}</span>
              </div>
              <div className="cert-detail-item">
                <label>Key Type:</label>
                <span>{results.certificate.keyType || 'Unknown'}</span>
              </div>
              <div className="cert-detail-item">
                <label>Key Size:</label>
                <span>{results.certificate.keySize || 'Unknown'} bits</span>
              </div>
              <div className="cert-detail-item">
                <label>Key Strength:</label>
                <span className={`key-strength ${(results.certificate.keyStrength || '').toLowerCase().replace(' ', '-')}`}>
                  {results.certificate.keyStrength || 'Unknown'}
                </span>
              </div>
              
              {/* Fingerprints */}
              <div className="fingerprints-section">
                <h4>Certificate Fingerprints</h4>
                <div className="fingerprint-list">
                  {results.certificate.fingerprint && Object.entries(results.certificate.fingerprint).map(([type, value]) => (
                    <div key={type} className="fingerprint-item">
                      <label>{type.toUpperCase()}:</label>
                      <span className="monospace">{value}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Certificate Weaknesses */}
              {results.certificate.weakness_detected && results.certificate.weakness_detected.length > 0 && (
                <div className="weaknesses-section">
                  <h4><FaExclamationTriangle /> Security Weaknesses Detected</h4>
                  <ul className="weakness-list">
                    {results.certificate.weakness_detected.map((weakness, index) => (
                      <li key={index} className="weakness-item">
                        <FaExclamationCircle className="weakness-icon" />
                        {weakness}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
          
          {/* Subject Alternative Names */}
          {results.certificate.subjectAltNames && results.certificate.subjectAltNames.length > 0 && (
            <div className="san-list">
              <h4>Subject Alternative Names:</h4>
              <div className="san-grid">
                {results.certificate.subjectAltNames.map((san, index) => (
                  <div key={index} className="san-item">{san}</div>
                ))}
              </div>
            </div>
          )}

          {/* Certificate Chain */}
          {results.certificate.chain && results.certificate.chain.length > 0 && (
            <div className="chain-section">
              <h4>Certificate Chain ({results.certificate.chain.length} certificates)</h4>
              <div className="chain-list">
                {results.certificate.chain.map((cert, index) => (
                  <div key={index} className="chain-item">
                    <div className="chain-index">{index + 1}</div>
                    <div className="chain-details">
                      <div className="chain-subject">
                        <strong>Subject:</strong> {typeof cert.subject === 'string' ? cert.subject : JSON.stringify(cert.subject)}
                      </div>
                      <div className="chain-issuer">
                        <strong>Issuer:</strong> {typeof cert.issuer === 'string' ? cert.issuer : JSON.stringify(cert.issuer)}
                      </div>
                      <div className="chain-validity">
                        <strong>Valid:</strong> {formatDate(cert.notBefore)} - {formatDate(cert.notAfter)}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );

  const renderProtocolsTab = () => (
    <div className="protocols-content">
      <div className="card ssl-section">
        <div className="section-header">
          <h3><FaLock /> Protocol Support</h3>
        </div>
        
        <div className="protocols-analysis">
          {/* Protocol Support Chart */}
          <div className="protocol-chart">
            <h4>Protocol Distribution</h4>
            <BarChart 
              data={getProtocolChartData().data}
              labels={getProtocolChartData().labels}
              colors={getProtocolChartData().colors}
            />
          </div>

          {/* Protocol Details */}
          <div className="protocols-grid">
            {Object.entries(results.protocols || {}).map(([protocol, details]) => (
              <div key={protocol} className={`protocol-item ${details.supported ? 'supported' : 'not-supported'}`}>
                <div className="protocol-header">
                  <span className="protocol-name">{protocol}</span>
                  <span className={`protocol-status ${details.supported ? 'supported' : 'not-supported'}`}>
                    {details.supported ? (
                      <><FaCheckCircle /> Supported</>
                    ) : (
                      <><FaTimesCircle /> Not Supported</>
                    )}
                  </span>
                </div>
                
                {details.supported && details.details && (
                  <div className="protocol-details">
                    {details.details.cipher_used && (
                      <div className="protocol-detail">
                        <label>Cipher:</label>
                        <span>{details.details.cipher_used}</span>
                      </div>
                    )}
                    {details.details.handshake_time && (
                      <div className="protocol-detail">
                        <label>Handshake Time:</label>
                        <span>{details.details.handshake_time}ms</span>
                      </div>
                    )}
                    {details.details.protocol_version && (
                      <div className="protocol-detail">
                        <label>Version:</label>
                        <span>{details.details.protocol_version}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Protocol Recommendations */}
        <div className="protocol-recommendations">
          <h4>Protocol Recommendations</h4>
          <div className="recommendation-list">
            {results.protocols?.SSLv2?.supported && (
              <div className="recommendation critical">
                <FaExclamationCircle />
                <span>Disable SSLv2 immediately - severely vulnerable</span>
              </div>
            )}
            {results.protocols?.SSLv3?.supported && (
              <div className="recommendation high">
                <FaExclamationTriangle />
                <span>Disable SSLv3 - vulnerable to POODLE attack</span>
              </div>
            )}
            {results.protocols?.['TLSv1.0']?.supported && (
              <div className="recommendation medium">
                <FaInfoCircle />
                <span>Consider disabling TLS 1.0 - deprecated protocol</span>
              </div>
            )}
            {!results.protocols?.['TLSv1.3']?.supported && (
              <div className="recommendation low">
                <FaInfoCircle />
                <span>Enable TLS 1.3 for better security and performance</span>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );

  const renderVulnerabilitiesTab = () => (
    <div className="vulnerabilities-content">
      <div className="card ssl-section">
        <div className="section-header">
          <h3><FaShieldAlt /> Vulnerability Assessment</h3>
        </div>
        
        {results.vulnerabilities && results.vulnerabilities.length > 0 ? (
          <div className="vulnerabilities-list">
            {results.vulnerabilities.map((vuln, index) => (
              <div key={index} className={`vulnerability-item ${vuln.status}`}>
                <div className="vuln-header">
                  {getVulnerabilityIcon(vuln.status)}
                  <div className="vuln-info">
                    <h4>{vuln.name}</h4>
                    <span className={`severity severity-${vuln.severity}`}>
                      {vuln.severity?.toUpperCase()}
                    </span>
                  </div>
                  <button 
                    className="btn btn-sm btn-secondary"
                    onClick={() => toggleDetails(`vuln-${index}`)}
                  >
                    {showDetails[`vuln-${index}`] ? 'Hide' : 'Show'} Details
                  </button>
                </div>
                
                <p className="vuln-description">{vuln.description}</p>
                
                {showDetails[`vuln-${index}`] && (
                  <div className="vuln-details">
                    {vuln.details && Object.keys(vuln.details).length > 0 && (
                      <div className="vuln-technical-details">
                        <h5>Technical Details:</h5>
                        <pre>{JSON.stringify(vuln.details, null, 2)}</pre>
                      </div>
                    )}
                    
                    {vuln.remediation && (
                      <div className="vuln-remediation">
                        <h5>Remediation:</h5>
                        <p>{vuln.remediation}</p>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="no-vulnerabilities">
            <FaCheckCircle className="success-icon" />
            <h4>No Known Vulnerabilities Detected</h4>
            <p>Your SSL/TLS configuration appears to be secure against common vulnerabilities.</p>
          </div>
        )}
      </div>
    </div>
  );

  const renderRecommendationsTab = () => (
    <div className="recommendations-content">
      <div className="card ssl-section">
        <div className="section-header">
          <h3><FaChartLine /> Security Recommendations</h3>
        </div>
        
        {results.recommendations && results.recommendations.length > 0 ? (
          <div className="recommendations-list">
            {results.recommendations.map((rec, index) => (
              <div key={index} className={`recommendation-item ${rec.priority?.toLowerCase() || 'medium'}`}>
                <div className="rec-header">
                  {getSeverityIcon(rec.priority)}
                  <div className="rec-info">
                    <h4>{rec.category || 'General'}: {rec.issue || rec}</h4>
                    {rec.priority && (
                      <span className={`priority priority-${rec.priority.toLowerCase()}`}>
                        {rec.priority} Priority
                      </span>
                    )}
                  </div>
                </div>
                
                {rec.recommendation && (
                  <div className="rec-content">
                    <p className="rec-recommendation">{rec.recommendation}</p>
                    {rec.impact && (
                      <p className="rec-impact">
                        <strong>Impact:</strong> {rec.impact}
                      </p>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="no-recommendations">
            <FaCheckCircle className="success-icon" />
            <h4>No Recommendations</h4>
            <p>Your SSL/TLS configuration appears to be optimally configured.</p>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="ssl-results-enhanced">
      {/* Header Section */}
      <div className="results-header">
        <div className="scan-info">
          <h2>SSL/TLS Scan Results</h2>
          <div className="scan-metadata">
            <span><FaGlobe /> Target: {results.target}:{results.port}</span>
            <span><FaClock /> Scanned: {formatDate(results.timestamp)}</span>
            <span><FaTachometerAlt /> Duration: {formatDuration(results.scan_duration)}</span>
          </div>
        </div>
        
        <div className="header-actions">
          <div className="export-controls">
            <select 
              value={exportFormat} 
              onChange={(e) => setExportFormat(e.target.value)}
              className="export-select"
            >
              <option value="json">JSON</option>
              <option value="pdf">PDF</option>
              <option value="csv">CSV</option>
            </select>
            <button 
              className="btn btn-primary"
              onClick={() => exportResults(exportFormat)}
            >
              <FaDownload /> Export
            </button>
          </div>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div className="results-tabs">
        <button 
          className={`tab-button ${activeTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          <FaTachometerAlt /> Overview
        </button>
        <button 
          className={`tab-button ${activeTab === 'certificate' ? 'active' : ''}`}
          onClick={() => setActiveTab('certificate')}
        >
          <FaCertificate /> Certificate
        </button>
        <button 
          className={`tab-button ${activeTab === 'protocols' ? 'active' : ''}`}
          onClick={() => setActiveTab('protocols')}
        >
          <FaLock /> Protocols
        </button>
        <button 
          className={`tab-button ${activeTab === 'vulnerabilities' ? 'active' : ''}`}
          onClick={() => setActiveTab('vulnerabilities')}
        >
          <FaShieldAlt /> Vulnerabilities
        </button>
        <button 
          className={`tab-button ${activeTab === 'recommendations' ? 'active' : ''}`}
          onClick={() => setActiveTab('recommendations')}
        >
          <FaChartLine /> Recommendations
        </button>
      </div>

      {/* Tab Content */}
      <div className="tab-content">
        {activeTab === 'overview' && renderOverviewTab()}
        {activeTab === 'certificate' && renderCertificateTab()}
        {activeTab === 'protocols' && renderProtocolsTab()}
        {activeTab === 'vulnerabilities' && renderVulnerabilitiesTab()}
        {activeTab === 'recommendations' && renderRecommendationsTab()}
      </div>
    </div>
  );
};

export default SSLResults;