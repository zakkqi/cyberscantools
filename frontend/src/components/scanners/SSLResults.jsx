// frontend/src/components/scanners/SSLResults.jsx
import React from 'react';
import { 
  FaCheckCircle, 
  FaExclamationTriangle, 
  FaTimesCircle,
  FaCertificate,
  FaShieldAlt,
  FaKey
} from 'react-icons/fa';

const SSLResults = ({ results }) => {
  // Add safety checks
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
  
  const getProtocolStatus = (supported) => {
    return supported ? (
      <span className="protocol-status supported">Supported</span>
    ) : (
      <span className="protocol-status not-supported">Not Supported</span>
    );
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
  
  const getCertificateStatus = (cert) => {
    if (!cert || typeof cert.isValid === 'undefined') return 'unknown';
    if (!cert.isValid) return 'invalid';
    if (cert.daysRemaining < 0) return 'expired';
    if (cert.daysRemaining < 30) return 'expiring';
    return 'valid';
  };
  
  // Safely get certificate subject
  const getSubjectName = (cert) => {
    if (!cert || !cert.subject) return 'Unknown';
    if (typeof cert.subject === 'string') return cert.subject;
    return cert.subject.CN || cert.subject.O || cert.subject.OU || 'Unknown';
  };
  
  // Safely get issuer name
  const getIssuerName = (cert) => {
    if (!cert || !cert.issuer) return 'Unknown';
    if (typeof cert.issuer === 'string') return cert.issuer;
    return cert.issuer.O || cert.issuer.CN || cert.issuer.OU || 'Unknown';
  };
  
  return (
    <div className="ssl-results">
      {/* Grade Overview */}
      <div className="card ssl-grade-card">
        <div className="grade-content">
          <div className="grade-circle" style={{ backgroundColor: getGradeColor(results.grade) }}>
            {results.grade}
          </div>
          <div className="grade-info">
            <h3>Overall SSL/TLS Grade</h3>
            <p>Based on protocols, cipher suites, and configuration</p>
          </div>
        </div>
      </div>
      
      {/* Certificate Information */}
      <div className="card ssl-section">
        <div className="section-header">
          <h3><FaCertificate /> Certificate Information</h3>
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
              <label>Signature Algorithm:</label>
              <span>{results.certificate.signatureAlgorithm || 'Unknown'}</span>
            </div>
            <div className="cert-detail-item">
              <label>Key Size:</label>
              <span>{results.certificate.keySize || 'Unknown'} bits</span>
            </div>
          </div>
          
          {results.certificate.subjectAltNames && results.certificate.subjectAltNames.length > 0 && (
            <div className="san-list">
              <h4>Subject Alternative Names:</h4>
              <ul>
                {results.certificate.subjectAltNames.map((san, index) => (
                  <li key={index}>{san}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
      
      {/* Rest of the component remains the same... */}
    </div>
  );
};

export default SSLResults;