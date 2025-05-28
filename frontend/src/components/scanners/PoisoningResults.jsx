// frontend/src/components/scanners/PoisoningResults.jsx
import React from 'react';
import { 
  FaExclamationTriangle, 
  FaCheckCircle,
  FaTimesCircle,
  FaInfoCircle
} from 'react-icons/fa';

const PoisoningResults = ({ results }) => {
  const getRiskLevelColor = (level) => {
    const colors = {
      'Critical': '#b71c1c',
      'High': '#d32f2f',
      'Medium': '#f57c00',
      'Low': '#388e3c'
    };
    return colors[level] || '#757575';
  };
  
  const getRiskLevelIcon = (level) => {
    switch (level) {
      case 'Critical':
      case 'High':
        return <FaTimesCircle className="risk-icon critical" />;
      case 'Medium':
        return <FaExclamationTriangle className="risk-icon warning" />;
      case 'Low':
        return <FaCheckCircle className="risk-icon safe" />;
      default:
        return <FaInfoCircle className="risk-icon" />;
    }
  };
  
  return (
    <div className="poisoning-results">
      {/* Risk Assessment */}
      <div className="card risk-assessment">
        <div className="risk-header">
          <h3>SEO Poisoning Risk Assessment</h3>
          <div 
            className="risk-badge"
            style={{ backgroundColor: getRiskLevelColor(results.risk_level) }}
          >
            {getRiskLevelIcon(results.risk_level)}
            <span>{results.risk_level} Risk</span>
          </div>
        </div>
        
        <div className="risk-status">
          {results.poisoning_detected ? (
            <div className="alert alert-danger">
              <FaTimesCircle /> SEO Poisoning Detected
            </div>
          ) : (
            <div className="alert alert-success">
              <FaCheckCircle /> No SEO Poisoning Detected
            </div>
          )}
        </div>
      </div>
      
      {/* SERP Manipulation */}
      {results.serp_manipulation && results.serp_manipulation.length > 0 && (
  <div className="card">
    <h3><FaExclamationTriangle /> SERP Manipulation Detected</h3>
    <div className="manipulation-list">
      {results.serp_manipulation.map((item, index) => (
        <div key={index} className="manipulation-item">
          <div className="query-info">
            <label>Search Query:</label>
            <code>{item.query}</code>
          </div>
          <div className="serp-content">
            <label>Google Shows:</label>
            <div className="serp-box">
              <h4>{item.serp_title}</h4>
              <p>{item.serp_snippet}</p>
              <cite>{item.url}</cite>
            </div>
          </div>
          <div className="actual-content">
            <label>But Website Actually Shows:</label>
            <p>Normal government content (no gambling content found)</p>
          </div>
          <div className="severity-badge critical">
            Critical - SEO Poisoning Confirmed
          </div>
        </div>
      ))}
    </div>
  </div>
)}
      
      {/* Cloaking Detection */}
      {results.cloaking_detected && (
        <div className="card">
          <h3><FaTimesCircle /> Cloaking Detected</h3>
          <p>Your website is showing different content to search engines vs regular users.</p>
          {results.cloaking_details && (
            <div className="cloaking-details">
              {results.cloaking_details.map((detail, index) => (
                <div key={index} className="cloaking-item">
                  <p>Path: <code>{detail.path}</code></p>
                  <p>Googlebot sees suspicious content: {detail.googlebot_content_suspicious ? 'Yes' : 'No'}</p>
                  <p>Normal users see suspicious content: {detail.normal_content_suspicious ? 'Yes' : 'No'}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      
      {/* Suspicious Content */}
      {results.suspicious_content && results.suspicious_content.length > 0 && (
        <div className="card">
          <h3><FaExclamationTriangle /> Suspicious Content Found</h3>
          <div className="suspicious-list">
            {results.suspicious_content.map((item, index) => (
              <div key={index} className="suspicious-item">
                <div className="content-type">{item.type}</div>
                <div className="content-path">Path: {item.path}</div>
                <div className="content-preview">{item.content}</div>
                <div className={`severity-badge ${item.severity.toLowerCase()}`}>
                  {item.severity}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      
      {/* Phishing Indicators */}
      {results.phishing_indicators && results.phishing_indicators.length > 0 && (
        <div className="card">
          <h3><FaExclamationTriangle /> Phishing Indicators</h3>
          <div className="phishing-list">
            {results.phishing_indicators.map((item, index) => (
              <div key={index} className="phishing-item">
                <p>Type: {item.type}</p>
                {item.action && <p>Form Action: <code>{item.action}</code></p>}
                {item.src && <p>iFrame Source: <code>{item.src}</code></p>}
              </div>
            ))}
          </div>
        </div>
      )}
      
      {/* Redirect Analysis */}
      {results.redirect_analysis && results.redirect_analysis.has_redirects && (
        <div className="card">
          <h3><FaInfoCircle /> Redirect Chain Analysis</h3>
          <div className={`redirect-status ${results.redirect_analysis.suspicious ? 'suspicious' : 'normal'}`}>
            {results.redirect_analysis.suspicious ? 
              'Suspicious redirects detected!' : 
              'Redirect chain appears normal'
            }
          </div>
          <div className="redirect-chain">
            {results.redirect_analysis.chain.map((redirect, index) => (
              <div key={index} className="redirect-item">
                <span>{redirect.from}</span>
                <span className="arrow">→</span>
                <span>{redirect.to}</span>
                <span className="status-code">({redirect.status})</span>
              </div>
            ))}
          </div>
        </div>
      )}
      
      {/* Blacklist Status */}
      {results.blacklist_status && results.blacklist_status.length > 0 && (
        <div className="card">
          <h3><FaInfoCircle /> Blacklist Status</h3>
          <div className="blacklist-list">
            {results.blacklist_status.map((item, index) => (
              <div key={index} className="blacklist-item">
                <span className="service">{item.service}:</span>
                <span className="status">{item.status}</span>
                <a href={item.url} target="_blank" rel="noopener noreferrer">
                  Check manually
                </a>
              </div>
            ))}
          </div>
        </div>
      )}
      
      {/* Recommendations */}
      {results.recommendations && results.recommendations.length > 0 && (
        <div className="card recommendations">
          <h3><FaInfoCircle /> Recommendations</h3>
          <ul>
            {results.recommendations.map((rec, index) => (
              <li key={index}>{rec}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default PoisoningResults;