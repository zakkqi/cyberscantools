// frontend/src/components/scanners/SubdomainResults.jsx
import React from 'react';
import { 
  FaCheckCircle, 
  FaExclamationTriangle, 
  FaGlobe,
  FaServer,
  FaCertificate
} from 'react-icons/fa';

const SubdomainResults = ({ results }) => {
  const getStatusIcon = (resolved) => {
    return resolved ? (
      <FaCheckCircle className="status-icon resolved" />
    ) : (
      <FaExclamationTriangle className="status-icon unresolved" />
    );
  };
  
  return (
    <div className="subdomain-results">
      {/* Summary */}
      <div className="card result-summary">
        <h3>Subdomain Discovery Summary</h3>
        <div className="summary-stats">
          <div className="stat-item">
            <span className="stat-value">{results.totalFound || 0}</span>
            <span className="stat-label">Total Subdomains</span>
          </div>
          <div className="stat-item">
            <span className="stat-value">{results.resolvedCount || 0}</span>
            <span className="stat-label">Resolved</span>
          </div>
          <div className="stat-item">
            <span className="stat-value">{results.uniqueIPs || 0}</span>
            <span className="stat-label">Unique IPs</span>
          </div>
          <div className="stat-item">
            <span className="stat-value">{results.technologiesDetected || 0}</span>
            <span className="stat-label">Technologies</span>
          </div>
        </div>
      </div>
      
      {/* Subdomains List */}
      <div className="card subdomains-list">
        <h3>Discovered Subdomains</h3>
        <div className="table-responsive">
          <table className="results-table">
            <thead>
              <tr>
                <th>Subdomain</th>
                <th>IP Address</th>
                <th>Status</th>
                <th>Technologies</th>
                <th>Source</th>
              </tr>
            </thead>
            <tbody>
              {results.subdomains && results.subdomains.map((subdomain, index) => (
                <tr key={index}>
                  <td>
                    <div className="subdomain-info">
                      {getStatusIcon(subdomain.resolved)}
                      <a href={`http://${subdomain.domain}`} target="_blank" rel="noopener noreferrer">
                        {subdomain.domain}
                      </a>
                    </div>
                  </td>
                  <td>{subdomain.ip || 'N/A'}</td>
                  <td>
                    <span className={`status-badge ${subdomain.resolved ? 'resolved' : 'unresolved'}`}>
                      {subdomain.resolved ? 'Resolved' : 'Unresolved'}
                    </span>
                  </td>
                  <td>
                    {subdomain.technologies && subdomain.technologies.length > 0 ? (
                      <div className="tech-tags">
                        {subdomain.technologies.map((tech, i) => (
                          <span key={i} className="tech-tag">{tech}</span>
                        ))}
                      </div>
                    ) : (
                      'N/A'
                    )}
                  </td>
                  <td>
                    <span className="source-tag">{subdomain.source || 'DNS'}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      
      {/* DNS Records */}
      {results.dnsRecords && (
        <div className="card dns-records">
          <h3>DNS Records</h3>
          <div className="dns-grid">
            {Object.entries(results.dnsRecords).map(([type, records]) => (
              <div key={type} className="dns-type">
                <h4>{type} Records</h4>
                <ul>
                  {records.map((record, index) => (
                    <li key={index}>{record}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      )}
      
      {/* WHOIS Information */}
      {results.whoisInfo && (
        <div className="card whois-info">
          <h3>WHOIS Information</h3>
          <div className="whois-content">
            {Object.entries(results.whoisInfo).map(([key, value]) => (
              <div key={key} className="whois-item">
                <label>{key}:</label>
                <span>{value}</span>
              </div>
            ))}
          </div>
        </div>
      )}
      
      {/* Technology Overview */}
      {results.technologyOverview && (
        <div className="card tech-overview">
          <h3>Technology Overview</h3>
          <div className="tech-categories">
            {Object.entries(results.technologyOverview).map(([category, items]) => (
              <div key={category} className="tech-category">
                <h4>{category}</h4>
                <div className="tech-items">
                  {items.map((item, index) => (
                    <div key={index} className="tech-item">
                      <span className="tech-name">{item.name}</span>
                      <span className="tech-count">{item.count}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default SubdomainResults;