// frontend/src/components/scanners/SubdomainResults.jsx
import React, { useState } from 'react';
import { 
  FaCheckCircle, 
  FaTimesCircle,
  FaExternalLinkAlt,
  FaFilter,
  FaDownload,
  FaCopy
} from 'react-icons/fa';

const SubdomainResults = ({ results }) => {
  const [filter, setFilter] = useState('all'); // all, resolved, unresolved
  const [copied, setCopied] = useState(false);
  
  const filteredSubdomains = results.subdomains?.filter(subdomain => {
    if (filter === 'resolved') return subdomain.resolved;
    if (filter === 'unresolved') return !subdomain.resolved;
    return true;
  }) || [];
  
  const handleCopySubdomains = () => {
    const subdomainList = filteredSubdomains.map(s => s.domain).join('\n');
    navigator.clipboard.writeText(subdomainList);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };
  
  const handleExportCSV = () => {
    const csvContent = [
      ['Subdomain', 'IP Address', 'Status', 'HTTP', 'HTTPS'],
      ...filteredSubdomains.map(s => [
        s.domain,
        s.ip || 'N/A',
        s.resolved ? 'Resolved' : 'Unresolved',
        s.http_status || 'N/A',
        s.https_status || 'N/A'
      ])
    ].map(row => row.join(',')).join('\n');
    
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `subdomains_${results.target}_${new Date().toISOString().split('T')[0]}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };
  
  const getStatusIcon = (resolved) => {
    return resolved ? (
      <FaCheckCircle className="status-icon resolved" title="Resolved" />
    ) : (
      <FaTimesCircle className="status-icon unresolved" title="Unresolved" />
    );
  };
  
  const getHttpStatusBadge = (status) => {
    if (!status) return null;
    
    const getStatusClass = (code) => {
      if (code >= 200 && code < 300) return 'success';
      if (code >= 300 && code < 400) return 'warning';
      if (code >= 400) return 'error';
      return 'default';
    };
    
    return (
      <span className={`http-status ${getStatusClass(status)}`}>
        {status}
      </span>
    );
  };
  
  return (
    <div className="subdomain-results">
      {/* Summary Card */}
      <div className="card result-summary">
        <h3>Scan Results for {results.target}</h3>
        <div className="summary-grid">
          <div className="summary-item">
            <span className="summary-value">{results.summary?.total_found || 0}</span>
            <span className="summary-label">Total Found</span>
          </div>
          <div className="summary-item">
            <span className="summary-value">{results.summary?.resolved || 0}</span>
            <span className="summary-label">Resolved</span>
          </div>
          <div className="summary-item">
            <span className="summary-value">{results.summary?.unique_ips || 0}</span>
            <span className="summary-label">Unique IPs</span>
          </div>
          <div className="summary-item">
            <span className="summary-value">{results.summary?.scan_duration || 0}s</span>
            <span className="summary-label">Duration</span>
          </div>
        </div>
      </div>
      
      {/* Subdomains List */}
      <div className="card subdomains-section">
        <div className="section-header">
          <h3>Discovered Subdomains ({filteredSubdomains.length})</h3>
          <div className="section-controls">
            <div className="filter-group">
              <FaFilter />
              <select 
                value={filter} 
                onChange={(e) => setFilter(e.target.value)}
                className="filter-select"
              >
                <option value="all">All ({results.subdomains?.length || 0})</option>
                <option value="resolved">Resolved ({results.summary?.resolved || 0})</option>
                <option value="unresolved">Unresolved ({(results.subdomains?.length || 0) - (results.summary?.resolved || 0)})</option>
              </select>
            </div>
            
            <button 
              onClick={handleCopySubdomains}
              className="btn btn-secondary btn-sm"
              title="Copy subdomain list"
            >
              <FaCopy />
              {copied ? 'Copied!' : 'Copy'}
            </button>
            
            <button 
              onClick={handleExportCSV}
              className="btn btn-secondary btn-sm"
              title="Export to CSV"
            >
              <FaDownload />
              Export
            </button>
          </div>
        </div>
        
        {filteredSubdomains.length > 0 ? (
          <div className="subdomains-table">
            <div className="table-header">
              <div className="col-domain">Subdomain</div>
              <div className="col-ip">IP Address</div>
              <div className="col-status">Status</div>
              <div className="col-http">HTTP</div>
              <div className="col-actions">Actions</div>
            </div>
            
            <div className="table-body">
              {filteredSubdomains.map((subdomain, index) => (
                <div key={index} className="table-row">
                  <div className="col-domain">
                    <div className="subdomain-info">
                      {getStatusIcon(subdomain.resolved)}
                      <span className="domain-name">{subdomain.domain}</span>
                    </div>
                  </div>
                  
                  <div className="col-ip">
                    <code>{subdomain.ip || 'N/A'}</code>
                  </div>
                  
                  <div className="col-status">
                    <span className={`status-badge ${subdomain.resolved ? 'resolved' : 'unresolved'}`}>
                      {subdomain.resolved ? 'Resolved' : 'Unresolved'}
                    </span>
                  </div>
                  
                  <div className="col-http">
                    <div className="http-statuses">
                      {getHttpStatusBadge(subdomain.http_status)}
                      {getHttpStatusBadge(subdomain.https_status)}
                    </div>
                  </div>
                  
                  <div className="col-actions">
                    {subdomain.resolved && (
                      <div className="action-buttons">
                        <a 
                          href={`http://${subdomain.domain}`} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="action-link"
                          title="Open HTTP"
                        >
                          HTTP
                        </a>
                        <a 
                          href={`https://${subdomain.domain}`} 
                          target="_blank" 
                          rel="noopener noreferrer"
                          className="action-link"
                          title="Open HTTPS"
                        >
                          HTTPS
                        </a>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="empty-state">
            <p>No subdomains found matching the current filter.</p>
          </div>
        )}
      </div>
      
      {/* DNS Records */}
      {results.dns_records && Object.keys(results.dns_records).length > 0 && (
        <div className="card dns-section">
          <h3>DNS Records</h3>
          <div className="dns-records-grid">
            {Object.entries(results.dns_records).map(([type, records]) => (
              records.length > 0 && (
                <div key={type} className="dns-record-type">
                  <h4>{type} Records</h4>
                  <div className="dns-records-list">
                    {records.map((record, index) => (
                      <code key={index} className="dns-record">{record}</code>
                    ))}
                  </div>
                </div>
              )
            ))}
          </div>
        </div>
      )}
      
      {/* WHOIS Information */}
      {results.whois_info && (
        <div className="card whois-section">
          <h3>WHOIS Information</h3>
          <div className="whois-grid">
            {Object.entries(results.whois_info).map(([key, value]) => (
              <div key={key} className="whois-item">
                <span className="whois-label">{key.replace('_', ' ')}:</span>
                <span className="whois-value">{value}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default SubdomainResults;