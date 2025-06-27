// frontend/src/components/scanners/DefacementResults.jsx
import React, { useState } from 'react';
import { 
  FaCheckCircle, 
  FaExclamationTriangle,
  FaTimesCircle,
  FaEye,
  FaCode,
  FaDownload,
  FaExpand,
  FaImage,
  FaClock,
  FaPercentage
} from 'react-icons/fa';

const DefacementResults = ({ results }) => {
  const [activeTab, setActiveTab] = useState('overview');
  const [showFullScreenshot, setShowFullScreenshot] = useState(false);
  const [selectedImage, setSelectedImage] = useState(null);
  
  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return '#dc2626';
      case 'high': return '#ea580c';
      case 'medium': return '#d97706';
      case 'low': return '#65a30d';
      default: return '#6b7280';
    }
  };
  
  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical': return <FaTimesCircle style={{ color: getSeverityColor(severity) }} />;
      case 'high': return <FaExclamationTriangle style={{ color: getSeverityColor(severity) }} />;
      case 'medium': return <FaExclamationTriangle style={{ color: getSeverityColor(severity) }} />;
      case 'low': return <FaCheckCircle style={{ color: getSeverityColor(severity) }} />;
      default: return <FaCheckCircle style={{ color: getSeverityColor(severity) }} />;
    }
  };
  
  const getStatusText = (changeDetected, severity) => {
    if (!changeDetected) return 'No Changes Detected';
    
    switch (severity) {
      case 'critical': return 'Critical Changes Detected';
      case 'high': return 'High Risk Changes';
      case 'medium': return 'Moderate Changes';
      case 'low': return 'Minor Changes';
      default: return 'Changes Detected';
    }
  };
  
  const openImageModal = (imageSrc, title) => {
    setSelectedImage({ src: imageSrc, title });
    setShowFullScreenshot(true);
  };
  
  const exportReport = () => {
    const reportData = {
      timestamp: results.timestamp,
      url: results.url,
      status: getStatusText(results.change_detected, results.severity),
      severity: results.severity,
      alerts: results.alerts,
      screenshot_comparison: results.screenshot_comparison,
      html_comparison: results.html_comparison
    };
    
    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `defacement_report_${new Date(results.timestamp).toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };
  
  return (
    <div className="defacement-results">
      {/* Summary Header */}
      <div className="card result-summary">
        <div className="summary-header">
          <div className="status-indicator">
            {getSeverityIcon(results.severity)}
            <div className="status-text">
              <h3>{getStatusText(results.change_detected, results.severity)}</h3>
              <p>Scan completed at {new Date(results.timestamp).toLocaleString()}</p>
            </div>
          </div>
          <button onClick={exportReport} className="btn btn-secondary btn-sm">
            <FaDownload /> Export Report
          </button>
        </div>
        
        <div className="summary-grid">
          <div className="summary-item">
            <div className="summary-icon">
              <FaEye />
            </div>
            <div className="summary-content">
              <span className="summary-value">
                {results.screenshot_comparison?.change_percentage || 0}%
              </span>
              <span className="summary-label">Visual Changes</span>
            </div>
          </div>
          
          <div className="summary-item">
            <div className="summary-icon">
              <FaCode />
            </div>
            <div className="summary-content">
              <span className="summary-value">
                {results.html_comparison?.change_percentage || 0}%
              </span>
              <span className="summary-label">Content Changes</span>
            </div>
          </div>
          
          <div className="summary-item">
            <div className="summary-icon">
              <FaExclamationTriangle />
            </div>
            <div className="summary-content">
              <span className="summary-value">
                {results.alerts?.length || 0}
              </span>
              <span className="summary-label">Alerts</span>
            </div>
          </div>
          
          <div className="summary-item">
            <div className="summary-icon">
              <FaClock />
            </div>
            <div className="summary-content">
              <span className="summary-value">
                {results.html_comparison?.suspicious_keywords?.length || 0}
              </span>
              <span className="summary-label">Suspicious Keywords</span>
            </div>
          </div>
        </div>
      </div>
      
      {/* Alerts Section */}
      {results.alerts && results.alerts.length > 0 && (
        <div className="card alerts-section">
          <h3>🚨 Detected Alerts</h3>
          <div className="alerts-list">
            {results.alerts.map((alert, index) => (
              <div key={index} className={`alert-item ${alert.severity}`}>
                <div className="alert-icon">
                  {getSeverityIcon(alert.severity)}
                </div>
                <div className="alert-content">
                  <div className="alert-type">{alert.type.replace('_', ' ').toUpperCase()}</div>
                  <div className="alert-message">{alert.message}</div>
                </div>
                <div className="alert-severity">
                  <span className={`severity-badge ${alert.severity}`}>
                    {alert.severity.toUpperCase()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      
      {/* Tabs Navigation */}
      <div className="card">
        <div className="tabs-container">
          <div className="tabs-nav">
            <button 
              className={`tab-button ${activeTab === 'overview' ? 'active' : ''}`}
              onClick={() => setActiveTab('overview')}
            >
              <FaEye /> Visual Comparison
            </button>
            <button 
              className={`tab-button ${activeTab === 'content' ? 'active' : ''}`}
              onClick={() => setActiveTab('content')}
            >
              <FaCode /> Content Analysis
            </button>
          </div>
          
          <div className="tab-content">
            {/* Visual Comparison Tab */}
            {activeTab === 'overview' && (
              <div className="visual-comparison">
                {results.screenshot_comparison && (
                  <>
                    <div className="comparison-header">
                      <h4>Screenshot Comparison</h4>
                      <div className="comparison-stats">
                        <span className="stat">
                          <FaPercentage />
                          {results.screenshot_comparison.change_percentage}% Changed
                        </span>
                        <span className="stat">
                          <FaImage />
                          {results.screenshot_comparison.changed_pixels?.toLocaleString()} pixels modified
                        </span>
                      </div>
                    </div>
                    
                    <div className="screenshots-grid">
                      <div className="screenshot-container">
                        <h5>Previous Version</h5>
                        <div 
                          className="screenshot-wrapper"
                          onClick={() => openImageModal('/api/screenshots/previous.png', 'Previous Version')}
                        >
                          <img 
                            src="/api/screenshots/previous.png" 
                            alt="Previous version"
                            className="screenshot-image"
                          />
                          <div className="screenshot-overlay">
                            <FaExpand />
                          </div>
                        </div>
                      </div>
                      
                      <div className="screenshot-container">
                        <h5>Current Version</h5>
                        <div 
                          className="screenshot-wrapper"
                          onClick={() => openImageModal('/api/screenshots/current.png', 'Current Version')}
                        >
                          <img 
                            src="/api/screenshots/current.png" 
                            alt="Current version"
                            className="screenshot-image"
                          />
                          <div className="screenshot-overlay">
                            <FaExpand />
                          </div>
                        </div>
                      </div>
                      
                      {results.screenshot_comparison.diff_image && (
                        <div className="screenshot-container">
                          <h5>Difference Highlight</h5>
                          <div 
                            className="screenshot-wrapper"
                            onClick={() => openImageModal('/api/screenshots/diff.png', 'Difference Highlight')}
                          >
                            <img 
                              src="/api/screenshots/diff.png" 
                              alt="Difference highlight"
                              className="screenshot-image"
                            />
                            <div className="screenshot-overlay">
                              <FaExpand />
                            </div>
                          </div>
                        </div>
                      )}
                    </div>
                  </>
                )}
                
                {(!results.screenshot_comparison || results.screenshot_comparison.change_percentage === 0) && (
                  <div className="no-changes">
                    <FaCheckCircle />
                    <h4>No Visual Changes Detected</h4>
                    <p>The website appears identical to the previous scan.</p>
                  </div>
                )}
              </div>
            )}
            
            {/* Content Analysis Tab */}
            {activeTab === 'content' && (
              <div className="content-analysis">
                {results.html_comparison && (
                  <>
                    <div className="analysis-header">
                      <h4>HTML Content Analysis</h4>
                      <div className="analysis-stats">
                        <div className="stat-item">
                          <span className="stat-label">Content Similarity</span>
                          <span className="stat-value">
                            {results.html_comparison.similarity_percentage}%
                          </span>
                        </div>
                        <div className="stat-item">
                          <span className="stat-label">File Size Change</span>
                          <span className="stat-value">
                            {results.html_comparison.html2_size - results.html_comparison.html1_size} bytes
                          </span>
                        </div>
                      </div>
                    </div>
                    
                    {/* Suspicious Keywords */}
                    {results.html_comparison.suspicious_keywords && results.html_comparison.suspicious_keywords.length > 0 && (
                      <div className="keywords-section">
                        <h5>🚨 Suspicious Keywords Detected</h5>
                        <div className="keywords-list">
                          {results.html_comparison.suspicious_keywords.map((keyword, index) => (
                            <span key={index} className="keyword-tag critical">
                              {keyword}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    
                    {/* Content Changes */}
                    <div className="content-changes">
                      <h5>Content Modifications</h5>
                      <div className="change-metrics">
                        <div className="metric">
                          <span className="metric-label">Overall Change</span>
                          <div className="metric-bar">
                            <div 
                              className="metric-fill"
                              style={{ 
                                width: `${results.html_comparison.change_percentage}%`,
                                backgroundColor: results.html_comparison.change_percentage > 15 ? '#dc2626' : 
                                               results.html_comparison.change_percentage > 5 ? '#d97706' : '#65a30d'
                              }}
                            ></div>
                          </div>
                          <span className="metric-value">{results.html_comparison.change_percentage}%</span>
                        </div>
                      </div>
                    </div>
                  </>
                )}
                
                {(!results.html_comparison || results.html_comparison.change_percentage === 0) && (
                  <div className="no-changes">
                    <FaCheckCircle />
                    <h4>No Content Changes Detected</h4>
                    <p>The HTML content is identical to the previous scan.</p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
      
      {/* Full Screen Screenshot Modal */}
      {showFullScreenshot && selectedImage && (
        <div className="screenshot-modal" onClick={() => setShowFullScreenshot(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{selectedImage.title}</h3>
              <button 
                className="modal-close"
                onClick={() => setShowFullScreenshot(false)}
              >
                ×
              </button>
            </div>
            <div className="modal-body">
              <img src={selectedImage.src} alt={selectedImage.title} />
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DefacementResults;