// frontend/src/components/history/ScanDetail.jsx
import React from 'react';
import { FaTimes, FaDownload, FaRedo } from 'react-icons/fa';
import { useNavigate } from 'react-router-dom';

const ScanDetail = ({ scan, onClose }) => {
  const navigate = useNavigate();

  const handleRerun = () => {
    // Navigate to scan page with pre-filled data
    navigate('/scan', { 
      state: { 
        scanType: scan.scanType, 
        target: scan.target,
        options: scan.scanOptions 
      } 
    });
    onClose();
  };

  const handleExport = (format) => {
    // Export functionality would go here
    console.log(`Exporting scan ${scan.id} as ${format}`);
  };

  const renderResults = () => {
    // Reuse existing result components based on scan type
    switch (scan.scanType) {
      case 'port':
        // Render port scan results
        return (
          <div className="scan-results">
            {/* Use existing port scan result rendering logic */}
            <pre>{JSON.stringify(scan.results, null, 2)}</pre>
          </div>
        );
      case 'ssl':
        // Render SSL scan results (to be implemented)
        return (
          <div className="scan-results">
            {/* SSL results will go here */}
            <pre>{JSON.stringify(scan.results, null, 2)}</pre>
          </div>
        );
      default:
        return <pre>{JSON.stringify(scan.results, null, 2)}</pre>;
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content scan-detail">
        <div className="modal-header">
          <h2>Scan Details</h2>
          <button className="close-button" onClick={onClose}>
            <FaTimes />
          </button>
        </div>
        
        <div className="modal-body">
          <div className="scan-summary">
            <div className="summary-item">
              <label>Target:</label>
              <span>{scan.target}</span>
            </div>
            <div className="summary-item">
              <label>Type:</label>
              <span>{scan.scanType}</span>
            </div>
            <div className="summary-item">
              <label>Date:</label>
              <span>{new Date(scan.timestamp).toLocaleString()}</span>
            </div>
            <div className="summary-item">
              <label>Status:</label>
              <span className={`badge badge-${scan.status}`}>
                {scan.status}
              </span>
            </div>
            <div className="summary-item">
              <label>Duration:</label>
              <span>{scan.duration || '-'}</span>
            </div>
          </div>
          
          <div className="scan-options-summary">
            <h3>Scan Options</h3>
            <pre>{JSON.stringify(scan.scanOptions, null, 2)}</pre>
          </div>
          
          <div className="scan-results-section">
            <h3>Results</h3>
            {renderResults()}
          </div>
        </div>
        
        <div className="modal-footer">
          <button 
            className="btn btn-secondary"
            onClick={() => handleExport('json')}
          >
            <FaDownload /> Export JSON
          </button>
          <button 
            className="btn btn-secondary"
            onClick={() => handleExport('pdf')}
          >
            <FaDownload /> Export PDF
          </button>
          <button 
            className="btn btn-primary"
            onClick={handleRerun}
          >
            <FaRedo /> Re-run Scan
          </button>
        </div>
      </div>
    </div>
  );
};

export default ScanDetail;