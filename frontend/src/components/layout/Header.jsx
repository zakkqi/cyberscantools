// frontend/src/components/layout/Header.jsx
import React from 'react';
import { useSelector } from 'react-redux';
import { Link } from 'react-router-dom';

const Header = () => {
  const { scanInProgress, activeScanId, scans } = useSelector(state => state.scan);
  
  return (
    <header className="app-header">
      <div className="logo">
        <Link to="/">CyberScan Tools</Link>
      </div>
      
      {scanInProgress && (
        <div className="scan-indicator">
          <div className="scan-pulse"></div>
          <div className="scan-info">
            <span>Scanning: {scans[activeScanId]?.target}</span>
            <span>{Math.round(scans[activeScanId]?.progress || 0)}%</span>
            <Link to={`/scan/results/${activeScanId}`}>View</Link>
          </div>
        </div>
      )}
      
      <nav>
        {/* Navigation links */}
      </nav>
    </header>
  );
};

export default Header;