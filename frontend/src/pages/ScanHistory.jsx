// frontend/src/pages/ScanHistory.jsx
import React, { useState, useEffect, useCallback } from 'react';
import { 
  FaHistory, 
  FaTrash, 
  FaFilter, 
  FaEye, 
  FaRedo, 
  FaDownload,
  FaUpload,
  FaExclamationTriangle,
  FaBug,
  FaInfoCircle
} from 'react-icons/fa';
import { historyService } from '../services/historyService';
import { useScannerIntegration } from '../hooks/useScannerIntegration';
import HistoryFilter from '../components/history/HistoryFilter';
import HistoryTable from '../components/history/HistoryTable';
import ScanDetail from '../components/history/ScanDetail';
import '../styles/History.css';

const ScanHistory = () => {
  const [history, setHistory] = useState([]);
  const [filteredHistory, setFilteredHistory] = useState([]);
  const [filters, setFilters] = useState({});
  const [selectedScan, setSelectedScan] = useState(null);
  const [showFilters, setShowFilters] = useState(false);
  const [sortBy, setSortBy] = useState('timestamp');
  const [sortOrder, setSortOrder] = useState('desc');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showDebug, setShowDebug] = useState(false);
  const [stats, setStats] = useState(null);

  // Use scanner integration hook for debugging
  const { } = useScannerIntegration();

  // Load history data
  const loadHistory = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      
      console.log('📊 Loading scan history...');
      
      // Get all history
      const data = historyService.getAllHistory();
      console.log(`Found ${data.length} history items`);
      
      // Get statistics
      const historyStats = historyService.getStats();
      setStats(historyStats);
      
      setHistory(data);
      
      // Log summary for debugging
      if (data.length === 0) {
        console.warn('⚠️ No scan history found');
        checkForLegacyData();
      } else {
        console.log('✅ History loaded successfully');
        logHistorySummary(data);
      }
      
    } catch (err) {
      console.error('❌ Error loading history:', err);
      setError('Failed to load scan history: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  // Check for legacy scanner data
  const checkForLegacyData = () => {
    const legacyKeys = [
      'portScanResults',
      'sslScanResults', 
      'webVulnResults',
      'subdomainResults',
      'defacementResults',
      'poisoningResults',
      'dorkingResults',
      'virusTotalResults'
    ];
    
    const foundLegacy = [];
    legacyKeys.forEach(key => {
      const data = localStorage.getItem(key);
      if (data) {
        try {
          const parsed = JSON.parse(data);
          foundLegacy.push({ key, count: Array.isArray(parsed) ? parsed.length : 1 });
        } catch (e) {
          console.warn(`Invalid data in ${key}`);
        }
      }
    });
    
    if (foundLegacy.length > 0) {
      console.log('🔄 Found legacy scanner data:', foundLegacy);
      console.log('💡 Triggering migration...');
      // Trigger migration by reinitializing history service
      historyService.migrateExistingData();
      // Reload after migration
      setTimeout(loadHistory, 1000);
    }
  };

  // Log history summary for debugging
  const logHistorySummary = (data) => {
    const summary = {};
    data.forEach(scan => {
      const type = scan.scannerType || 'unknown';
      summary[type] = (summary[type] || 0) + 1;
    });
    console.log('📈 History summary by scanner type:', summary);
  };

  // Apply filters and sorting
  const applyFiltersAndSort = useCallback(() => {
    try {
      let filtered = historyService.filterHistory(filters, history);
      filtered = historyService.sortHistory(filtered, sortBy, sortOrder);
      
      console.log(`🔍 Applied filters: ${filtered.length}/${history.length} items`);
      setFilteredHistory(filtered);
    } catch (err) {
      console.error('Error applying filters:', err);
      setFilteredHistory(history);
    }
  }, [history, filters, sortBy, sortOrder]);

  // Effects
  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  useEffect(() => {
    applyFiltersAndSort();
  }, [applyFiltersAndSort]);

  // Event handlers
  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this scan?')) {
      try {
        const success = historyService.deleteScan(id);
        if (success) {
          await loadHistory();
          console.log('✅ Scan deleted successfully');
        } else {
          alert('Failed to delete scan');
        }
      } catch (err) {
        console.error('Error deleting scan:', err);
        alert('Failed to delete scan: ' + err.message);
      }
    }
  };

  const handleClearAll = async () => {
    if (window.confirm('Are you sure you want to clear all scan history? This action cannot be undone.')) {
      try {
        const success = historyService.clearHistory();
        if (success) {
          await loadHistory();
          console.log('✅ History cleared successfully');
        } else {
          alert('Failed to clear history');
        }
      } catch (err) {
        console.error('Error clearing history:', err);
        alert('Failed to clear history: ' + err.message);
      }
    }
  };

  const handleViewDetails = (scan) => {
    setSelectedScan(scan);
  };

  const handleCloseDetails = () => {
    setSelectedScan(null);
  };

  const handleSort = (field) => {
    if (sortBy === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortOrder('desc');
    }
  };

  const handleRefresh = () => {
    console.log('🔄 Manual refresh triggered');
    loadHistory();
  };

  const handleExport = () => {
    try {
      historyService.exportHistory();
      console.log('✅ History exported successfully');
    } catch (err) {
      console.error('Error exporting history:', err);
      alert('Failed to export history: ' + err.message);
    }
  };

  const handleImport = (event) => {
    const file = event.target.files[0];
    if (file) {
      historyService.importHistory(file)
        .then(importedCount => {
          console.log(`✅ Imported ${importedCount} scans`);
          loadHistory();
          alert(`Successfully imported ${importedCount} scans`);
        })
        .catch(err => {
          console.error('Error importing history:', err);
          alert('Failed to import history: ' + err.message);
        });
    }
    // Reset file input
    event.target.value = '';
  };

  // Debug functions
  const handleDebugToggle = () => {
    setShowDebug(!showDebug);
  };

  const runDebugCheck = () => {
    console.log('🐛 Running debug check...');
    
    // Check all localStorage
    const allKeys = Object.keys(localStorage);
    const scanKeys = allKeys.filter(key => 
      key.includes('scan') || key.includes('result') || key.includes('history')
    );
    
    console.log('🔍 All scan-related localStorage keys:', scanKeys);
    
    scanKeys.forEach(key => {
      try {
        const data = localStorage.getItem(key);
        const parsed = JSON.parse(data);
        console.log(`📦 ${key}:`, {
          type: Array.isArray(parsed) ? 'Array' : typeof parsed,
          length: Array.isArray(parsed) ? parsed.length : 'N/A',
          sample: Array.isArray(parsed) ? parsed[0] : parsed
        });
      } catch (e) {
        console.warn(`❌ Invalid JSON in ${key}`);
      }
    });
    
    // Force migration check
    historyService.migrateExistingData();
    loadHistory();
  };

  // Render loading state
  if (loading) {
    return (
      <div className="scan-history-page">
        <div className="loading-container">
          <div className="loading-spinner"></div>
          <p>Loading scan history...</p>
        </div>
      </div>
    );
  }

  // Render error state
  if (error) {
    return (
      <div className="scan-history-page">
        <div className="error-container">
          <FaExclamationTriangle className="error-icon" />
          <h3>Error Loading History</h3>
          <p>{error}</p>
          <div className="error-actions">
            <button className="btn btn-primary" onClick={handleRefresh}>
              <FaRedo /> Try Again
            </button>
            <button className="btn btn-outline" onClick={runDebugCheck}>
              <FaBug /> Debug Check
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="scan-history-page">
      {/* Header */}
      <div className="history-header">
        <div className="header-content">
          <div className="header-title">
            <h1><FaHistory /> Scan History</h1>
            {stats && (
              <div className="header-stats">
                <div className="stat-item">
                  <span className="stat-label">Total:</span>
                  <span className="stat-value">{stats.total}</span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">Recent (24h):</span>
                  <span className="stat-value">{stats.recentScans}</span>
                </div>
                <div className="stat-item">
                  <span className="stat-label">Vulnerabilities:</span>
                  <span className="stat-value">{stats.totalVulnerabilities}</span>
                </div>
              </div>
            )}
          </div>
          
          <div className="header-actions">
            <button
              className="btn btn-outline btn-sm"
              onClick={handleRefresh}
              title="Refresh history"
            >
              <FaRedo />
            </button>
            
            <button
              className="btn btn-secondary"
              onClick={() => setShowFilters(!showFilters)}
            >
              <FaFilter /> {showFilters ? 'Hide' : 'Show'} Filters
            </button>
            
            <button
              className="btn btn-outline"
              onClick={handleExport}
              title="Export history"
            >
              <FaDownload /> Export
            </button>
            
            <label className="btn btn-outline file-input-label">
              <FaUpload /> Import
              <input
                type="file"
                accept=".json"
                onChange={handleImport}
                style={{ display: 'none' }}
              />
            </label>
            
            <button
              className="btn btn-outline btn-sm"
              onClick={handleDebugToggle}
              title="Toggle debug info"
            >
              <FaBug />
            </button>
            
            {history.length > 0 && (
              <button
                className="btn btn-danger"
                onClick={handleClearAll}
              >
                <FaTrash /> Clear All
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Debug Panel */}
      {showDebug && (
        <div className="debug-panel">
          <div className="debug-header">
            <h3><FaBug /> Debug Information</h3>
            <button className="btn btn-sm btn-outline" onClick={runDebugCheck}>
              Run Full Check
            </button>
          </div>
          
          <div className="debug-content">
            <div className="debug-stats">
              <div className="debug-stat">
                <strong>Total History:</strong> {history.length}
              </div>
              <div className="debug-stat">
                <strong>Filtered:</strong> {filteredHistory.length}
              </div>
              <div className="debug-stat">
                <strong>Active Filters:</strong> {Object.keys(filters).length}
              </div>
              <div className="debug-stat">
                <strong>Sort:</strong> {sortBy} ({sortOrder})
              </div>
            </div>
            
            {stats && (
              <div className="debug-scanner-stats">
                <strong>By Scanner Type:</strong>
                <ul>
                  {Object.entries(stats.byScanner).map(([type, count]) => (
                    <li key={type}>{type}: {count}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Filters */}
      {showFilters && (
        <HistoryFilter
          onFilterChange={setFilters}
          currentFilters={filters}
          scannerStats={stats?.byScanner || {}}
        />
      )}

      {/* Content */}
      {filteredHistory.length === 0 ? (
        <div className="empty-state">
          <FaHistory className="empty-icon" />
          <h3>No scan history found</h3>
          
          {history.length === 0 ? (
            <div className="empty-content">
              <p>You haven't performed any scans yet.</p>
              <div className="empty-actions">
                <button className="btn btn-primary" onClick={() => window.location.href = '/new-scan'}>
                  Start Your First Scan
                </button>
                <button className="btn btn-outline" onClick={runDebugCheck}>
                  <FaInfoCircle /> Check for Data
                </button>
              </div>
            </div>
          ) : (
            <div className="empty-content">
              <p>No scans match your current filters.</p>
              <p><strong>{history.length}</strong> total scans available.</p>
              <button 
                className="btn btn-outline" 
                onClick={() => setFilters({})}
              >
                Clear Filters
              </button>
            </div>
          )}
        </div>
      ) : (
        <HistoryTable
          history={filteredHistory}
          onDelete={handleDelete}
          onViewDetails={handleViewDetails}
          onSort={handleSort}
          sortBy={sortBy}
          sortOrder={sortOrder}
        />
      )}

      {/* Scan Detail Modal */}
      {selectedScan && (
        <ScanDetail
          scan={selectedScan}
          onClose={handleCloseDetails}
        />
      )}
    </div>
  );
};

export default ScanHistory;