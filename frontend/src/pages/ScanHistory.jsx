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
  FaInfoCircle,
  FaSearch,
  FaTimes,
  FaChartLine,
  FaClock,
  FaShieldAlt,
  FaGlobe
} from 'react-icons/fa';
import { historyService } from '../services/historyService';
import '../styles/History.css';

const ScanHistory = () => {
  const [history, setHistory] = useState([]);
  const [filteredHistory, setFilteredHistory] = useState([]);
  const [filters, setFilters] = useState({
    search: '',
    scannerType: '',
    status: '',
    dateFrom: '',
    dateTo: ''
  });
  const [selectedScan, setSelectedScan] = useState(null);
  const [showFilters, setShowFilters] = useState(false);
  const [sortBy, setSortBy] = useState('timestamp');
  const [sortOrder, setSortOrder] = useState('desc');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showDebug, setShowDebug] = useState(false);
  const [stats, setStats] = useState(null);

  // Load history data
  const loadHistory = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      
      console.log('📊 Loading scan history...');
      
      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 500));
      
      // Get all history
      const data = historyService.getAllHistory();
      console.log(`Found ${data.length} history items`);
      
      // Calculate statistics
      const historyStats = calculateStats(data);
      setStats(historyStats);
      
      setHistory(data);
      
      if (data.length === 0) {
        console.warn('⚠️ No scan history found');
        // Generate mock data for demo
        generateMockData();
      } else {
        console.log('✅ History loaded successfully');
      }
      
    } catch (err) {
      console.error('❌ Error loading history:', err);
      setError('Failed to load scan history: ' + err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  // Generate mock data for demonstration
  const generateMockData = () => {
    const mockData = [
      {
        id: Date.now() + 1,
        target: 'example.com',
        scannerType: 'port-scanner',
        status: 'completed',
        timestamp: new Date(Date.now() - 1000 * 60 * 30).toISOString(), // 30 minutes ago
        duration: '2m 15s',
        vulnerabilitiesFound: 3,
        results: { openPorts: [80, 443, 22], totalPorts: 1000 }
      },
      {
        id: Date.now() + 2,
        target: 'api.example.com',
        scannerType: 'ssl-scanner',
        status: 'completed',
        timestamp: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(), // 2 hours ago
        duration: '45s',
        vulnerabilitiesFound: 1,
        results: { certificateValid: false, weakCiphers: true }
      },
      {
        id: Date.now() + 3,
        target: 'shop.example.com',
        scannerType: 'web-vulnerability',
        status: 'completed',
        timestamp: new Date(Date.now() - 1000 * 60 * 60 * 6).toISOString(), // 6 hours ago
        duration: '8m 32s',
        vulnerabilitiesFound: 5,
        results: { xss: 2, sqli: 1, csrf: 2 }
      },
      {
        id: Date.now() + 4,
        target: 'blog.example.com',
        scannerType: 'subdomain-scanner',
        status: 'failed',
        timestamp: new Date(Date.now() - 1000 * 60 * 60 * 12).toISOString(), // 12 hours ago
        duration: '1m 23s',
        vulnerabilitiesFound: 0,
        error: 'Connection timeout'
      },
      {
        id: Date.now() + 5,
        target: 'test.example.com',
        scannerType: 'defacement-scanner',
        status: 'running',
        timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(), // 5 minutes ago
        duration: '5m 12s',
        vulnerabilitiesFound: 0,
        results: null
      }
    ];

    setHistory(mockData);
    const mockStats = calculateStats(mockData);
    setStats(mockStats);
  };

  // Calculate statistics
  const calculateStats = (data) => {
    const now = Date.now();
    const oneDayAgo = now - (24 * 60 * 60 * 1000);
    
    const recentScans = data.filter(scan => 
      scan.timestamp && new Date(scan.timestamp).getTime() > oneDayAgo
    ).length;
    
    const totalVulnerabilities = data.reduce((sum, scan) => 
      sum + (scan.vulnerabilitiesFound || 0), 0
    );
    
    const byScanner = {};
    const byStatus = {};
    
    data.forEach(scan => {
      const type = scan.scannerType || 'unknown';
      const status = scan.status || 'unknown';
      
      byScanner[type] = (byScanner[type] || 0) + 1;
      byStatus[status] = (byStatus[status] || 0) + 1;
    });

    return {
      total: data.length,
      recentScans,
      totalVulnerabilities,
      byScanner,
      byStatus
    };
  };

  // Apply filters and sorting
  const applyFiltersAndSort = useCallback(() => {
    let filtered = [...history];

    // Apply search filter
    if (filters.search) {
      filtered = filtered.filter(scan =>
        (scan.target || '').toLowerCase().includes(filters.search.toLowerCase()) ||
        (scan.scannerType || '').toLowerCase().includes(filters.search.toLowerCase())
      );
    }

    // Apply scanner type filter
    if (filters.scannerType) {
      filtered = filtered.filter(scan => (scan.scannerType || '') === filters.scannerType);
    }

    // Apply status filter
    if (filters.status) {
      filtered = filtered.filter(scan => (scan.status || '') === filters.status);
    }

    // Apply date filters
    if (filters.dateFrom) {
      filtered = filtered.filter(scan =>
        scan.timestamp && new Date(scan.timestamp) >= new Date(filters.dateFrom)
      );
    }

    if (filters.dateTo) {
      filtered = filtered.filter(scan =>
        scan.timestamp && new Date(scan.timestamp) <= new Date(filters.dateTo)
      );
    }

    // Apply sorting
    filtered.sort((a, b) => {
      let aValue = a[sortBy];
      let bValue = b[sortBy];

      if (sortBy === 'timestamp') {
        aValue = aValue ? new Date(aValue).getTime() : 0;
        bValue = bValue ? new Date(bValue).getTime() : 0;
      }

      if (sortOrder === 'asc') {
        return aValue > bValue ? 1 : -1;
      } else {
        return aValue < bValue ? 1 : -1;
      }
    });

    setFilteredHistory(filtered);
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
      const updatedHistory = history.filter(scan => scan.id !== id);
      setHistory(updatedHistory);
      console.log('✅ Scan deleted successfully');
    }
  };

  const handleClearAll = async () => {
    if (window.confirm('Are you sure you want to clear all scan history? This action cannot be undone.')) {
      setHistory([]);
      setStats(calculateStats([]));
      console.log('✅ History cleared successfully');
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

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const clearFilters = () => {
    setFilters({
      search: '',
      scannerType: '',
      status: '',
      dateFrom: '',
      dateTo: ''
    });
  };

  const getScannerIcon = (type) => {
    const icons = {
      'port-scanner': FaShieldAlt,
      'ssl-scanner': FaGlobe,
      'web-vulnerability': FaExclamationTriangle,
      'subdomain-scanner': FaSearch,
      'defacement-scanner': FaEye,
      'google-dorking': FaSearch,
      'virustotal': FaBug
    };
    return icons[type] || FaInfoCircle;
  };

  const getStatusBadge = (status) => {
    const badges = {
      completed: 'badge-success',
      running: 'badge-warning',
      failed: 'badge-danger',
      cancelled: 'badge-secondary'
    };
    return badges[status] || 'badge-secondary';
  };

  const formatTimestamp = (timestamp) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
    const diffDays = Math.floor(diffHours / 24);

    if (diffHours < 1) {
      const diffMins = Math.floor(diffMs / (1000 * 60));
      return `${diffMins}m ago`;
    } else if (diffHours < 24) {
      return `${diffHours}h ago`;
    } else if (diffDays < 7) {
      return `${diffDays}d ago`;
    } else {
      return date.toLocaleDateString();
    }
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
            <button className="btn btn-primary" onClick={loadHistory}>
              <FaRedo /> Try Again
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
                  <FaChartLine />
                  <div className="stat-content">
                    <span className="stat-label">Total Scans</span>
                    <span className="stat-value">{stats.total}</span>
                  </div>
                </div>
                <div className="stat-item">
                  <FaClock />
                  <div className="stat-content">
                    <span className="stat-label">Recent (24h)</span>
                    <span className="stat-value">{stats.recentScans}</span>
                  </div>
                </div>
                <div className="stat-item">
                  <FaExclamationTriangle />
                  <div className="stat-content">
                    <span className="stat-label">Vulnerabilities</span>
                    <span className="stat-value">{stats.totalVulnerabilities}</span>
                  </div>
                </div>
              </div>
            )}
          </div>
          
          <div className="header-actions">
            <button
              className="btn btn-outline btn-sm"
              onClick={loadHistory}
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
              className="btn btn-outline btn-sm"
              onClick={() => setShowDebug(!showDebug)}
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
        <div className="history-filter">
          <div className="filter-grid">
            <div className="filter-item">
              <label>Search</label>
              <div className="search-input">
                <FaSearch />
                <input
                  type="text"
                  className="form-input"
                  placeholder="Search targets or scanner types..."
                  value={filters.search}
                  onChange={(e) => handleFilterChange('search', e.target.value)}
                />
              </div>
            </div>
            
            <div className="filter-item">
              <label>Scanner Type</label>
              <select
                className="form-select"
                value={filters.scannerType}
                onChange={(e) => handleFilterChange('scannerType', e.target.value)}
              >
                <option value="">All Types</option>
                <option value="port-scanner">Port Scanner</option>
                <option value="ssl-scanner">SSL Scanner</option>
                <option value="web-vulnerability">Web Vulnerability</option>
                <option value="subdomain-scanner">Subdomain Scanner</option>
                <option value="defacement-scanner">Defacement Scanner</option>
              </select>
            </div>
            
            <div className="filter-item">
              <label>Status</label>
              <select
                className="form-select"
                value={filters.status}
                onChange={(e) => handleFilterChange('status', e.target.value)}
              >
                <option value="">All Status</option>
                <option value="completed">Completed</option>
                <option value="running">Running</option>
                <option value="failed">Failed</option>
                <option value="cancelled">Cancelled</option>
              </select>
            </div>
            
            <div className="filter-item">
              <label>Date From</label>
              <input
                type="date"
                className="form-input"
                value={filters.dateFrom}
                onChange={(e) => handleFilterChange('dateFrom', e.target.value)}
              />
            </div>
            
            <div className="filter-item">
              <label>Date To</label>
              <input
                type="date"
                className="form-input"
                value={filters.dateTo}
                onChange={(e) => handleFilterChange('dateTo', e.target.value)}
              />
            </div>
            
            <div className="filter-actions">
              <button className="btn btn-outline" onClick={clearFilters}>
                <FaTimes /> Clear
              </button>
            </div>
          </div>
        </div>
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
              </div>
            </div>
          ) : (
            <div className="empty-content">
              <p>No scans match your current filters.</p>
              <p><strong>{history.length}</strong> total scans available.</p>
              <button className="btn btn-outline" onClick={clearFilters}>
                Clear Filters
              </button>
            </div>
          )}
        </div>
      ) : (
        <div className="history-table-container">
          <table className="history-table">
            <thead>
              <tr>
                <th className={`sortable ${sortBy === 'target' ? 'active' : ''} ${sortBy === 'target' && sortOrder === 'desc' ? 'desc' : ''}`}
                    onClick={() => handleSort('target')}>
                  Target
                </th>
                <th className={`sortable ${sortBy === 'scannerType' ? 'active' : ''} ${sortBy === 'scannerType' && sortOrder === 'desc' ? 'desc' : ''}`}
                    onClick={() => handleSort('scannerType')}>
                  Scanner Type
                </th>
                <th className={`sortable ${sortBy === 'status' ? 'active' : ''} ${sortBy === 'status' && sortOrder === 'desc' ? 'desc' : ''}`}
                    onClick={() => handleSort('status')}>
                  Status
                </th>
                <th className={`sortable ${sortBy === 'timestamp' ? 'active' : ''} ${sortBy === 'timestamp' && sortOrder === 'desc' ? 'desc' : ''}`}
                    onClick={() => handleSort('timestamp')}>
                  Time
                </th>
                <th>Duration</th>
                <th>Vulnerabilities</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredHistory.map((scan) => {
                const ScannerIcon = getScannerIcon(scan.scannerType || 'unknown');
                return (
                  <tr key={scan.id}>
                    <td>
                      <span className="target-cell">{scan.target || 'N/A'}</span>
                    </td>
                    <td>
                      <div className="scanner-type-cell">
                        <ScannerIcon />
                        <span>{(scan.scannerType || 'unknown').replace('-', ' ')}</span>
                      </div>
                    </td>
                    <td>
                      <span className={`badge ${getStatusBadge(scan.status || 'unknown')}`}>
                        {scan.status || 'unknown'}
                      </span>
                    </td>
                    <td className="timestamp-cell">
                      {scan.timestamp ? formatTimestamp(scan.timestamp) : 'N/A'}
                    </td>
                    <td className="duration-cell">
                      {scan.duration || 'N/A'}
                    </td>
                    <td>
                      <span className={scan.vulnerabilitiesFound > 0 ? 'vulnerabilities-found' : 'vulnerabilities-none'}>
                        {scan.vulnerabilitiesFound || 0}
                      </span>
                    </td>
                    <td>
                      <div className="actions-cell">
                        <button
                          className="btn-icon"
                          onClick={() => handleViewDetails(scan)}
                          title="View Details"
                        >
                          <FaEye />
                        </button>
                        <button
                          className="btn-icon btn-danger"
                          onClick={() => handleDelete(scan.id)}
                          title="Delete"
                        >
                          <FaTrash />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Scan Detail Modal */}
      {selectedScan && (
        <div className="modal-overlay" onClick={handleCloseDetails}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h2>Scan Details - {selectedScan.target}</h2>
              <button className="close-button" onClick={handleCloseDetails}>
                ×
              </button>
            </div>
            
            <div className="modal-body">
              <div className="scan-summary">
                <div className="summary-item">
                  <label>Target</label>
                  <div className="value">{selectedScan.target}</div>
                </div>
                <div className="summary-item">
                  <label>Scanner Type</label>
                  <div className="value">{selectedScan.scannerType}</div>
                </div>
                <div className="summary-item">
                  <label>Status</label>
                  <div className="value">
                    <span className={`badge ${getStatusBadge(selectedScan.status)}`}>
                      {selectedScan.status}
                    </span>
                  </div>
                </div>
                <div className="summary-item">
                  <label>Duration</label>
                  <div className="value">{selectedScan.duration}</div>
                </div>
                <div className="summary-item">
                  <label>Vulnerabilities Found</label>
                  <div className="value">{selectedScan.vulnerabilitiesFound || 0}</div>
                </div>
                <div className="summary-item">
                  <label>Timestamp</label>
                  <div className="value">{new Date(selectedScan.timestamp).toLocaleString()}</div>
                </div>
              </div>
              
              {selectedScan.results && (
                <div className="scan-results-section">
                  <h3>Scan Results</h3>
                  <pre>{JSON.stringify(selectedScan.results, null, 2)}</pre>
                </div>
              )}
              
              {selectedScan.error && (
                <div className="scan-error-section">
                  <h3>Error Details</h3>
                  <div className="error-message">{selectedScan.error}</div>
                </div>
              )}
            </div>
            
            <div className="modal-footer">
              <button className="btn btn-outline" onClick={handleCloseDetails}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ScanHistory;