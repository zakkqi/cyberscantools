// frontend/src/components/Dashboard.js - Page Component Version
import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSelector } from 'react-redux';
import { 
  FaShieldAlt, 
  FaExclamationTriangle, 
  FaCheckCircle, 
  FaChartLine,
  FaServer,
  FaGlobe,
  FaLock,
  FaSearch,
  FaRocket,
  FaHistory,
  FaUsers,
  FaClock,
  FaEye,
  FaDownload,
  FaSyncAlt
} from 'react-icons/fa';
import { historyService } from '../services/historyService';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';

const Dashboard = () => {
  const navigate = useNavigate();
  const { user } = useSelector(state => state.auth);
  
  const [dashboardData, setDashboardData] = useState({
    totalScans: 0,
    highRisk: 0,
    mediumRisk: 0,
    lowRisk: 0,
    scanTrends: [],
    scannerBreakdown: [],
    recentScans: [],
    systemHealth: {},
    vulnerabilityTrends: []
  });
  
  const [timeRange] = useState(14); // 14 days
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState(new Date());
  const [autoRefresh, setAutoRefresh] = useState(true);

  // Colors for charts
  const COLORS = {
    high: '#dc3545',
    medium: '#fd7e14',
    low: '#ffc107',
    success: '#28a745',
    primary: '#007bff',
    info: '#17a2b8'
  };

  const PIE_COLORS = ['#007bff', '#28a745', '#dc3545', '#fd7e14', '#6f42c1', '#20c997', '#ffc107'];

  // Memoized data calculations
  const calculateMetrics = useCallback((scans) => {
    let highRisk = 0;
    let mediumRisk = 0;
    let lowRisk = 0;

    scans.forEach(scan => {
      const summary = scan.summary || {};
      highRisk += summary.high_severity || 0;
      mediumRisk += summary.medium_severity || 0;
      lowRisk += summary.low_severity || 0;
    });

    return { highRisk, mediumRisk, lowRisk };
  }, []);

  const calculateTrends = useCallback((scans) => {
    const dailyScans = {};
    
    // Initialize last 14 days
    for (let i = timeRange - 1; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      dailyScans[dateStr] = {
        date: dateStr,
        scans: 0,
        successful: 0,
        failed: 0,
        vulnerabilities: 0
      };
    }

    // Populate with actual data
    scans.forEach(scan => {
      const scanDate = new Date(scan.timestamp).toISOString().split('T')[0];
      if (dailyScans[scanDate]) {
        dailyScans[scanDate].scans++;
        if (scan.status === 'completed') {
          dailyScans[scanDate].successful++;
        } else {
          dailyScans[scanDate].failed++;
        }
        
        const summary = scan.summary || {};
        dailyScans[scanDate].vulnerabilities += 
          (summary.high_severity || 0) + 
          (summary.medium_severity || 0) + 
          (summary.low_severity || 0);
      }
    });

    return Object.values(dailyScans);
  }, [timeRange]);

  const calculateScannerBreakdown = useCallback((scans) => {
    const scannerMap = {};
    
    scans.forEach(scan => {
      const scanner = scan.scannerType || 'Unknown';
      if (!scannerMap[scanner]) {
        scannerMap[scanner] = {
          name: formatScannerName(scanner),
          count: 0,
          successful: 0,
          failed: 0
        };
      }
      
      scannerMap[scanner].count++;
      if (scan.status === 'completed') {
        scannerMap[scanner].successful++;
      } else {
        scannerMap[scanner].failed++;
      }
    });

    return Object.values(scannerMap);
  }, []);

  const calculateVulnerabilityTrends = useCallback((scans) => {
    const vulnTrends = {};
    
    // Initialize last 14 days
    for (let i = timeRange - 1; i >= 0; i--) {
      const date = new Date();
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      vulnTrends[dateStr] = {
        date: dateStr,
        high: 0,
        medium: 0,
        low: 0
      };
    }

    scans.forEach(scan => {
      const scanDate = new Date(scan.timestamp).toISOString().split('T')[0];
      if (vulnTrends[scanDate]) {
        const summary = scan.summary || {};
        vulnTrends[scanDate].high += summary.high_severity || 0;
        vulnTrends[scanDate].medium += summary.medium_severity || 0;
        vulnTrends[scanDate].low += summary.low_severity || 0;
      }
    });

    return Object.values(vulnTrends);
  }, [timeRange]);

  const calculateSystemHealth = useCallback((scans) => {
    const total = scans.length;
    const successful = scans.filter(s => s.status === 'completed').length;
    const failed = scans.filter(s => s.status === 'failed').length;
    
    return {
      successRate: total > 0 ? Math.round((successful / total) * 100) : 100,
      totalScans: total,
      avgDuration: scans.length > 0 ? 
        Math.round(scans.reduce((acc, scan) => acc + (scan.duration || 0), 0) / scans.length) : 0
    };
  }, []);

  const loadDashboardData = useCallback(async () => {
    try {
      setLoading(true);
      const history = historyService.getAllHistory();
      
      // Filter to last 14 days
      const fourteenDaysAgo = new Date();
      fourteenDaysAgo.setDate(fourteenDaysAgo.getDate() - timeRange);
      
      const recentHistory = history.filter(scan => 
        new Date(scan.timestamp) >= fourteenDaysAgo
      );

      // Calculate metrics
      const metrics = calculateMetrics(recentHistory);
      const trends = calculateTrends(recentHistory);
      const scannerStats = calculateScannerBreakdown(recentHistory);
      const vulnTrends = calculateVulnerabilityTrends(recentHistory);
      
      setDashboardData({
        totalScans: recentHistory.length,
        highRisk: metrics.highRisk,
        mediumRisk: metrics.mediumRisk,
        lowRisk: metrics.lowRisk,
        scanTrends: trends,
        scannerBreakdown: scannerStats,
        recentScans: recentHistory.slice(0, 5), // Latest 5 scans
        systemHealth: calculateSystemHealth(recentHistory),
        vulnerabilityTrends: vulnTrends
      });
      
      setLastUpdate(new Date());
    } catch (error) {
      console.error('Error loading dashboard data:', error);
    } finally {
      setLoading(false);
    }
  }, [timeRange, calculateMetrics, calculateTrends, calculateScannerBreakdown, calculateVulnerabilityTrends, calculateSystemHealth]);

  // Initial load and event listeners
  useEffect(() => {
    loadDashboardData();
    
    // Listen for scan completion events
    const handleScanCompleted = () => {
      loadDashboardData();
    };

    const handleForceRefresh = () => {
      loadDashboardData();
    };

    window.addEventListener('scan-completed', handleScanCompleted);
    window.addEventListener('force-dashboard-refresh', handleForceRefresh);
    
    return () => {
      window.removeEventListener('scan-completed', handleScanCompleted);
      window.removeEventListener('force-dashboard-refresh', handleForceRefresh);
    };
  }, [loadDashboardData]);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      loadDashboardData();
    }, 30000); // 30 seconds

    return () => clearInterval(interval);
  }, [autoRefresh, loadDashboardData]);

  const formatScannerName = (scannerType) => {
    const nameMap = {
      'port_scanner': 'Port Scanner',
      'ssl_scanner': 'SSL Scanner', 
      'web_vulnerability': 'Web Vuln',
      'subdomain_finder': 'Subdomain',
      'defacement_scanner': 'Defacement',
      'google_poisoning': 'G. Poisoning',
      'google_dorking': 'G. Dorking',
      'virustotal_scanner': 'VirusTotal'
    };
    return nameMap[scannerType] || scannerType;
  };

  const formatTimeAgo = (timestamp) => {
    const now = new Date();
    const scanTime = new Date(timestamp);
    const diffInMinutes = Math.floor((now - scanTime) / (1000 * 60));
    
    if (diffInMinutes < 1) return 'Just now';
    if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
    if (diffInMinutes < 1440) return `${Math.floor(diffInMinutes / 60)}h ago`;
    return `${Math.floor(diffInMinutes / 1440)}d ago`;
  };

  const getSeverityIcon = (scan) => {
    const summary = scan.summary || {};
    if (summary.high_severity > 0) return { icon: '🔴', class: 'high-risk' };
    if (summary.medium_severity > 0) return { icon: '🟡', class: 'medium-risk' };
    if (summary.low_severity > 0) return { icon: '🟢', class: 'low-risk' };
    return { icon: '⚪', class: 'no-risk' };
  };

  const handleStartScan = (scannerType = null) => {
    if (scannerType) {
      // Navigate to specific scanner
      const scannerRoutes = {
        'port': '/new-scan?scanner=port',
        'web-vuln': '/new-scan?scanner=web-vulnerability', 
        'ssl': '/new-scan?scanner=ssl',
        'subdomain': '/new-scan?scanner=subdomain',
        'defacement': '/new-scan?scanner=defacement',
        'google-dorking': '/google-dorking',
        'virustotal': '/virustotal'
      };
      
      const route = scannerRoutes[scannerType] || '/new-scan';
      navigate(route);
    } else {
      navigate('/new-scan');
    }
  };

  const handleViewScanDetails = (scanId) => {
    navigate(`/scan-results/${scanId}`);
  };

  const handleExportData = () => {
    historyService.exportHistory();
  };

  const handleManualRefresh = () => {
    loadDashboardData();
  };

  if (loading && dashboardData.totalScans === 0) {
    return (
      <div className="dashboard-loading">
        <div className="loading-spinner">
          <FaSyncAlt className="spin" />
          Loading dashboard...
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      {/* Header */}
      <div className="dashboard-header">
        <div className="header-content">
          <h1>Security Dashboard</h1>
          <div className="header-meta">
            {user && (
              <div className="user-info">
                <FaUsers className="icon" />
                Welcome, {user.username || user.email}
              </div>
            )}
            <div className="last-update">
              <FaClock className="icon" />
              Last updated: {lastUpdate.toLocaleTimeString()}
            </div>
            <div className="time-range">
              <FaHistory className="icon" />
              Last {timeRange} days
            </div>
          </div>
        </div>
        <div className="header-actions">
          <button 
            className="btn btn-secondary refresh-btn"
            onClick={handleManualRefresh}
            title="Refresh Dashboard"
          >
            <FaSyncAlt className={loading ? 'spin' : ''} />
          </button>
          <button 
            className="btn btn-secondary export-btn"
            onClick={handleExportData}
            title="Export History"
          >
            <FaDownload />
          </button>
          <button 
            className="btn btn-primary start-scan-btn"
            onClick={() => handleStartScan()}
          >
            <FaRocket /> Start New Scan
          </button>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="metrics-grid">
        <div className="metric-card total-scans">
          <div className="metric-icon">
            <FaChartLine />
          </div>
          <div className="metric-content">
            <h3>{dashboardData.totalScans}</h3>
            <p>Total Scans</p>
            <span className="metric-subtitle">Last {timeRange} days</span>
          </div>
        </div>

        <div className="metric-card high-risk">
          <div className="metric-icon">
            <FaExclamationTriangle />
          </div>
          <div className="metric-content">
            <h3>{dashboardData.highRisk}</h3>
            <p>High Risk</p>
            <span className="metric-subtitle">Critical findings</span>
          </div>
        </div>

        <div className="metric-card medium-risk">
          <div className="metric-icon">
            <FaShieldAlt />
          </div>
          <div className="metric-content">
            <h3>{dashboardData.mediumRisk}</h3>
            <p>Medium Risk</p>
            <span className="metric-subtitle">Warning findings</span>
          </div>
        </div>

        <div className="metric-card low-risk">
          <div className="metric-icon">
            <FaCheckCircle />
          </div>
          <div className="metric-content">
            <h3>{dashboardData.lowRisk}</h3>
            <p>Low Risk</p>
            <span className="metric-subtitle">Info findings</span>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="charts-grid">
        {/* Scan Activity Trends */}
        <div className="chart-card scan-trends">
          <div className="chart-header">
            <h3>Scan Activity Trends</h3>
            <div className="chart-legend">
              <span className="legend-item">
                <span className="legend-color primary"></span>
                Total Scans
              </span>
              <span className="legend-item">
                <span className="legend-color success"></span>
                Successful
              </span>
            </div>
          </div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={dashboardData.scanTrends}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="date" 
                  tickFormatter={(date) => new Date(date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                />
                <YAxis />
                <Tooltip 
                  labelFormatter={(date) => new Date(date).toLocaleDateString()}
                />
                <Line 
                  type="monotone" 
                  dataKey="scans" 
                  stroke={COLORS.primary} 
                  strokeWidth={3}
                  name="Total Scans"
                />
                <Line 
                  type="monotone" 
                  dataKey="successful" 
                  stroke={COLORS.success} 
                  strokeWidth={2}
                  name="Successful"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Vulnerability Trends */}
        <div className="chart-card vuln-trends">
          <div className="chart-header">
            <h3>Vulnerability Discovery Trends</h3>
            <div className="chart-legend">
              <span className="legend-item">
                <span className="legend-color high"></span>
                High
              </span>
              <span className="legend-item">
                <span className="legend-color medium"></span>
                Medium
              </span>
              <span className="legend-item">
                <span className="legend-color low"></span>
                Low
              </span>
            </div>
          </div>
          <div className="chart-container">
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={dashboardData.vulnerabilityTrends}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis 
                  dataKey="date" 
                  tickFormatter={(date) => new Date(date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                />
                <YAxis />
                <Tooltip 
                  labelFormatter={(date) => new Date(date).toLocaleDateString()}
                />
                <Line 
                  type="monotone" 
                  dataKey="high" 
                  stroke={COLORS.high} 
                  strokeWidth={3}
                  name="High Risk"
                />
                <Line 
                  type="monotone" 
                  dataKey="medium" 
                  stroke={COLORS.medium} 
                  strokeWidth={2}
                  name="Medium Risk"
                />
                <Line 
                  type="monotone" 
                  dataKey="low" 
                  stroke={COLORS.low} 
                  strokeWidth={2}
                  name="Low Risk"
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Scanner Breakdown & System Health */}
      <div className="stats-grid">
        {/* Scanner Usage */}
        <div className="chart-card scanner-breakdown">
          <div className="chart-header">
            <h3>Scanner Usage</h3>
          </div>
          <div className="chart-container">
            {dashboardData.scannerBreakdown.length > 0 ? (
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={dashboardData.scannerBreakdown}
                    cx="50%"
                    cy="50%"
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="count"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {dashboardData.scannerBreakdown.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="no-data">
                <p>No scanner data available</p>
                <button className="btn btn-primary" onClick={() => handleStartScan()}>
                  Start First Scan
                </button>
              </div>
            )}
          </div>
        </div>

        {/* System Health */}
        <div className="health-card">
          <div className="chart-header">
            <h3>System Health</h3>
          </div>
          <div className="health-stats">
            <div className="health-item">
              <div className="health-label">Success Rate</div>
              <div className="health-value success">
                {dashboardData.systemHealth.successRate}%
              </div>
            </div>
            <div className="health-item">
              <div className="health-label">Total Scans</div>
              <div className="health-value">
                {dashboardData.systemHealth.totalScans}
              </div>
            </div>
            <div className="health-item">
              <div className="health-label">Avg Duration</div>
              <div className="health-value">
                {Math.floor(dashboardData.systemHealth.avgDuration / 1000)}s
              </div>
            </div>
            <div className="health-item">
              <div className="health-label">Auto Refresh</div>
              <label className="health-toggle">
                <input 
                  type="checkbox" 
                  checked={autoRefresh}
                  onChange={(e) => setAutoRefresh(e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="quick-actions-section">
        <h3>Quick Actions</h3>
        <div className="quick-actions-grid">
          <div className="action-card port-scan">
            <div className="action-icon">
              <FaServer />
            </div>
            <div className="action-content">
              <h4>Port Scan</h4>
              <p>Quick port scan for common services</p>
            </div>
            <button className="action-btn" onClick={() => handleStartScan('port')}>
              Start Scan
            </button>
          </div>

          <div className="action-card web-vuln">
            <div className="action-icon">
              <FaGlobe />
            </div>
            <div className="action-content">
              <h4>Web Vulnerability Scan</h4>
              <p>OWASP ZAP security scan</p>
            </div>
            <button className="action-btn" onClick={() => handleStartScan('web-vuln')}>
              Start Scan
            </button>
          </div>

          <div className="action-card ssl-check">
            <div className="action-icon">
              <FaLock />
            </div>
            <div className="action-content">
              <h4>SSL/TLS Check</h4>
              <p>Certificate and protocol verification</p>
            </div>
            <button className="action-btn" onClick={() => handleStartScan('ssl')}>
              Start Scan
            </button>
          </div>

          <div className="action-card subdomain-scan">
            <div className="action-icon">
              <FaSearch />
            </div>
            <div className="action-content">
              <h4>Subdomain Discovery</h4>
              <p>Find subdomains of target domain</p>
            </div>
            <button className="action-btn" onClick={() => handleStartScan('subdomain')}>
              Start Scan
            </button>
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="recent-activity-section">
        <div className="section-header">
          <h3>
            <FaHistory className="section-icon" />
            Recent Activity
          </h3>
          <button className="view-all-btn" onClick={() => navigate('/scan-history')}>
            <FaEye /> View All
          </button>
        </div>
        
        <div className="activity-list">
          {dashboardData.recentScans.length === 0 ? (
            <div className="no-activity">
              <p>No recent scan activity</p>
              <button className="btn btn-primary" onClick={() => handleStartScan()}>
                Start Your First Scan
              </button>
            </div>
          ) : (
            dashboardData.recentScans.map((scan, index) => {
              const severity = getSeverityIcon(scan);
              return (
                <div key={scan.id || index} className="activity-item" data-status={scan.status}>
                  <div className="activity-icon">
                    <span className={`severity-indicator ${severity.class}`}>
                      {severity.icon}
                    </span>
                  </div>
                  <div className="activity-details">
                    <div className="activity-main">
                      <span className="scanner-type">
                        {formatScannerName(scan.scannerType)}
                      </span>
                      <span className="target">{scan.target}</span>
                    </div>
                    <div className="activity-meta">
                      <span className={`status ${scan.status}`}>
                        {scan.status === 'completed' ? '✅ Completed' : '❌ Failed'}
                      </span>
                      <span className="timestamp">
                        {formatTimeAgo(scan.timestamp)}
                      </span>
                      {scan.summary && (
                        <span className="findings">
                          {(scan.summary.high_severity || 0) + 
                           (scan.summary.medium_severity || 0) + 
                           (scan.summary.low_severity || 0)} findings
                        </span>
                      )}
                      {scan.duration && (
                        <span className="duration">
                          {Math.floor(scan.duration / 1000)}s
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="activity-actions">
                    <button 
                      className="view-btn" 
                      title="View Details"
                      onClick={() => handleViewScanDetails(scan.id)}
                    >
                      <FaEye />
                    </button>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Dashboard Insights */}
      {dashboardData.totalScans > 0 && (
        <div className="insights-section">
          <h3>📊 Insights & Recommendations</h3>
          <div className="insights-grid">
            {dashboardData.highRisk > 0 && (
              <div className="insight-card critical">
                <h4>⚠️ High Risk Findings</h4>
                <p>
                  Found {dashboardData.highRisk} high-risk vulnerabilities. 
                  Consider prioritizing these for immediate remediation.
                </p>
                <button className="insight-action" onClick={() => navigate('/scan-history?filter=high-risk')}>
                  View High Risk Scans
                </button>
              </div>
            )}
            
            {dashboardData.systemHealth.successRate < 80 && (
              <div className="insight-card warning">
                <h4>🔧 System Performance</h4>
                <p>
                  Success rate is {dashboardData.systemHealth.successRate}%. 
                  Check scanner configurations and network connectivity.
                </p>
                <button className="insight-action" onClick={() => navigate('/settings')}>
                  Check Settings
                </button>
              </div>
            )}
            
            {dashboardData.totalScans === 0 && (
              <div className="insight-card info">
                <h4>🚀 Get Started</h4>
                <p>
                  No scans performed yet. Start with a port scan to discover 
                  open services on your target systems.
                </p>
                <button className="insight-action" onClick={() => handleStartScan('port')}>
                  Start Port Scan
                </button>
              </div>
            )}
            
            {dashboardData.scannerBreakdown.length === 1 && (
              <div className="insight-card tip">
                <h4>💡 Scanner Diversity</h4>
                <p>
                  You're only using one scanner type. Try different scanners 
                  for comprehensive security assessment.
                </p>
                <button className="insight-action" onClick={() => handleStartScan()}>
                  Explore Scanners
                </button>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;