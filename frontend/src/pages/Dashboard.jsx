// frontend/src/pages/Dashboard.jsx - UPDATED WITH CLEAN PROFESSIONAL STYLE
import React, { useState, useEffect, useCallback } from 'react';
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
  FaClock,
  FaEye,
  FaDownload,
  FaSyncAlt,
  FaWifi,
  FaBug,
  FaTachometerAlt,
  FaLightbulb,
  FaExclamationCircle,
  FaUser,
  FaGoogle
} from 'react-icons/fa';
import { historyService } from '../services/historyService';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, BarChart, Bar, PieChart, Pie, Cell } from 'recharts';
import '../styles/Dashboard.css';

const Dashboard = () => {
  const navigate = useNavigate();
  
  // Redux state
  const currentUser = useSelector(state => state.auth.user);
  const { token } = useSelector(state => state.auth);
  
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
  
  const [timeRange] = useState(14);
  const [loading, setLoading] = useState(true);
  const [lastUpdate, setLastUpdate] = useState(new Date());
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Colors for charts - modern palette
  const COLORS = {
    high: '#ef4444',
    medium: '#f59e0b',
    low: '#10b981',
    success: '#22c55e',
    primary: '#3b82f6',
    info: '#06b6d4',
    purple: '#8b5cf6',
    indigo: '#6366f1'
  };

  const PIE_COLORS = ['#3b82f6', '#10b981', '#ef4444', '#f59e0b', '#8b5cf6', '#06b6d4', '#f97316'];

  const calculateMetrics = useCallback((scans) => {
    let highRisk = 0;
    let mediumRisk = 0;
    let lowRisk = 0;

    scans.forEach(scan => {
      const summary = scan.summary || {};
      const vulnerabilities = scan.vulnerabilities || [];
      
      // Try both summary and vulnerabilities array
      highRisk += summary.high_severity || 
                  vulnerabilities.filter(v => v.severity === 'critical' || v.severity === 'high').length || 0;
      mediumRisk += summary.medium_severity || 
                    vulnerabilities.filter(v => v.severity === 'medium').length || 0;
      lowRisk += summary.low_severity || 
                 vulnerabilities.filter(v => v.severity === 'low' || v.severity === 'info').length || 0;
    });

    return { highRisk, mediumRisk, lowRisk };
  }, []);

  const calculateTrends = useCallback((scans) => {
    const dailyScans = {};
    
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
        const vulnerabilities = scan.vulnerabilities || [];
        dailyScans[scanDate].vulnerabilities += 
          (summary.high_severity || 0) + 
          (summary.medium_severity || 0) + 
          (summary.low_severity || 0) + 
          vulnerabilities.length;
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
        const vulnerabilities = scan.vulnerabilities || [];
        
        vulnTrends[scanDate].high += summary.high_severity || 
                                     vulnerabilities.filter(v => v.severity === 'critical' || v.severity === 'high').length || 0;
        vulnTrends[scanDate].medium += summary.medium_severity || 
                                       vulnerabilities.filter(v => v.severity === 'medium').length || 0;
        vulnTrends[scanDate].low += summary.low_severity || 
                                    vulnerabilities.filter(v => v.severity === 'low' || v.severity === 'info').length || 0;
      }
    });

    return Object.values(vulnTrends);
  }, [timeRange]);

  const calculateSystemHealth = useCallback((scans) => {
    const total = scans.length;
    const successful = scans.filter(s => s.status === 'completed').length;
    
    return {
      successRate: total > 0 ? Math.round((successful / total) * 100) : 100,
      totalScans: total,
      avgDuration: scans.length > 0 ? 
        Math.round(scans.reduce((acc, scan) => acc + (scan.duration || 0), 0) / scans.length) : 0
    };
  }, []);

  const loadDashboardData = useCallback(async () => {
    try {
      setRefreshing(true);
      
      // Get real history from service
      const history = historyService.getAllHistory();
      
      const fourteenDaysAgo = new Date();
      fourteenDaysAgo.setDate(fourteenDaysAgo.getDate() - timeRange);
      
      const recentHistory = history.filter(scan => 
        new Date(scan.timestamp) >= fourteenDaysAgo
      );

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
        recentScans: recentHistory.slice(0, 5),
        systemHealth: calculateSystemHealth(recentHistory),
        vulnerabilityTrends: vulnTrends
      });
      
      setLastUpdate(new Date());
    } catch (error) {
      console.error('Error loading dashboard data:', error);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [timeRange, calculateMetrics, calculateTrends, calculateScannerBreakdown, calculateVulnerabilityTrends, calculateSystemHealth]);

  useEffect(() => {
    loadDashboardData();
    
    const handleScanCompleted = () => {
      loadDashboardData();
    };

    window.addEventListener('scan-completed', handleScanCompleted);
    window.addEventListener('force-dashboard-refresh', handleScanCompleted);
    
    return () => {
      window.removeEventListener('scan-completed', handleScanCompleted);
      window.removeEventListener('force-dashboard-refresh', handleScanCompleted);
    };
  }, [loadDashboardData]);

  useEffect(() => {
    if (!autoRefresh) return;

    const interval = setInterval(() => {
      loadDashboardData();
    }, 30000);

    return () => clearInterval(interval);
  }, [autoRefresh, loadDashboardData]);

  const formatScannerName = (scannerType) => {
    const nameMap = {
      'port-scanner': 'Port Scanner',
      'port_scanner': 'Port Scanner',
      'ssl-scanner': 'SSL Scanner', 
      'ssl_scanner': 'SSL Scanner',
      'web-vulnerability': 'Web Vuln',
      'web_vulnerability': 'Web Vuln',
      'subdomain-scanner': 'Subdomain',
      'subdomain_scanner': 'Subdomain',
      'defacement-scanner': 'Defacement',
      'defacement_scanner': 'Defacement',
      'google-poisoning': 'G. Poisoning',
      'google_poisoning': 'G. Poisoning',
      'google-dorking': 'G. Dorking',
      'google_dorking': 'G. Dorking',
      'virustotal-scanner': 'VirusTotal',
      'virustotal_scanner': 'VirusTotal'
    };
    return nameMap[scannerType] || scannerType.replace(/[-_]/g, ' ');
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
    const vulnerabilities = scan.vulnerabilities || [];
    
    const highCount = summary.high_severity || vulnerabilities.filter(v => v.severity === 'critical' || v.severity === 'high').length || 0;
    const mediumCount = summary.medium_severity || vulnerabilities.filter(v => v.severity === 'medium').length || 0;
    const lowCount = summary.low_severity || vulnerabilities.filter(v => v.severity === 'low' || v.severity === 'info').length || 0;
    
    if (highCount > 0) return { icon: <FaExclamationTriangle />, class: 'high-risk' };
    if (mediumCount > 0) return { icon: <FaExclamationCircle />, class: 'medium-risk' };
    if (lowCount > 0) return { icon: <FaCheckCircle />, class: 'low-risk' };
    return { icon: <FaShieldAlt />, class: 'no-risk' };
  };

  // UPDATED: Quick Action Scanner configurations with clean professional design
  const quickActionScanners = [
    {
      id: 'port-scan',
      title: 'Port Scan',
      description: 'Quick port scan for common services and open ports',
      icon: <FaServer />,
      route: 'port'
    },
    {
      id: 'web-vuln',
      title: 'Web Vulnerability Scan',
      description: 'OWASP ZAP security scan for web applications',
      icon: <FaGlobe />,
      route: 'web-vuln'
    },
    {
      id: 'ssl-check',
      title: 'SSL/TLS Check',
      description: 'Certificate and protocol security verification',
      icon: <FaLock />,
      route: 'ssl'
    },
    {
      id: 'subdomain-scan',
      title: 'Subdomain Discovery',
      description: 'Find and enumerate subdomains of target domain',
      icon: <FaSearch />,
      route: 'subdomain'
    },
    {
      id: 'defacement-scan',
      title: 'Web Defacement Scan',
      description: 'Monitor and detect website defacement activities',
      icon: <FaShieldAlt />,
      route: 'defacement'
    },
    {
      id: 'google-poisoning',
      title: 'Google Poisoning Scan',
      description: 'Detect search engine poisoning and malicious SEO',
      icon: <FaExclamationTriangle />,
      route: 'google-poisoning'
    },
    {
      id: 'google-dorking',
      title: 'Google Dorking Scan',
      description: 'Find exposed information using Google operators',
      icon: <FaGoogle />,
      route: 'google-dorking'
    },
    {
      id: 'virustotal-scan',
      title: 'VirusTotal Scan',
      description: 'Multi-engine scanning for malicious files and URLs',
      icon: <FaBug />,
      route: 'virustotal'
    }
  ];

  const handleStartScan = (scannerType = null) => {
    if (scannerType) {
      const scannerRoutes = {
        'port': '/new-scan?scanner=port',
        'web-vuln': '/new-scan?scanner=web-vulnerability', 
        'ssl': '/new-scan?scanner=ssl',
        'subdomain': '/new-scan?scanner=subdomain',
        'defacement': '/new-scan?scanner=defacement',
        'google-poisoning': '/new-scan?scanner=google-poisoning',
        'google-dorking': '/new-scan?scanner=google-dorking',
        'virustotal': '/new-scan?scanner=virustotal'
      };
      
      const route = scannerRoutes[scannerType] || '/new-scan';
      navigate(route);
    } else {
      navigate('/new-scan');
    }
  };

  const handleViewScanDetails = (scanId) => {
    navigate('/scan-history');
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
          <span>Loading dashboard...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="dashboard-container">
      {/* Header with User Info */}
      <div className="dashboard-header">
        <div className="header-content">
          <div className="header-title">
            <h1>
              <FaTachometerAlt /> 
              Security Dashboard
            </h1>
            <div className="header-meta">
              <div className="user-welcome">
                <FaUser className="icon" />
                Welcome back, {currentUser?.first_name || currentUser?.username || 'User'}!
              </div>
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
        </div>
        <div className="header-actions">
          <button 
            className="btn btn-secondary refresh-btn"
            onClick={handleManualRefresh}
            title="Refresh Dashboard"
            disabled={refreshing}
          >
            <FaSyncAlt className={refreshing ? 'spin' : ''} />
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
            <FaExclamationCircle />
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
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis 
                  dataKey="date" 
                  tickFormatter={(date) => new Date(date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                  stroke="#6b7280"
                />
                <YAxis stroke="#6b7280" />
                <Tooltip 
                  labelFormatter={(date) => new Date(date).toLocaleDateString()}
                  contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #e5e7eb', borderRadius: '8px' }}
                />
                <Line 
                  type="monotone" 
                  dataKey="scans" 
                  stroke={COLORS.primary} 
                  strokeWidth={3}
                  name="Total Scans"
                  dot={{ fill: COLORS.primary, strokeWidth: 2, r: 4 }}
                />
                <Line 
                  type="monotone" 
                  dataKey="successful" 
                  stroke={COLORS.success} 
                  strokeWidth={2}
                  name="Successful"
                  dot={{ fill: COLORS.success, strokeWidth: 2, r: 3 }}
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
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis 
                  dataKey="date" 
                  tickFormatter={(date) => new Date(date).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                  stroke="#6b7280"
                />
                <YAxis stroke="#6b7280" />
                <Tooltip 
                  labelFormatter={(date) => new Date(date).toLocaleDateString()}
                  contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #e5e7eb', borderRadius: '8px' }}
                />
                <Line 
                  type="monotone" 
                  dataKey="high" 
                  stroke={COLORS.high} 
                  strokeWidth={3}
                  name="High Risk"
                  dot={{ fill: COLORS.high, strokeWidth: 2, r: 4 }}
                />
                <Line 
                  type="monotone" 
                  dataKey="medium" 
                  stroke={COLORS.medium} 
                  strokeWidth={2}
                  name="Medium Risk"
                  dot={{ fill: COLORS.medium, strokeWidth: 2, r: 3 }}
                />
                <Line 
                  type="monotone" 
                  dataKey="low" 
                  stroke={COLORS.low} 
                  strokeWidth={2}
                  name="Low Risk"
                  dot={{ fill: COLORS.low, strokeWidth: 2, r: 3 }}
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
                    dataKey="count"
                    label={({ name, value }) => `${name}: ${value}`}
                  >
                    {dashboardData.scannerBreakdown.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#ffffff', border: '1px solid #e5e7eb', borderRadius: '8px' }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="no-data">
                <FaBug style={{ fontSize: '3rem', color: '#9ca3af', marginBottom: '1rem' }} />
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
            <h3><FaTachometerAlt /> System Health</h3>
          </div>
          <div className="health-stats">
            <div className="health-item">
              <div className="health-label">
                <FaCheckCircle style={{ color: COLORS.success, marginRight: '0.5rem' }} />
                Success Rate
              </div>
              <div className="health-value success">
                {dashboardData.systemHealth.successRate}%
              </div>
            </div>
            <div className="health-item">
              <div className="health-label">
                <FaChartLine style={{ color: COLORS.primary, marginRight: '0.5rem' }} />
                Total Scans
              </div>
              <div className="health-value">
                {dashboardData.systemHealth.totalScans}
              </div>
            </div>
            <div className="health-item">
              <div className="health-label">
                <FaClock style={{ color: COLORS.info, marginRight: '0.5rem' }} />
                Avg Duration
              </div>
              <div className="health-value">
                {Math.floor(dashboardData.systemHealth.avgDuration / 1000)}s
              </div>
            </div>
            <div className="health-item">
              <div className="health-label">
                <FaSyncAlt style={{ color: COLORS.purple, marginRight: '0.5rem' }} />
                Auto Refresh
              </div>
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

      {/* Quick Actions - UPDATED TO CLEAN PROFESSIONAL GRID */}
      <div className="quick-actions-section">
        <h3><FaRocket /> Quick Actions</h3>
        <div className="quick-actions-grid">
          {quickActionScanners.map((scanner) => (
            <div 
              key={scanner.id} 
              className="action-card"
              onClick={() => handleStartScan(scanner.route)}
            >
              <div className="action-icon">
                {scanner.icon}
              </div>
              <div className="action-content">
                <h4>{scanner.title}</h4>
                <p>{scanner.description}</p>
              </div>
              <button 
                className="action-btn"
                onClick={(e) => {
                  e.stopPropagation();
                  handleStartScan(scanner.route);
                }}
              >
                Start Scan
              </button>
            </div>
          ))}
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
              <FaHistory style={{ fontSize: '3rem', color: '#9ca3af', marginBottom: '1rem' }} />
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
                        {scan.status === 'completed' ? 'Completed' : 'Failed'}
                      </span>
                      <span className="timestamp">
                        {formatTimeAgo(scan.timestamp)}
                      </span>
                      {(scan.summary || scan.vulnerabilities) && (
                        <span className="findings">
                          {((scan.summary?.high_severity || 0) + 
                            (scan.summary?.medium_severity || 0) + 
                            (scan.summary?.low_severity || 0) +
                            (scan.vulnerabilities?.length || 0))} findings
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
          <h3><FaLightbulb /> Insights & Recommendations</h3>
          <div className="insights-grid">
            {dashboardData.highRisk > 0 && (
              <div className="insight-card critical">
                <h4><FaExclamationTriangle /> High Risk Findings</h4>
                <p>
                  Found {dashboardData.highRisk} high-risk vulnerabilities. 
                  Consider prioritizing these for immediate remediation.
                </p>
                <button className="insight-action" onClick={() => navigate('/scan-history')}>
                  View High Risk Scans
                </button>
              </div>
            )}
            
            {dashboardData.systemHealth.successRate < 80 && (
              <div className="insight-card warning">
                <h4><FaWifi /> System Performance</h4>
                <p>
                  Success rate is {dashboardData.systemHealth.successRate}%. 
                  Check scanner configurations and network connectivity.
                </p>
                <button className="insight-action" onClick={() => navigate('/settings')}>
                  Check Settings
                </button>
              </div>
            )}
            
            {dashboardData.totalScans < 5 && (
              <div className="insight-card info">
                <h4><FaRocket /> Get Started</h4>
                <p>
                  Limited scan history. Start with a port scan to discover 
                  open services on your target systems.
                </p>
                <button className="insight-action" onClick={() => handleStartScan('port')}>
                  Start Port Scan
                </button>
              </div>
            )}
            
            {dashboardData.scannerBreakdown.length === 1 && (
              <div className="insight-card tip">
                <h4><FaLightbulb /> Scanner Diversity</h4>
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