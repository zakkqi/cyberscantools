// frontend/src/pages/Reports.jsx
import React from 'react';
import '../styles/Reports.css'; // Import the CSS file for styling

const Reports = () => {
    return (
    
            <div class="reports-container">

            <div class="page-header">
                <div class="header-content">
                <h1>📊 Security Reports</h1>
                <p>Comprehensive security analysis and reporting dashboard</p>
                </div>
                <div class="header-actions">
                <button class="btn btn-primary">
                    <i class="icon-download"></i>
                    Generate Report
                </button>
                <button class="btn btn-outline">
                    <i class="icon-schedule"></i>
                    Schedule Reports
                </button>
                </div>
            </div>

            <div class="reports-stats-grid">
                <div class="stat-card">
                <div class="stat-icon red">
                    <i class="icon-alert-triangle"></i>
                </div>
                <div class="stat-content">
                    <h3>Total Vulnerabilities</h3>
                    <div class="stat-number">247</div>
                    <div class="stat-change negative">+12 this week</div>
                </div>
                </div>
                
                <div class="stat-card">
                <div class="stat-icon blue">
                    <i class="icon-shield-check"></i>
                </div>
                <div class="stat-content">
                    <h3>Scans Performed</h3>
                    <div class="stat-number">1,453</div>
                    <div class="stat-change positive">+89 this month</div>
                </div>
                </div>
                
                <div class="stat-card">
                <div class="stat-icon green">
                    <i class="icon-check-circle"></i>
                </div>
                <div class="stat-content">
                    <h3>Issues Resolved</h3>
                    <div class="stat-number">198</div>
                    <div class="stat-change positive">+45 this week</div>
                </div>
                </div>
                
                <div class="stat-card">
                <div class="stat-icon orange">
                    <i class="icon-clock"></i>
                </div>
                <div class="stat-content">
                    <h3>Avg. Response Time</h3>
                    <div class="stat-number">2.4h</div>
                    <div class="stat-change positive">-0.3h improved</div>
                </div>
                </div>
            </div>

            <div class="reports-content">
                <div class="report-categories">
                <div class="report-section">
                    <div class="section-header">
                    <h2>📈 Executive Reports</h2>
                    <p>High-level security overview for management</p>
                    </div>
                    
                    <div class="report-grid">
                    <div class="report-card">
                        <div class="report-icon">
                        <i class="icon-trending-up"></i>
                        </div>
                        <div class="report-content">
                        <h3>Security Dashboard</h3>
                        <p>Overall security posture and key metrics</p>
                        <div class="report-meta">
                            <span class="report-type">Weekly</span>
                            <span class="report-date">Last updated: 2 hours ago</span>
                        </div>
                        </div>
                        <div class="report-actions">
                        <button class="btn btn-sm btn-primary">View Report</button>
                        <button class="btn btn-sm btn-outline">Download PDF</button>
                        </div>
                    </div>

                    <div class="report-card">
                        <div class="report-icon">
                        <i class="icon-pie-chart"></i>
                        </div>
                        <div class="report-content">
                        <h3>Risk Assessment</h3>
                        <p>Comprehensive risk analysis and recommendations</p>
                        <div class="report-meta">
                            <span class="report-type">Monthly</span>
                            <span class="report-date">Last updated: 1 day ago</span>
                        </div>
                        </div>
                        <div class="report-actions">
                        <button class="btn btn-sm btn-primary">View Report</button>
                        <button class="btn btn-sm btn-outline">Download PDF</button>
                        </div>
                    </div>

                    <div class="report-card">
                        <div class="report-icon">
                        <i class="icon-award"></i>
                        </div>
                        <div class="report-content">
                        <h3>Compliance Status</h3>
                        <p>Compliance with security standards and regulations</p>
                        <div class="report-meta">
                            <span class="report-type">Quarterly</span>
                            <span class="report-date">Last updated: 5 days ago</span>
                        </div>
                        </div>
                        <div class="report-actions">
                        <button class="btn btn-sm btn-primary">View Report</button>
                        <button class="btn btn-sm btn-outline">Download PDF</button>
                        </div>
                    </div>
                    </div>
                </div>

                <div class="report-section">
                    <div class="section-header">
                    <h2>🔧 Technical Reports</h2>
                    <p>Detailed technical analysis and findings</p>
                    </div>
                    
                    <div class="report-grid">
                    <div class="report-card">
                        <div class="report-icon">
                        <i class="icon-globe"></i>
                        </div>
                        <div class="report-content">
                        <h3>Web Vulnerability Analysis</h3>
                        <p>OWASP Top 10 and web security assessment</p>
                        <div class="report-meta">
                            <span class="report-type">Daily</span>
                            <span class="report-date">Last scan: 30 minutes ago</span>
                        </div>
                        </div>
                        <div class="report-actions">
                        <button class="btn btn-sm btn-primary">View Details</button>
                        <button class="btn btn-sm btn-outline">Export CSV</button>
                        </div>
                    </div>

                    <div class="report-card">
                        <div class="report-icon">
                        <i class="icon-wifi"></i>
                        </div>
                        <div class="report-content">
                        <h3>Network Port Analysis</h3>
                        <p>Open ports and network service discovery</p>
                        <div class="report-meta">
                            <span class="report-type">Daily</span>
                            <span class="report-date">Last scan: 1 hour ago</span>
                        </div>
                        </div>
                        <div class="report-actions">
                        <button class="btn btn-sm btn-primary">View Details</button>
                        <button class="btn btn-sm btn-outline">Export CSV</button>
                        </div>
                    </div>

                    <div class="report-card">
                        <div class="report-icon">
                        <i class="icon-lock"></i>
                        </div>
                        <div class="report-content">
                        <h3>SSL/TLS Certificate Report</h3>
                        <p>Certificate validity and security configuration</p>
                        <div class="report-meta">
                            <span class="report-type">Weekly</span>
                            <span class="report-date">Last check: 3 hours ago</span>
                        </div>
                        </div>
                        <div class="report-actions">
                        <button class="btn btn-sm btn-primary">View Details</button>
                        <button class="btn btn-sm btn-outline">Export CSV</button>
                        </div>
                    </div>

                    <div class="report-card">
                        <div class="report-icon">
                        <i class="icon-search"></i>
                        </div>
                        <div class="report-content">
                        <h3>Subdomain Discovery</h3>
                        <p>Domain enumeration and attack surface analysis</p>
                        <div class="report-meta">
                            <span class="report-type">Weekly</span>
                            <span class="report-date">Last scan: 6 hours ago</span>
                        </div>
                        </div>
                        <div class="report-actions">
                        <button class="btn btn-sm btn-primary">View Details</button>
                        <button class="btn btn-sm btn-outline">Export CSV</button>
                        </div>
                    </div>
                    </div>
                </div>

                <div class="report-section">
                    <div class="section-header">
                    <h2>📊 Trend Analysis</h2>
                    <p>Historical data and security trends</p>
                    </div>
                    
                    <div class="trends-container">
                    <div class="trend-card">
                        <h3>Vulnerability Trends</h3>
                        <div class="chart-container">
                        <div class="chart-placeholder">
                            <i class="icon-bar-chart-2"></i>
                            <p>Vulnerability count over time</p>
                        </div>
                        </div>
                    </div>
                    
                    <div class="trend-card">
                        <h3>Scan Frequency</h3>
                        <div class="chart-container">
                        <div class="chart-placeholder">
                            <i class="icon-activity"></i>
                            <p>Scanning activity patterns</p>
                        </div>
                        </div>
                    </div>
                    </div>
                </div>

                <div class="report-section">
                    <div class="section-header">
                    <h2>⚙️ Custom Reports</h2>
                    <p>Create and manage custom report templates</p>
                    </div>
                    
                    <div class="custom-reports">
                    <div class="custom-report-builder">
                        <div class="builder-header">
                        <h3>Report Builder</h3>
                        <button class="btn btn-primary">Create New Report</button>
                        </div>
                        
                        <div class="saved-templates">
                        <div class="template-item">
                            <div class="template-info">
                            <h4>Monthly Security Review</h4>
                            <p>Custom template for monthly security assessments</p>
                            </div>
                            <div class="template-actions">
                            <button class="btn btn-sm btn-outline">Edit</button>
                            <button class="btn btn-sm btn-primary">Generate</button>
                            </div>
                        </div>
                        
                        <div class="template-item">
                            <div class="template-info">
                            <h4>Incident Response Report</h4>
                            <p>Template for security incident documentation</p>
                            </div>
                            <div class="template-actions">
                            <button class="btn btn-sm btn-outline">Edit</button>
                            <button class="btn btn-sm btn-primary">Generate</button>
                            </div>
                        </div>
                        </div>
                    </div>
                    </div>
                </div>
                </div>
            </div>
            </div>
                );
            };

export default Reports;