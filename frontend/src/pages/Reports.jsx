// frontend/src/pages/Reports.jsx
import React, { useState, useEffect } from 'react';
import { FaPlus, FaDownload, FaEdit, FaTrash, FaEye, FaFileAlt, FaClock, FaExclamationTriangle } from 'react-icons/fa';
import '../styles/Reports.css';

const Reports = () => {
    const [findings, setFindings] = useState([]);
    const [reports, setReports] = useState([]);
    const [showFindingModal, setShowFindingModal] = useState(false);
    const [selectedScanResults, setSelectedScanResults] = useState([]);
    const [newFinding, setNewFinding] = useState({
        title: '',
        target: '',
        riskLevel: 'medium',
        status: 'open',
        description: '',
        evidence: '',
        recommendation: '',
        references: '',
        cvss: '',
        cwe: '',
        owasp: ''
    });

    // Mock data - in real app, fetch from MongoDB
    useEffect(() => {
        // Simulate fetching findings from database
        const mockFindings = [
            {
                id: 1,
                title: 'SQL Injection in Login Form',
                target: 'example.com',
                riskLevel: 'high',
                status: 'open',
                scanType: 'web-vulnerability',
                createdAt: '2024-06-01',
                verified: true
            },
            {
                id: 2,
                title: 'Weak SSL Configuration',
                target: 'api.example.com',
                riskLevel: 'medium',
                status: 'open',
                scanType: 'ssl-scanner',
                createdAt: '2024-06-02',
                verified: false
            },
            {
                id: 3,
                title: 'Open SSH Port on Non-Standard Port',
                target: '192.168.1.100',
                riskLevel: 'low',
                status: 'fixed',
                scanType: 'port-scanner',
                createdAt: '2024-06-03',
                verified: true
            }
        ];

        const mockReports = [
            {
                id: 1,
                name: 'Q2 2024 Security Assessment',
                type: 'comprehensive',
                status: 'completed',
                findings: 12,
                createdAt: '2024-06-01',
                updatedAt: '2024-06-03'
            },
            {
                id: 2,
                name: 'Web Application Security Review',
                type: 'web-focused',
                status: 'draft',
                findings: 5,
                createdAt: '2024-06-02',
                updatedAt: '2024-06-03'
            }
        ];

        setFindings(mockFindings);
        setReports(mockReports);
    }, []);

    const handleAddFinding = () => {
        setShowFindingModal(true);
    };

    const handleSaveFinding = () => {
        const finding = {
            ...newFinding,
            id: Date.now(),
            createdAt: new Date().toISOString().split('T')[0],
            verified: false
        };
        
        setFindings([...findings, finding]);
        setNewFinding({
            title: '',
            target: '',
            riskLevel: 'medium',
            status: 'open',
            description: '',
            evidence: '',
            recommendation: '',
            references: '',
            cvss: '',
            cwe: '',
            owasp: ''
        });
        setShowFindingModal(false);
    };

    const getRiskLevelColor = (level) => {
        const colors = {
            critical: '#dc2626',
            high: '#f97316',
            medium: '#eab308',
            low: '#06b6d4',
            info: '#8b5cf6'
        };
        return colors[level] || colors.medium;
    };

    const getStatusColor = (status) => {
        const colors = {
            open: '#ef4444',
            'false-positive': '#f59e0b',
            ignored: '#6b7280',
            fixed: '#10b981',
            accepted: '#8b5cf6'
        };
        return colors[status] || colors.open;
    };

    return (
        <div className="reports-container">
            <div className="page-header">
                <div className="header-content">
                    <div className="header-info">
                        <h1><i className="fas fa-file-alt"></i> Pentest Reports</h1>
                        <p>Manage findings and generate professional penetration testing reports</p>
                    </div>
                    <div className="header-actions">
                        <button className="btn btn-success" onClick={handleAddFinding}>
                            <FaPlus /> Add Finding
                        </button>
                        <button className="btn btn-primary">
                            <FaFileAlt /> New Report
                        </button>
                        <button className="btn btn-outline">
                            <FaDownload /> Export All
                        </button>
                    </div>
                </div>
            </div>

            <div className="reports-stats-grid">
                <div className="stat-card critical">
                    <div className="stat-icon">
                        <i className="fas fa-exclamation-triangle"></i>
                    </div>
                    <div className="stat-content">
                        <h3>Critical Findings</h3>
                        <div className="stat-number">3</div>
                        <div className="stat-change">Requires immediate attention</div>
                    </div>
                </div>
                
                <div className="stat-card high">
                    <div className="stat-icon">
                        <i className="fas fa-shield-alt"></i>
                    </div>
                    <div className="stat-content">
                        <h3>High Risk</h3>
                        <div className="stat-number">8</div>
                        <div className="stat-change">+2 this week</div>
                    </div>
                </div>
                
                <div className="stat-card medium">
                    <div className="stat-icon">
                        <i className="fas fa-exclamation-circle"></i>
                    </div>
                    <div className="stat-content">
                        <h3>Medium Risk</h3>
                        <div className="stat-number">15</div>
                        <div className="stat-change">+5 this week</div>
                    </div>
                </div>
                
                <div className="stat-card success">
                    <div className="stat-icon">
                        <i className="fas fa-check-circle"></i>
                    </div>
                    <div className="stat-content">
                        <h3>Fixed Issues</h3>
                        <div className="stat-number">24</div>
                        <div className="stat-change">+6 this week</div>
                    </div>
                </div>
            </div>

            <div className="reports-content">
                {/* Findings Management Section */}
                <div className="report-section">
                    <div className="section-header">
                        <h2><i className="fas fa-bug"></i> Findings Management</h2>
                        <p>Manage security findings from all scan modules</p>
                    </div>
                    
                    <div className="findings-table-container">
                        <div className="table-filters">
                            <div className="filter-group">
                                <label>Risk Level:</label>
                                <select className="filter-select">
                                    <option value="">All Levels</option>
                                    <option value="critical">Critical</option>
                                    <option value="high">High</option>
                                    <option value="medium">Medium</option>
                                    <option value="low">Low</option>
                                    <option value="info">Info</option>
                                </select>
                            </div>
                            <div className="filter-group">
                                <label>Status:</label>
                                <select className="filter-select">
                                    <option value="">All Status</option>
                                    <option value="open">Open</option>
                                    <option value="fixed">Fixed</option>
                                    <option value="false-positive">False Positive</option>
                                    <option value="accepted">Accepted</option>
                                </select>
                            </div>
                            <div className="filter-group">
                                <label>Scan Type:</label>
                                <select className="filter-select">
                                    <option value="">All Types</option>
                                    <option value="web-vulnerability">Web Vulnerability</option>
                                    <option value="port-scanner">Port Scanner</option>
                                    <option value="ssl-scanner">SSL Scanner</option>
                                    <option value="subdomain-scanner">Subdomain Scanner</option>
                                </select>
                            </div>
                        </div>

                        <div className="findings-table">
                            <table>
                                <thead>
                                    <tr>
                                        <th>Finding</th>
                                        <th>Target</th>
                                        <th>Risk Level</th>
                                        <th>Status</th>
                                        <th>Scan Type</th>
                                        <th>Date</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {findings.map(finding => (
                                        <tr key={finding.id}>
                                            <td>
                                                <div className="finding-title">
                                                    {finding.title}
                                                    {finding.verified && <i className="fas fa-check-circle verified-icon"></i>}
                                                </div>
                                            </td>
                                            <td>{finding.target}</td>
                                            <td>
                                                <span 
                                                    className="risk-badge"
                                                    style={{ backgroundColor: getRiskLevelColor(finding.riskLevel) }}
                                                >
                                                    {finding.riskLevel.toUpperCase()}
                                                </span>
                                            </td>
                                            <td>
                                                <span 
                                                    className="status-badge"
                                                    style={{ backgroundColor: getStatusColor(finding.status) }}
                                                >
                                                    {finding.status.replace('-', ' ').toUpperCase()}
                                                </span>
                                            </td>
                                            <td>{finding.scanType.replace('-', ' ')}</td>
                                            <td>{finding.createdAt}</td>
                                            <td>
                                                <div className="action-buttons">
                                                    <button className="btn-icon" title="View">
                                                        <FaEye />
                                                    </button>
                                                    <button className="btn-icon" title="Edit">
                                                        <FaEdit />
                                                    </button>
                                                    <button className="btn-icon delete" title="Delete">
                                                        <FaTrash />
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                {/* Report Templates Section */}
                <div className="report-section">
                    <div className="section-header">
                        <h2><i className="fas fa-file-export"></i> Report Generation</h2>
                        <p>Generate professional penetration testing reports</p>
                    </div>
                    
                    <div className="report-templates-grid">
                        <div className="template-card">
                            <div className="template-icon">
                                <i className="fas fa-file-pdf"></i>
                            </div>
                            <div className="template-content">
                                <h3>Executive Summary Report</h3>
                                <p>High-level overview for management and executives</p>
                                <div className="template-features">
                                    <span>• Risk overview</span>
                                    <span>• Key findings</span>
                                    <span>• Recommendations</span>
                                </div>
                            </div>
                            <button className="btn btn-primary">Generate</button>
                        </div>

                        <div className="template-card">
                            <div className="template-icon">
                                <i className="fas fa-code"></i>
                            </div>
                            <div className="template-content">
                                <h3>Technical Report</h3>
                                <p>Detailed technical findings for IT teams</p>
                                <div className="template-features">
                                    <span>• Detailed findings</span>
                                    <span>• Proof of concepts</span>
                                    <span>• Remediation steps</span>
                                </div>
                            </div>
                            <button className="btn btn-primary">Generate</button>
                        </div>

                        <div className="template-card">
                            <div className="template-icon">
                                <i className="fas fa-shield-alt"></i>
                            </div>
                            <div className="template-content">
                                <h3>Compliance Report</h3>
                                <p>Security compliance and audit documentation</p>
                                <div className="template-features">
                                    <span>• Compliance mapping</span>
                                    <span>• Gap analysis</span>
                                    <span>• Audit trail</span>
                                </div>
                            </div>
                            <button className="btn btn-primary">Generate</button>
                        </div>
                    </div>
                </div>

                {/* Recent Reports Section */}
                <div className="report-section">
                    <div className="section-header">
                        <h2><i className="fas fa-history"></i> Recent Reports</h2>
                        <p>Previously generated reports and drafts</p>
                    </div>
                    
                    <div className="recent-reports-list">
                        {reports.map(report => (
                            <div key={report.id} className="report-item">
                                <div className="report-info">
                                    <div className="report-title">
                                        <h4>{report.name}</h4>
                                        <span className={`report-status ${report.status}`}>
                                            {report.status}
                                        </span>
                                    </div>
                                    <div className="report-meta">
                                        <span><FaClock /> Updated: {report.updatedAt}</span>
                                        <span><FaExclamationTriangle /> Findings: {report.findings}</span>
                                        <span>Type: {report.type}</span>
                                    </div>
                                </div>
                                <div className="report-actions">
                                    <button className="btn btn-outline">
                                        <FaEye /> View
                                    </button>
                                    <button className="btn btn-outline">
                                        <FaEdit /> Edit
                                    </button>
                                    <button className="btn btn-primary">
                                        <FaDownload /> Download
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Add Finding Modal */}
            {showFindingModal && (
                <div className="modal-overlay">
                    <div className="modal-content">
                        <div className="modal-header">
                            <h3>Add New Finding</h3>
                            <button 
                                className="modal-close"
                                onClick={() => setShowFindingModal(false)}
                            >
                                ×
                            </button>
                        </div>
                        
                        <div className="modal-body">
                            <div className="form-row">
                                <div className="form-group">
                                    <label>Finding Title</label>
                                    <input
                                        type="text"
                                        value={newFinding.title}
                                        onChange={(e) => setNewFinding({...newFinding, title: e.target.value})}
                                        placeholder="e.g., SQL Injection in Login Form"
                                    />
                                </div>
                                <div className="form-group">
                                    <label>Target</label>
                                    <input
                                        type="text"
                                        value={newFinding.target}
                                        onChange={(e) => setNewFinding({...newFinding, target: e.target.value})}
                                        placeholder="e.g., example.com"
                                    />
                                </div>
                            </div>
                            
                            <div className="form-row">
                                <div className="form-group">
                                    <label>Risk Level</label>
                                    <select
                                        value={newFinding.riskLevel}
                                        onChange={(e) => setNewFinding({...newFinding, riskLevel: e.target.value})}
                                    >
                                        <option value="critical">Critical</option>
                                        <option value="high">High</option>
                                        <option value="medium">Medium</option>
                                        <option value="low">Low</option>
                                        <option value="info">Info</option>
                                    </select>
                                </div>
                                <div className="form-group">
                                    <label>Status</label>
                                    <select
                                        value={newFinding.status}
                                        onChange={(e) => setNewFinding({...newFinding, status: e.target.value})}
                                    >
                                        <option value="open">Open</option>
                                        <option value="false-positive">False Positive</option>
                                        <option value="ignored">Ignored</option>
                                        <option value="fixed">Fixed</option>
                                        <option value="accepted">Accepted</option>
                                    </select>
                                </div>
                            </div>
                            
                            <div className="form-group">
                                <label>Description</label>
                                <textarea
                                    value={newFinding.description}
                                    onChange={(e) => setNewFinding({...newFinding, description: e.target.value})}
                                    rows="4"
                                    placeholder="Detailed description of the vulnerability..."
                                />
                            </div>
                            
                            <div className="form-group">
                                <label>Evidence</label>
                                <textarea
                                    value={newFinding.evidence}
                                    onChange={(e) => setNewFinding({...newFinding, evidence: e.target.value})}
                                    rows="3"
                                    placeholder="Proof of concept, screenshots, logs..."
                                />
                            </div>
                            
                            <div className="form-group">
                                <label>Recommendation</label>
                                <textarea
                                    value={newFinding.recommendation}
                                    onChange={(e) => setNewFinding({...newFinding, recommendation: e.target.value})}
                                    rows="3"
                                    placeholder="Remediation steps and recommendations..."
                                />
                            </div>
                        </div>
                        
                        <div className="modal-footer">
                            <button 
                                className="btn btn-outline"
                                onClick={() => setShowFindingModal(false)}
                            >
                                Cancel
                            </button>
                            <button 
                                className="btn btn-success"
                                onClick={handleSaveFinding}
                            >
                                Save Finding
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default Reports;