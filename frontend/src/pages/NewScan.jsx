// frontend/src/pages/NewScan.jsx - CLEAN PROFESSIONAL DESIGN
import React, { useState, useEffect } from 'react';
import { FaSpinner, FaServer, FaGlobe, FaLock, FaSearch, FaShieldAlt, FaExclamationTriangle, FaGoogle, FaVirus, FaRocket, FaArrowLeft } from 'react-icons/fa';
import PortScanner from '../components/scanners/PortScanner';
import SSLScanner from '../components/scanners/SSLScanner';
import SubdomainScanner from '../components/scanners/SubdomainScanner';
import DefacementScanner from '../components/scanners/DefacementScanner';
import PoisoningScanner from '../components/scanners/PoisoningScanner';
import GoogleDorkingScanner from '../components/scanners/GoogleDorkingScanner';
import WebVulnerabilityScanner from '../components/scanners/WebVulnerabilityScanner';
import VirusTotalScanner from '../components/scanners/VirusTotalScanner';
import { api } from '../utils/api';
import '../styles/NewScan.css';

const NewScan = () => {
    const [scanners, setScanners] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [selectedScanner, setSelectedScanner] = useState(null);
    
    // Enhanced scanner data with clean professional styling
    const scannerEnhancements = {
        'port-scanner': {
            icon: FaServer,
            description: 'Scan for open ports on target hosts',
            iconClass: 'port-scanner'
        },
        'ssl-scanner': {
            icon: FaLock,
            description: 'Comprehensive SSL/TLS security analysis',
            iconClass: 'ssl-scanner'
        },
        'web-scanner': {
            icon: FaGlobe,
            description: 'Detect web vulnerabilities using OWASP ZAP',
            iconClass: 'web-scanner'
        },
        'subdomain-scanner': {
            icon: FaSearch,
            description: 'Discover subdomains of a target domain',
            iconClass: 'subdomain-scanner'
        },
        'defacement-scanner': {
            icon: FaShieldAlt,
            description: 'Monitor and detect website defacement activities',
            iconClass: 'defacement-scanner'
        },
        'poisoning-scanner': {
            icon: FaExclamationTriangle,
            description: 'Detect search engine poisoning and malicious SEO activities',
            iconClass: 'poisoning-scanner'
        },
        'google-dorking-scanner': {
            icon: FaGoogle,
            description: 'Find exposed information using Google search operators',
            iconClass: 'google-dorking-scanner'
        },
        'virustotal-scanner': {
            icon: FaVirus,
            description: 'Leverage VirusTotal\'s multi-engine scanning to detect malicious files and URLs',
            iconClass: 'virustotal-scanner'
        }
    };
    
    useEffect(() => {
        const fetchScanners = async () => {
            try {
                setLoading(true);
                setError(null);
                console.log('🔍 Attempting to fetch scanners...');
                
                // Test backend connection first
                try {
                    const status = await api.getStatus();
                    console.log('✅ API Status:', status);
                } catch (statusError) {
                    console.error('❌ Cannot connect to API:', statusError);
                    setError(`Cannot connect to backend server. Please ensure the backend is running.`);
                    setLoading(false);
                    return;
                }
                
                // Fetch scanners
                const response = await api.getScanners();
                console.log('📋 Scanners received:', response);
                
                // Enhance scanners with our custom data
                const enhancedScanners = response.map(scanner => {
                    const enhancement = scannerEnhancements[scanner.id] || {};
                    return {
                        ...scanner,
                        icon: enhancement.icon || FaServer,
                        description: enhancement.description || scanner.description,
                        iconClass: enhancement.iconClass || scanner.id
                    };
                });
                
                setScanners(enhancedScanners);
                
            } catch (err) {
                console.error('❌ Error fetching scanners:', err);
                setError('Failed to load scanners. Please try again.');
            } finally {
                setLoading(false);
            }
        };
        
        fetchScanners();
    }, []);
    
    const renderSelectedScanner = () => {
        switch (selectedScanner) {
            case 'port-scanner':
                return <PortScanner onBack={() => setSelectedScanner(null)} />;
            case 'ssl-scanner':
                return <SSLScanner onBack={() => setSelectedScanner(null)} />;
            case 'web-scanner':
                return <WebVulnerabilityScanner onBack={() => setSelectedScanner(null)} />;
            case 'subdomain-scanner':
                return <SubdomainScanner onBack={() => setSelectedScanner(null)} />;
            case 'defacement-scanner':
                return <DefacementScanner onBack={() => setSelectedScanner(null)} />;
            case 'poisoning-scanner':
                return <PoisoningScanner onBack={() => setSelectedScanner(null)} />;
            case 'google-dorking-scanner':
                return <GoogleDorkingScanner onBack={() => setSelectedScanner(null)} />;
            case 'virustotal-scanner':
                return <VirusTotalScanner onBack={() => setSelectedScanner(null)} />;
            default:
                return (
                    <div className="simple-container">
                        <button 
                            className="back-button"
                            onClick={() => setSelectedScanner(null)}
                        >
                            <FaArrowLeft /> Back to Scanner Selection
                        </button>
                        <div className="simple-card">
                            <FaExclamationTriangle className="error-icon" />
                            <h3>Scanner Not Available</h3>
                            <p>This scanner is currently not implemented.</p>
                            <button 
                                className="simple-button secondary"
                                onClick={() => setSelectedScanner(null)}
                            >
                                Back to Scanner Selection
                            </button>
                        </div>
                    </div>
                );  
        }
    };
    
    const handleScannerClick = (scanner) => {
        if (scanner.status === 'active') {
            setSelectedScanner(scanner.id);
        }
    };
    
    if (loading) {
        return (
            <div className="simple-container">
                <div className="simple-card">
                    <FaSpinner className="loading-spinner" />
                    <h3>Loading Security Scanners...</h3>
                    <p>Please wait while we load the available security scanners...</p>
                </div>
            </div>
        );
    }
    
    if (error) {
        return (
            <div className="simple-container">
                <div className="simple-card">
                    <FaExclamationTriangle className="error-icon" />
                    <h3>Connection Error</h3>
                    <p>{error}</p>
                    <button 
                        onClick={() => window.location.reload()} 
                        className="simple-button primary"
                    >
                        Retry Connection
                    </button>
                </div>
            </div>
        );
    }
    
    if (selectedScanner) {
        return renderSelectedScanner();
    }
    
    return (
        <div className="simple-container">
            {/* Header */}
            <div className="simple-header">
                <h1>
                    <FaRocket />
                    Select a Security Scanner
                </h1>
                <p>Choose the type of security scan you want to perform on your target.</p>
            </div>

            {/* Scanners Grid - Clean Professional Style */}
            <div className="simple-scanners-grid">
                {scanners.map((scanner) => {
                    const IconComponent = scanner.icon;
                    return (
                        <div 
                            key={scanner.id} 
                            className={`simple-scanner-card ${scanner.status !== 'active' ? 'disabled' : ''}`}
                            onClick={() => handleScannerClick(scanner)}
                        >
                            {/* Scanner Icon */}
                            <div className="scanner-icon-container">
                                <div className={`scanner-icon ${scanner.iconClass || scanner.id}`}>
                                    <IconComponent />
                                </div>
                            </div>
                            
                            {/* Scanner Content */}
                            <h3 className="scanner-name">{scanner.name}</h3>
                            <p className="scanner-description">{scanner.description}</p>
                            
                            {/* Action Button */}
                            <button 
                                className={`simple-button ${scanner.status === 'active' ? 'primary' : 'disabled'}`}
                                disabled={scanner.status !== 'active'}
                                onClick={(e) => {
                                    e.stopPropagation();
                                    handleScannerClick(scanner);
                                }}
                            >
                                {scanner.status === 'active' ? 'Select Scanner' : 'Unavailable'}
                            </button>
                        </div>
                    );
                })}
            </div>

            {/* No Scanners Message */}
            {scanners.length === 0 && !loading && !error && (
                <div className="simple-card">
                    <FaExclamationTriangle className="error-icon" />
                    <h3>No Scanners Available</h3>
                    <p>No security scanners are currently available. Please check your configuration.</p>
                    <button 
                        onClick={() => window.location.reload()} 
                        className="simple-button primary"
                    >
                        Refresh
                    </button>
                </div>
            )}
        </div>
    );
};

export default NewScan;