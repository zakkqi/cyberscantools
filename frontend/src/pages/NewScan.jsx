// frontend/src/pages/NewScan.jsx
import React, { useState, useEffect } from 'react';
import { FaSpinner, FaServer, FaGlobe, FaLock, FaSearch, FaShieldAlt, FaExclamationTriangle, FaGoogle } from 'react-icons/fa';
import PortScanner from '../components/scanners/PortScanner';
import SSLScanner from '../components/scanners/SSLScanner';
import SubdomainScanner from '../components/scanners/SubdomainScanner';
import DefacementScanner from '../components/scanners/DefacementScanner';
import PoisoningScanner from '../components/scanners/PoisoningScanner';
import GoogleDorkingScanner from '../components/scanners/GoogleDorkingScanner';
import WebVulnerabilityScanner from '../components/scanners/WebVulnerabilityScanner';
import { api } from '../utils/api';
import '../styles/NewScan.css';
import VirusTotalScanner from '../components/scanners/VirusTotalScanner';


const NewScan = () => {
    const [scanners, setScanners] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [selectedScanner, setSelectedScanner] = useState(null);
    
    useEffect(() => {
        const fetchScanners = async () => {
            try {
                console.log('Attempting to fetch scanners...');
                
                try {
                    const status = await api.getStatus();
                    console.log('API Status:', status);
                } catch (statusError) {
                    console.error('Cannot connect to API:', statusError);
                    setError(`Cannot connect to backend server at http://localhost:5000. Please ensure the backend is running.`);
                    setLoading(false);
                    return;
                }
                
                const response = await api.getScanners();
                console.log('Scanners received:', response);
                
                // Enhance scanners with our custom data
                const enhancedScanners = response.map(scanner => ({
                    ...scanner,
                    icon: getIcon(scanner.id),
                    gradient: getGradient(scanner.id),
                    details: getDetails(scanner.id)
                }));
                
                setScanners(enhancedScanners);
                setLoading(false);
            } catch (err) {
                console.error('Error fetching scanners:', err);
                let errorMessage = 'Failed to load scanners. ';
                
                if (err.message === 'Network Error') {
                    errorMessage += 'Cannot connect to the backend server. Please ensure the backend is running on http://localhost:5000';
                } else if (err.response) {
                    errorMessage += `Server error: ${err.response.status} - ${err.response.statusText}`;
                } else {
                    errorMessage += err.message;
                }
                
                setError(errorMessage);
                setLoading(false);
            }
        };
        
        fetchScanners();
    }, []);
    
    const getIcon = (scannerId) => {
        const icons = {
            'port-scanner': '🖥️',
            'ssl-scanner': '🔒',
            'web-scanner': '🌐',
            'subdomain-scanner': '🔍',
            'defacement-scanner': '🛡️',
            'poisoning-scanner': '⚠️',
            'google-dorking-scanner': '🔎'
        };
        return icons[scannerId] || '📡';
    };
    
    const getGradient = (scannerId) => {
        const gradients = {
            'port-scanner': 'gradient-blue',
            'ssl-scanner': 'gradient-green',
            'web-scanner': 'gradient-red',
            'subdomain-scanner': 'gradient-purple',
            'defacement-scanner': 'gradient-orange',
            'poisoning-scanner': 'gradient-yellow',
            'google-dorking-scanner': 'gradient-cyan'
        };
        return gradients[scannerId] || 'gradient-default';
    };
    
    const getDetails = (scannerId) => {
        const details = {
            'port-scanner': 'Identify open TCP/UDP ports and running services',
            'ssl-scanner': 'Analyze certificate validity, protocol support, and cipher suites',
            'web-scanner': 'Find security issues like XSS, SQL injection, and more',
            'subdomain-scanner': 'Enumerate subdomains using multiple techniques',
            'defacement-scanner': 'Real-time monitoring for unauthorized changes',
            'poisoning-scanner': 'Identify compromised search results and SEO attacks',
            'google-dorking-scanner': 'Advanced Google search techniques for security testing'
        };
        return details[scannerId] || '';
    };
    
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
                return <VirusTotalScanner />;
                default:
                return (
                    <div className="card text-center scanner-not-implemented">
                        <h3>Scanner Not Implemented</h3>
                        <p>This scanner is not yet implemented.</p>
                        <button 
                            className="btn btn-secondary"
                            onClick={() => setSelectedScanner(null)}
                        >
                            Back
                        </button>
                    </div>
                );  
        }
    };
    
    if (loading) {
        return (
            <div className="loading-container">
                <FaSpinner className="loading-spinner" />
                <p>Loading scanners...</p>
            </div>
        );
    }
    
    if (error) {
        return (
            <div className="error-container">
                <div className="alert alert-error">
                    <h3>Error</h3>
                    <p>{error}</p>
                    <button 
                        onClick={() => window.location.reload()} 
                        className="btn btn-primary mt-4"
                    >
                        Retry
                    </button>
                </div>
            </div>
        );
    }
    
    if (selectedScanner) {
        return renderSelectedScanner();
    }
    
    return (
        <div className="new-scan-container">
            <div className="header-section">
                <h1 className="page-title">Select a Security Scanner</h1>
                <p className="page-subtitle">Choose the type of security scan you want to perform on your target.</p>
            </div>

            <div className="scanners-grid">
                {scanners.map((scanner) => (
                    <div 
                        key={scanner.id} 
                        className="scanner-card"
                        onClick={() => setSelectedScanner(scanner.id)}
                    >
                        <div className={`card-header ${scanner.gradient}`}>
                            <span className="scanner-icon">{scanner.icon}</span>
                        </div>
                        
                        <div className="card-body">
                            <h3 className="scanner-name">{scanner.name}</h3>
                            <p className="scanner-description">{scanner.description}</p>
                            <p className="scanner-details">{scanner.details}</p>
                            
                            {scanner.features && (
                                <ul className="features-list">
                                    {scanner.features.map((feature, index) => (
                                        <li key={index}>{feature}</li>
                                    ))}
                                </ul>
                            )}
                        </div>
                        
                        <div className="card-footer">
                            <button 
                                className="select-button"
                                onClick={(e) => {
                                    e.stopPropagation();
                                    setSelectedScanner(scanner.id);
                                }}
                            >
                                Select Scanner
                                <span className="arrow">→</span>
                            </button>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default NewScan;