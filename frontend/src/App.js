// frontend/src/App.js - INTEGRATED WITH ENHANCED DASHBOARD
import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { fetchCurrentUser } from './store/authSlice';

// Services and Hooks
import { historyService } from './services/historyService';
import { debugScannerIntegration } from './hooks/useScannerIntegration';

// Components
import Layout from './components/layout/Layout';
import ProtectedRoute from './components/auth/ProtectedRoute';

// Pages
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard'; // Updated to use enhanced dashboard
import NewScan from './pages/NewScan';
import ScanHistory from './pages/ScanHistory';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import ScanResultsPage from './pages/ScanResultsPage';
import VirusTotalPage from './pages/VirusTotalPage';
import GoogleDorking from './pages/GoogleDorking';

// Styles
import './styles/global.css';
import './styles/Layout.css';
import './styles/Dashboard.css'; // Add enhanced dashboard styles

const App = () => {
    const dispatch = useDispatch();
    const { isAuthenticated } = useSelector(state => state.auth);
   
    // Initialize the application
    useEffect(() => {
        console.log('🚀 CyberScan Tools initializing with Enhanced Dashboard...');
        
        // Initialize history service (auto-migration will occur)
        try {
            const stats = historyService.getStats();
            console.log('📊 History service initialized:', {
                totalScans: stats.total,
                recentScans: stats.recentScans,
                scannerTypes: Object.keys(stats.byScanner).length,
                successRate: stats.byStatus.completed ? 
                    Math.round((stats.byStatus.completed / stats.total) * 100) : 100
            });
            
            // Check for legacy data and migrate if needed
            if (stats.total === 0) {
                console.log('🔍 No history found, checking for legacy data...');
                historyService.migrateExistingData();
                
                // Generate test data in development if no data exists
                if (process.env.NODE_ENV === 'development') {
                    console.log('🧪 Generating test data for development...');
                    generateTestScanData();
                }
            }
            
        } catch (error) {
            console.error('❌ Error initializing history service:', error);
        }
        
        // Validate token on app load
        if (isAuthenticated) {
            dispatch(fetchCurrentUser());
        }
        
        // Run debug check in development
        if (process.env.NODE_ENV === 'development') {
            setTimeout(() => {
                console.log('🐛 Running development debug check...');
                try {
                    const debugInfo = debugScannerIntegration();
                    console.log('Debug info:', debugInfo);
                } catch (error) {
                    console.warn('Debug check failed:', error);
                }
            }, 2000);
        }
        
        // Expose debug functions in development
        if (process.env.NODE_ENV === 'development') {
            window.cyberscanDebug = {
                historyService,
                debugScannerIntegration,
                clearHistory: () => {
                    if (window.confirm('⚠️ This will delete ALL scan history. Are you sure?')) {
                        historyService.clearHistory();
                        console.log('✅ History cleared');
                        window.location.reload();
                    }
                },
                getStats: () => historyService.getStats(),
                exportHistory: () => historyService.exportHistory(),
                generateTestData: () => {
                    const testData = generateTestScanData();
                    console.log('✅ Generated test data:', testData.length, 'scans');
                    // Trigger dashboard refresh event
                    window.dispatchEvent(new CustomEvent('scan-completed'));
                    return testData;
                },
                migrateData: () => {
                    historyService.migrateExistingData();
                    console.log('✅ Migration completed');
                    window.dispatchEvent(new CustomEvent('scan-completed'));
                },
                checkLocalStorage: () => {
                    const allKeys = Object.keys(localStorage);
                    const scanKeys = allKeys.filter(key => 
                        key.includes('scan') || 
                        key.includes('result') || 
                        key.includes('history')
                    );
                    console.log('📦 All localStorage keys:', allKeys.length);
                    console.log('🔍 Scan-related keys:', scanKeys);
                    scanKeys.forEach(key => {
                        try {
                            const data = localStorage.getItem(key);
                            const parsed = JSON.parse(data);
                            console.log(`📄 ${key}:`, {
                                type: Array.isArray(parsed) ? 'Array' : typeof parsed,
                                length: Array.isArray(parsed) ? parsed.length : 'N/A',
                                size: `${(data.length / 1024).toFixed(2)} KB`
                            });
                        } catch (e) {
                            console.warn(`❌ Invalid JSON in ${key}`);
                        }
                    });
                    return scanKeys;
                },
                // Dashboard specific debug functions
                dashboardDebug: {
                    refreshDashboard: () => {
                        window.dispatchEvent(new CustomEvent('force-dashboard-refresh'));
                        console.log('🔄 Dashboard refresh triggered');
                    },
                    simulateScanComplete: (scannerType = 'port_scanner') => {
                        const mockScan = {
                            scannerType,
                            target: 'test.example.com',
                            status: 'completed',
                            duration: Math.floor(Math.random() * 10000) + 1000,
                            results: [{ name: 'Test Result', status: 'success' }],
                            vulnerabilities: [],
                            metadata: { test: true }
                        };
                        historyService.saveScanResult(mockScan);
                        window.dispatchEvent(new CustomEvent('scan-completed'));
                        console.log('✅ Mock scan completed:', mockScan);
                    },
                    getDashboardData: () => {
                        const history = historyService.getAllHistory();
                        const fourteenDaysAgo = new Date();
                        fourteenDaysAgo.setDate(fourteenDaysAgo.getDate() - 14);
                        const recentHistory = history.filter(scan => 
                            new Date(scan.timestamp) >= fourteenDaysAgo
                        );
                        return {
                            totalHistory: history.length,
                            recentHistory: recentHistory.length,
                            scannerBreakdown: recentHistory.reduce((acc, scan) => {
                                acc[scan.scannerType] = (acc[scan.scannerType] || 0) + 1;
                                return acc;
                            }, {}),
                            statusBreakdown: recentHistory.reduce((acc, scan) => {
                                acc[scan.status] = (acc[scan.status] || 0) + 1;
                                return acc;
                            }, {})
                        };
                    }
                }
            };
            console.log('🛠️ Debug tools available at window.cyberscanDebug');
            console.log('📊 Dashboard debug tools at window.cyberscanDebug.dashboardDebug');
        }
        
    }, [dispatch, isAuthenticated]);

    // Generate test data for development with enhanced dashboard compatibility
    const generateTestScanData = () => {
        const scanners = [
            'port_scanner',
            'ssl_scanner', 
            'web_vulnerability',
            'subdomain_finder',
            'defacement_scanner',
            'google_dorking',
            'google_poisoning',
            'virustotal_scanner'
        ];
        
        const targets = [
            'example.com',
            'test.org',
            '192.168.1.1',
            'demo.site.com',
            'sample.net',
            'localhost',
            'scanme.nmap.org',
            'google.com',
            'microsoft.com',
            'github.com'
        ];
        
        const statuses = ['completed', 'failed', 'completed', 'completed', 'completed'];
        const testData = [];
        
        // Generate data spread over last 30 days for better dashboard visualization
        for (let i = 0; i < 50; i++) {
            const scanner = scanners[Math.floor(Math.random() * scanners.length)];
            const target = targets[Math.floor(Math.random() * targets.length)];
            const status = statuses[Math.floor(Math.random() * statuses.length)];
            
            // Create more realistic vulnerability data
            const severityDistribution = {
                'critical': Math.floor(Math.random() * 2), // 0-1 critical
                'high': Math.floor(Math.random() * 3),     // 0-2 high
                'medium': Math.floor(Math.random() * 5),   // 0-4 medium
                'low': Math.floor(Math.random() * 8),      // 0-7 low
                'info': Math.floor(Math.random() * 10)     // 0-9 info
            };
            
            const vulnerabilities = [];
            Object.entries(severityDistribution).forEach(([severity, count]) => {
                for (let j = 0; j < count; j++) {
                    vulnerabilities.push({
                        id: `${severity}-${j}`,
                        title: `${severity.charAt(0).toUpperCase() + severity.slice(1)} Vulnerability ${j + 1}`,
                        description: `Test ${severity} vulnerability description for ${scanner}`,
                        severity: severity,
                        cvss: severity === 'critical' ? (9 + Math.random()).toFixed(1) :
                              severity === 'high' ? (7 + Math.random() * 2).toFixed(1) :
                              severity === 'medium' ? (4 + Math.random() * 3).toFixed(1) :
                              severity === 'low' ? (1 + Math.random() * 3).toFixed(1) :
                              (0 + Math.random()).toFixed(1),
                        cwe: `CWE-${Math.floor(Math.random() * 900) + 100}`,
                        recommendation: `Fix this ${severity} vulnerability by following security best practices.`
                    });
                }
            });
            
            // Generate timestamp spread over last 30 days with more recent data
            const daysAgo = Math.floor(Math.random() * 30);
            const hoursAgo = Math.floor(Math.random() * 24);
            const minutesAgo = Math.floor(Math.random() * 60);
            const timestamp = new Date();
            timestamp.setDate(timestamp.getDate() - daysAgo);
            timestamp.setHours(timestamp.getHours() - hoursAgo);
            timestamp.setMinutes(timestamp.getMinutes() - minutesAgo);
            
            const totalVulns = vulnerabilities.length;
            const duration = Math.floor(Math.random() * 15000) + 1000; // 1-16 seconds
            
            testData.push({
                id: `test-${Date.now().toString(36)}-${Math.random().toString(36).substr(2)}`,
                timestamp: timestamp.toISOString(),
                scannerType: scanner,
                target: target,
                status: status,
                duration: duration,
                results: status === 'completed' ? Array.from({length: Math.floor(Math.random() * 15) + 1}, (_, j) => ({
                    id: j,
                    name: `${scanner} Result ${j + 1}`,
                    value: `Test value ${j + 1}`,
                    status: Math.random() > 0.2 ? 'success' : 'warning',
                    details: `Detailed information for result ${j + 1}`
                })) : [],
                vulnerabilities: status === 'completed' ? vulnerabilities : [],
                summary: {
                    total_found: status === 'completed' ? totalVulns : 0,
                    high_severity: severityDistribution.critical + severityDistribution.high,
                    medium_severity: severityDistribution.medium,
                    low_severity: severityDistribution.low,
                    info_severity: severityDistribution.info
                },
                metadata: {
                    userAgent: navigator.userAgent,
                    testData: true,
                    generated: new Date().toISOString(),
                    scannerVersion: '1.0.0',
                    executionTime: duration,
                    dataSource: 'automated-test-generation'
                },
                ...(status === 'failed' && { 
                    error: [
                        'Connection timeout',
                        'Target unreachable', 
                        'Permission denied',
                        'Service unavailable',
                        'Rate limit exceeded'
                    ][Math.floor(Math.random() * 5)]
                })
            });
        }
        
        // Sort by timestamp (newest first) for better dashboard display
        testData.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        localStorage.setItem('scanHistory', JSON.stringify(testData));
        console.log('🧪 Generated enhanced test data:', {
            totalScans: testData.length,
            scannerTypes: [...new Set(testData.map(s => s.scannerType))],
            dateRange: {
                oldest: testData[testData.length - 1]?.timestamp,
                newest: testData[0]?.timestamp
            },
            statusBreakdown: testData.reduce((acc, scan) => {
                acc[scan.status] = (acc[scan.status] || 0) + 1;
                return acc;
            }, {}),
            totalVulnerabilities: testData.reduce((acc, scan) => 
                acc + (scan.vulnerabilities?.length || 0), 0
            )
        });
        
        return testData;
    };

    // Setup global error handling
    useEffect(() => {
        const handleUnhandledRejection = (event) => {
            console.error('🚨 Unhandled promise rejection:', event.reason);
            // Optionally show user-friendly error message
        };

        const handleError = (event) => {
            console.error('🚨 Global error:', event.error);
        };

        window.addEventListener('unhandledrejection', handleUnhandledRejection);
        window.addEventListener('error', handleError);

        return () => {
            window.removeEventListener('unhandledrejection', handleUnhandledRejection);
            window.removeEventListener('error', handleError);
        };
    }, []);

    // Dashboard navigation handler
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
            window.location.href = route;
        } else {
            // Navigate to scanner selection page
            window.location.href = '/new-scan';
        }
    };

    // Enhanced Dashboard wrapper with navigation integration
    const EnhancedDashboard = () => {
        return <Dashboard onStartScan={handleStartScan} />;
    };
   
    return (
        <BrowserRouter>
            <Routes>
                {/* Public Routes */}
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
               
                {/* Protected Routes */}
                <Route path="/" element={
                    <ProtectedRoute>
                        <Layout />
                    </ProtectedRoute>
                }>
                    {/* Main Dashboard - Enhanced */}
                    <Route index element={<Navigate to="/dashboard" replace />} />
                    <Route path="dashboard" element={<EnhancedDashboard />} />
                    
                    {/* Scanning Routes */}
                    <Route path="new-scan" element={<NewScan />} />
                    <Route path="scan-results/:scanId" element={<ScanResultsPage />} />
                    
                    {/* History and Reports */}
                    <Route path="scan-history" element={<ScanHistory />} />
                    <Route path="history" element={<Navigate to="/scan-history" replace />} />
                    <Route path="reports" element={<Reports />} />
                    
                    {/* Settings */}
                    <Route path="settings" element={<Settings />} />
                    
                    {/* Individual Scanner Pages */}
                    <Route path="virustotal" element={<VirusTotalPage />} />
                    <Route path="google-dorking" element={<GoogleDorking />} />
                    
                    {/* Legacy route redirects */}
                    <Route path="scan/:scanType" element={<Navigate to="/new-scan" replace />} />
                </Route>
               
                {/* Catch all route */}
                <Route path="*" element={
                    isAuthenticated ? 
                    <Navigate to="/dashboard" replace /> : 
                    <Navigate to="/login" replace />
                } />
            </Routes>
        </BrowserRouter>
    );
};

export default App;