// frontend/src/App.js - CLEAN VERSION
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

// Auth Pages
import Login from './pages/Login';
import Register from './pages/Register';

// Main Pages - Import Dashboard dari pages folder
import Dashboard from './pages/Dashboard';
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
import './styles/Dashboard.css';

const App = () => {
    const dispatch = useDispatch();
    const { isAuthenticated, loading } = useSelector(state => state.auth);
    
    // Initialize the application
    useEffect(() => {
        console.log('🚀 CyberScan Tools initializing...');
        
        // Initialize history service
        try {
            const stats = historyService.getStats();
            console.log('📊 History service initialized:', {
                totalScans: stats.total,
                recentScans: stats.recentScans,
                scannerTypes: Object.keys(stats.byScanner).length
            });
            
            // Check for legacy data and migrate if needed
            if (stats.total === 0) {
                console.log('🔍 No history found, checking for legacy data...');
                historyService.migrateExistingData();
            }
            
        } catch (error) {
            console.error('❌ Error initializing history service:', error);
        }
        
        // Validate token on app load and fetch user data
        if (isAuthenticated) {
            dispatch(fetchCurrentUser());
        }
        
        // Expose debug functions in development
        if (process.env.NODE_ENV === 'development') {
            window.cyberscanDebug = {
                historyService,
                debugScannerIntegration,
                authState: () => {
                    const state = JSON.parse(localStorage.getItem('persist:auth') || '{}');
                    return {
                        token: !!localStorage.getItem('token'),
                        user: !!localStorage.getItem('user'),
                        parsedState: state
                    };
                },
                clearAuth: () => {
                    localStorage.removeItem('token');
                    localStorage.removeItem('user');
                    localStorage.removeItem('persist:auth');
                    window.location.reload();
                }
            };
            console.log('🛠️ Debug tools available at window.cyberscanDebug');
        }
        
    }, [dispatch, isAuthenticated]);

    // Setup global error handling
    useEffect(() => {
        const handleUnhandledRejection = (event) => {
            console.error('🚨 Unhandled promise rejection:', event.reason);
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

    // Show loading spinner while checking authentication
    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-50">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto"></div>
                    <p className="mt-4 text-gray-600">Loading CyberScan Tools...</p>
                </div>
            </div>
        );
    }
   
    return (
        <BrowserRouter>
            <Routes>
                {/* Public Routes */}
                <Route 
                    path="/login" 
                    element={
                        isAuthenticated ? 
                        <Navigate to="/dashboard" replace /> : 
                        <Login />
                    } 
                />
                <Route 
                    path="/register" 
                    element={
                        isAuthenticated ? 
                        <Navigate to="/dashboard" replace /> : 
                        <Register />
                    } 
                />

                {/* Protected Routes with Layout */}
                <Route
                    element={
                        <ProtectedRoute>
                            <Layout />
                        </ProtectedRoute>
                    }
                >
                    {/* Main App Routes */}
                    <Route path="/" element={<Navigate to="/dashboard" replace />} />
                    <Route path="/dashboard" element={<Dashboard />} />
                    <Route path="/new-scan" element={<NewScan />} />
                    <Route path="/scan-history" element={<ScanHistory />} />
                    <Route path="/history" element={<Navigate to="/scan-history" replace />} />
                    <Route path="/reports" element={<Reports />} />
                    <Route path="/settings" element={<Settings />} />
                    
                    {/* Scanner Result Pages */}
                    <Route path="/scan-results/:scanId" element={<ScanResultsPage />} />
                    
                    {/* Individual Scanner Pages */}
                    <Route path="/virustotal" element={<VirusTotalPage />} />
                    <Route path="/google-dorking" element={<GoogleDorking />} />

                    {/* Debug Route for Development */}
                    {process.env.NODE_ENV === 'development' && (
                        <Route 
                            path="/debug" 
                            element={
                                <div className="p-6">
                                    <h1 className="text-2xl font-bold mb-4">🐛 Debug Information</h1>
                                    <div className="space-y-4">
                                        <div className="bg-gray-100 p-4 rounded">
                                            <h3 className="font-bold mb-2">Auth State:</h3>
                                            <pre className="text-xs">{JSON.stringify({ isAuthenticated }, null, 2)}</pre>
                                        </div>
                                        <div className="bg-blue-100 p-4 rounded">
                                            <h3 className="font-bold mb-2">Quick Actions:</h3>
                                            <button 
                                                onClick={() => window.cyberscanDebug?.clearAuth()}
                                                className="bg-red-500 text-white px-4 py-2 rounded"
                                            >
                                                Clear Auth & Reload
                                            </button>
                                        </div>
                                        <div className="bg-green-100 p-4 rounded">
                                            <h3 className="font-bold mb-2">Local Storage:</h3>
                                            <pre className="text-xs">{JSON.stringify({
                                                token: !!localStorage.getItem('token'),
                                                user: !!localStorage.getItem('user'),
                                                tokenLength: localStorage.getItem('token')?.length || 0
                                            }, null, 2)}</pre>
                                        </div>
                                    </div>
                                </div>
                            } 
                        />
                    )}

                    {/* 404 Route */}
                    <Route path="*" element={
                        <div className="min-h-screen flex items-center justify-center">
                            <div className="text-center">
                                <h1 className="text-4xl font-bold text-gray-900 mb-4">404</h1>
                                <p className="text-gray-600 mb-4">Page not found</p>
                                <p className="text-sm text-gray-500 mb-4">Current path: {window.location.pathname}</p>
                                <button
                                    onClick={() => window.history.back()}
                                    className="text-blue-600 hover:text-blue-800 underline"
                                >
                                    Go Back
                                </button>
                            </div>
                        </div>
                    } />
                </Route>
            </Routes>
        </BrowserRouter>
    );
};

export default App;