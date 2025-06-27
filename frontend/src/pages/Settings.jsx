// frontend/src/pages/Settings.jsx
import React, { useState, useEffect } from 'react';
import { FaSave, FaUndo, FaCog, FaSearch, FaShieldAlt, FaBell, FaLink, FaCode } from 'react-icons/fa';
import '../styles/Settings.css';

const Settings = () => {
    const [activeSection, setActiveSection] = useState('general');
    const [settings, setSettings] = useState({
        // General Settings
        theme: 'light',
        language: 'en',
        timezone: 'Asia/Jakarta',
        autoRefresh: true,
        refreshInterval: 30,
        showAdvancedMetrics: false,
        
        // Scanning Settings
        scanTimeout: 300,
        concurrentThreads: 5,
        scanIntensity: 'normal',
        enabledModules: {
            portScanner: true,
            sslScanner: true,
            webVulnScanner: true,
            subdomainScanner: true,
            defacementScanner: false,
            googleDorkingScanner: false,
            virusTotalScanner: false
        },
        
        // Security Settings
        sessionTimeout: 60,
        maxSessions: 3,
        apiAccess: true,
        apiRateLimit: 1000,
        
        // Notification Settings
        notifications: {
            highSeverity: true,
            scanCompletion: true,
            weeklyReport: false,
            email: 'user@example.com',
            slackWebhook: ''
        },
        
        // Advanced Settings
        debugMode: false,
        dataRetention: 90
    });

    const [hasChanges, setHasChanges] = useState(false);

    // Load settings from localStorage on component mount
    useEffect(() => {
        const savedSettings = localStorage.getItem('cyberScanSettings');
        if (savedSettings) {
            const parsed = JSON.parse(savedSettings);
            setSettings(prev => ({ ...prev, ...parsed }));
            // Apply theme immediately
            applyTheme(parsed.theme || 'light');
        }
    }, []);

    // Apply theme to document
    const applyTheme = (theme) => {
        document.documentElement.setAttribute('data-theme', theme);
        if (theme === 'dark') {
            document.body.classList.add('dark-theme');
        } else {
            document.body.classList.remove('dark-theme');
        }
    };

    // Update settings and mark as changed
    const updateSetting = (path, value) => {
        setSettings(prev => {
            const newSettings = { ...prev };
            const keys = path.split('.');
            let current = newSettings;
            
            for (let i = 0; i < keys.length - 1; i++) {
                current = current[keys[i]];
            }
            current[keys[keys.length - 1]] = value;
            
            return newSettings;
        });
        setHasChanges(true);

        // Apply certain settings immediately
        if (path === 'theme') {
            applyTheme(value);
        }
        if (path === 'autoRefresh') {
            console.log('Auto-refresh', value ? 'enabled' : 'disabled');
        }
        if (path === 'language') {
            console.log('Language changed to:', value);
            // Here you would typically update the app's language
        }
    };

    // Save all settings
    const saveSettings = () => {
        localStorage.setItem('cyberScanSettings', JSON.stringify(settings));
        setHasChanges(false);
        
        // Show success notification
        const notification = document.createElement('div');
        notification.className = 'save-notification';
        notification.textContent = 'Settings saved successfully!';
        document.body.appendChild(notification);
        
        setTimeout(() => {
            notification.remove();
        }, 3000);
    };

    // Reset to defaults
    const resetToDefaults = () => {
        const defaultSettings = {
            theme: 'light',
            language: 'en',
            timezone: 'Asia/Jakarta',
            autoRefresh: true,
            refreshInterval: 30,
            showAdvancedMetrics: false,
            scanTimeout: 300,
            concurrentThreads: 5,
            scanIntensity: 'normal',
            enabledModules: {
                portScanner: true,
                sslScanner: true,
                webVulnScanner: true,
                subdomainScanner: true,
                defacementScanner: false,
                googleDorkingScanner: false,
                virusTotalScanner: false
            },
            sessionTimeout: 60,
            maxSessions: 3,
            apiAccess: true,
            apiRateLimit: 1000,
            notifications: {
                highSeverity: true,
                scanCompletion: true,
                weeklyReport: false,
                email: 'user@example.com',
                slackWebhook: ''
            },
            debugMode: false,
            dataRetention: 90
        };
        
        setSettings(defaultSettings);
        applyTheme('light');
        setHasChanges(true);
    };

    // Clear scan data
    const clearScanData = () => {
        if (window.confirm('Are you sure you want to clear all scan data? This action cannot be undone.')) {
            localStorage.removeItem('scanHistory');
            localStorage.removeItem('scanResults');
            alert('Scan data cleared successfully!');
        }
    };

    return (
        <div className="settings-container">
            <div className="page-header">
                <div className="header-content">
                    <div className="header-info">
                        <h1><FaCog /> Settings</h1>
                        <p>Configure your CyberScan Tools preferences and security settings</p>
                    </div>
                    <div className="header-actions">
                        <button 
                            className={`btn btn-success ${!hasChanges ? 'disabled' : ''}`}
                            onClick={saveSettings}
                            disabled={!hasChanges}
                        >
                            <FaSave /> Save All Changes
                        </button>
                        <button className="btn btn-outline" onClick={resetToDefaults}>
                            <FaUndo /> Reset to Defaults
                        </button>
                    </div>
                </div>
            </div>

            <div className="settings-content">
                <div className="settings-nav">
                    {[
                        { id: 'general', icon: FaCog, label: 'General' },
                        { id: 'scanning', icon: FaSearch, label: 'Scanning' },
                        { id: 'security', icon: FaShieldAlt, label: 'Security' },
                        { id: 'notifications', icon: FaBell, label: 'Notifications' },
                        { id: 'advanced', icon: FaCode, label: 'Advanced' }
                    ].map(({ id, icon: Icon, label }) => (
                        <div 
                            key={id}
                            className={`nav-item ${activeSection === id ? 'active' : ''}`}
                            onClick={() => setActiveSection(id)}
                        >
                            <Icon />
                            <span>{label}</span>
                        </div>
                    ))}
                </div>

                <div className="settings-panels">
                    {/* General Settings */}
                    <div className={`settings-panel ${activeSection === 'general' ? 'active' : ''}`}>
                        <div className="panel-header">
                            <h2>General Settings</h2>
                            <p>Basic application preferences and display options</p>
                        </div>
                        
                        <div className="settings-groups">
                            <div className="settings-group">
                                <h3>Application Preferences</h3>
                                
                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Theme</label>
                                        <p>Choose your preferred color scheme</p>
                                    </div>
                                    <div className="setting-control">
                                        <select 
                                            className="form-select"
                                            value={settings.theme}
                                            onChange={(e) => updateSetting('theme', e.target.value)}
                                        >
                                            <option value="light">Light Theme</option>
                                            <option value="dark">Dark Theme</option>
                                            <option value="auto">Auto (System)</option>
                                        </select>
                                    </div>
                                </div>

                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Language</label>
                                        <p>Select your preferred language</p>
                                    </div>
                                    <div className="setting-control">
                                        <select 
                                            className="form-select"
                                            value={settings.language}
                                            onChange={(e) => updateSetting('language', e.target.value)}
                                        >
                                            <option value="en">English</option>
                                            <option value="id">Bahasa Indonesia</option>
                                            <option value="es">Español</option>
                                        </select>
                                    </div>
                                </div>

                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Timezone</label>
                                        <p>Set your local timezone</p>
                                    </div>
                                    <div className="setting-control">
                                        <select 
                                            className="form-select"
                                            value={settings.timezone}
                                            onChange={(e) => updateSetting('timezone', e.target.value)}
                                        >
                                            <option value="Asia/Jakarta">Asia/Jakarta (WIB)</option>
                                            <option value="UTC">UTC</option>
                                            <option value="America/New_York">America/New_York (EST)</option>
                                            <option value="Europe/London">Europe/London (GMT)</option>
                                        </select>
                                    </div>
                                </div>
                            </div>

                            <div className="settings-group">
                                <h3>Dashboard Configuration</h3>
                                
                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Auto-refresh Dashboard</label>
                                        <p>Automatically refresh dashboard data</p>
                                    </div>
                                    <div className="setting-control">
                                        <label className="toggle-switch">
                                            <input 
                                                type="checkbox" 
                                                checked={settings.autoRefresh}
                                                onChange={(e) => updateSetting('autoRefresh', e.target.checked)}
                                            />
                                            <span className="toggle-slider"></span>
                                        </label>
                                    </div>
                                </div>

                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Refresh Interval</label>
                                        <p>How often to refresh data (seconds)</p>
                                    </div>
                                    <div className="setting-control">
                                        <input 
                                            type="number" 
                                            className="form-input" 
                                            value={settings.refreshInterval}
                                            min="10" 
                                            max="300"
                                            onChange={(e) => updateSetting('refreshInterval', parseInt(e.target.value))}
                                            disabled={!settings.autoRefresh}
                                        />
                                    </div>
                                </div>

                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Show Advanced Metrics</label>
                                        <p>Display detailed technical metrics on dashboard</p>
                                    </div>
                                    <div className="setting-control">
                                        <label className="toggle-switch">
                                            <input 
                                                type="checkbox" 
                                                checked={settings.showAdvancedMetrics}
                                                onChange={(e) => updateSetting('showAdvancedMetrics', e.target.checked)}
                                            />
                                            <span className="toggle-slider"></span>
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Scanning Settings */}
                    <div className={`settings-panel ${activeSection === 'scanning' ? 'active' : ''}`}>
                        <div className="panel-header">
                            <h2>Scanning Configuration</h2>
                            <p>Configure default scanning behavior and parameters</p>
                        </div>
                        
                        <div className="settings-groups">
                            <div className="settings-group">
                                <h3>Default Scan Parameters</h3>
                                
                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Scan Timeout (seconds)</label>
                                        <p>Maximum time to wait for scan completion</p>
                                    </div>
                                    <div className="setting-control">
                                        <input 
                                            type="number" 
                                            className="form-input" 
                                            value={settings.scanTimeout}
                                            min="60" 
                                            max="3600"
                                            onChange={(e) => updateSetting('scanTimeout', parseInt(e.target.value))}
                                        />
                                    </div>
                                </div>

                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Concurrent Threads</label>
                                        <p>Number of parallel scanning threads</p>
                                    </div>
                                    <div className="setting-control">
                                        <input 
                                            type="number" 
                                            className="form-input" 
                                            value={settings.concurrentThreads}
                                            min="1" 
                                            max="20"
                                            onChange={(e) => updateSetting('concurrentThreads', parseInt(e.target.value))}
                                        />
                                    </div>
                                </div>

                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Scan Intensity</label>
                                        <p>Level of scan thoroughness</p>
                                    </div>
                                    <div className="setting-control">
                                        <select 
                                            className="form-select"
                                            value={settings.scanIntensity}
                                            onChange={(e) => updateSetting('scanIntensity', e.target.value)}
                                        >
                                            <option value="light">Light (Fast)</option>
                                            <option value="normal">Normal</option>
                                            <option value="intensive">Intensive (Thorough)</option>
                                        </select>
                                    </div>
                                </div>
                            </div>

                            <div className="settings-group">
                                <h3>Scanner Modules</h3>
                                <p>Enable or disable specific scanning modules</p>
                                
                                <div className="scanner-modules">
                                    {[
                                        { key: 'portScanner', icon: '🖥️', title: 'Port Scanner', desc: 'Scan for open network ports', color: 'blue' },
                                        { key: 'sslScanner', icon: '🔒', title: 'SSL/TLS Scanner', desc: 'Check SSL certificate security', color: 'green' },
                                        { key: 'webVulnScanner', icon: '🌐', title: 'Web Vulnerability Scanner', desc: 'OWASP Top 10 vulnerability detection', color: 'red' },
                                        { key: 'subdomainScanner', icon: '🔍', title: 'Subdomain Scanner', desc: 'Discover subdomains and DNS records', color: 'purple' },
                                        { key: 'defacementScanner', icon: '🛡️', title: 'Defacement Scanner', desc: 'Monitor website integrity', color: 'orange' },
                                        { key: 'googleDorkingScanner', icon: '🔎', title: 'Google Dorking Scanner', desc: 'Advanced Google search techniques', color: 'cyan' },
                                        { key: 'virusTotalScanner', icon: '🦠', title: 'VirusTotal Scanner', desc: 'Multi-engine malware detection', color: 'indigo' }
                                    ].map(module => (
                                        <div key={module.key} className="module-item">
                                            <div className="module-info">
                                                <div className={`module-icon ${module.color}`}>
                                                    <span>{module.icon}</span>
                                                </div>
                                                <div className="module-details">
                                                    <h4>{module.title}</h4>
                                                    <p>{module.desc}</p>
                                                </div>
                                            </div>
                                            <label className="toggle-switch">
                                                <input 
                                                    type="checkbox" 
                                                    checked={settings.enabledModules[module.key]}
                                                    onChange={(e) => updateSetting(`enabledModules.${module.key}`, e.target.checked)}
                                                />
                                                <span className="toggle-slider"></span>
                                            </label>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Security Settings */}
                    <div className={`settings-panel ${activeSection === 'security' ? 'active' : ''}`}>
                        <div className="panel-header">
                            <h2>Security & Access Control</h2>
                            <p>Manage authentication, authorization, and security policies</p>
                        </div>
                        
                        <div className="settings-groups">
                            <div className="settings-group">
                                <h3>Session Management</h3>
                                
                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Session Timeout</label>
                                        <p>Automatically logout after inactivity (minutes)</p>
                                    </div>
                                    <div className="setting-control">
                                        <input 
                                            type="number" 
                                            className="form-input" 
                                            value={settings.sessionTimeout}
                                            min="15" 
                                            max="480"
                                            onChange={(e) => updateSetting('sessionTimeout', parseInt(e.target.value))}
                                        />
                                    </div>
                                </div>

                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Maximum Concurrent Sessions</label>
                                        <p>Maximum number of simultaneous sessions</p>
                                    </div>
                                    <div className="setting-control">
                                        <input 
                                            type="number" 
                                            className="form-input" 
                                            value={settings.maxSessions}
                                            min="1" 
                                            max="10"
                                            onChange={(e) => updateSetting('maxSessions', parseInt(e.target.value))}
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="settings-group">
                                <h3>API Security</h3>
                                
                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>API Access</label>
                                        <p>Enable API access for external integrations</p>
                                    </div>
                                    <div className="setting-control">
                                        <label className="toggle-switch">
                                            <input 
                                                type="checkbox" 
                                                checked={settings.apiAccess}
                                                onChange={(e) => updateSetting('apiAccess', e.target.checked)}
                                            />
                                            <span className="toggle-slider"></span>
                                        </label>
                                    </div>
                                </div>

                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>API Rate Limit</label>
                                        <p>Maximum API requests per hour</p>
                                    </div>
                                    <div className="setting-control">
                                        <input 
                                            type="number" 
                                            className="form-input" 
                                            value={settings.apiRateLimit}
                                            min="100" 
                                            max="10000"
                                            disabled={!settings.apiAccess}
                                            onChange={(e) => updateSetting('apiRateLimit', parseInt(e.target.value))}
                                        />
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Notification Settings */}
                    <div className={`settings-panel ${activeSection === 'notifications' ? 'active' : ''}`}>
                        <div className="panel-header">
                            <h2>Notification Settings</h2>
                            <p>Configure alerts and notification preferences</p>
                        </div>
                        
                        <div className="settings-groups">
                            <div className="settings-group">
                                <h3>Email Notifications</h3>
                                
                                {[
                                    { key: 'highSeverity', title: 'High Severity Vulnerabilities', desc: 'Immediate alerts for critical security issues' },
                                    { key: 'scanCompletion', title: 'Scan Completion', desc: 'Notify when scans finish successfully' },
                                    { key: 'weeklyReport', title: 'Weekly Security Report', desc: 'Summary of security status and trends' }
                                ].map(notification => (
                                    <div key={notification.key} className="notification-item">
                                        <div className="notification-info">
                                            <h4>{notification.title}</h4>
                                            <p>{notification.desc}</p>
                                        </div>
                                        <label className="toggle-switch">
                                            <input 
                                                type="checkbox" 
                                                checked={settings.notifications[notification.key]}
                                                onChange={(e) => updateSetting(`notifications.${notification.key}`, e.target.checked)}
                                            />
                                            <span className="toggle-slider"></span>
                                        </label>
                                    </div>
                                ))}
                            </div>

                            <div className="settings-group">
                                <h3>Notification Channels</h3>
                                
                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Email Address</label>
                                        <p>Primary email for notifications</p>
                                    </div>
                                    <div className="setting-control">
                                        <input 
                                            type="email" 
                                            className="form-input" 
                                            value={settings.notifications.email}
                                            onChange={(e) => updateSetting('notifications.email', e.target.value)}
                                        />
                                    </div>
                                </div>

                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Slack Webhook URL</label>
                                        <p>Send notifications to Slack channel</p>
                                    </div>
                                    <div className="setting-control">
                                        <input 
                                            type="url" 
                                            className="form-input" 
                                            value={settings.notifications.slackWebhook}
                                            placeholder="https://hooks.slack.com/services/..."
                                            onChange={(e) => updateSetting('notifications.slackWebhook', e.target.value)}
                                        />
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Advanced Settings */}
                    <div className={`settings-panel ${activeSection === 'advanced' ? 'active' : ''}`}>
                        <div className="panel-header">
                            <h2>Advanced Configuration</h2>
                            <p>Expert settings for advanced users</p>
                        </div>
                        
                        <div className="settings-groups">
                            <div className="settings-group">
                                <h3>System Settings</h3>
                                
                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Debug Mode</label>
                                        <p>Enable detailed logging for troubleshooting</p>
                                    </div>
                                    <div className="setting-control">
                                        <label className="toggle-switch">
                                            <input 
                                                type="checkbox" 
                                                checked={settings.debugMode}
                                                onChange={(e) => updateSetting('debugMode', e.target.checked)}
                                            />
                                            <span className="toggle-slider"></span>
                                        </label>
                                    </div>
                                </div>

                                <div className="setting-item">
                                    <div className="setting-label">
                                        <label>Data Retention</label>
                                        <p>How long to keep scan results (days)</p>
                                    </div>
                                    <div className="setting-control">
                                        <input 
                                            type="number" 
                                            className="form-input" 
                                            value={settings.dataRetention}
                                            min="7" 
                                            max="365"
                                            onChange={(e) => updateSetting('dataRetention', parseInt(e.target.value))}
                                        />
                                    </div>
                                </div>
                            </div>

                            <div className="settings-group danger-zone">
                                <h3>⚠️ Danger Zone</h3>
                                
                                <div className="danger-actions">
                                    <div className="danger-item">
                                        <div className="danger-info">
                                            <h4>Clear All Scan Data</h4>
                                            <p>Permanently delete all scan results and history</p>
                                        </div>
                                        <button className="btn btn-danger" onClick={clearScanData}>
                                            Clear Data
                                        </button>
                                    </div>

                                    <div className="danger-item">
                                        <div className="danger-info">
                                            <h4>Reset Configuration</h4>
                                            <p>Reset all settings to factory defaults</p>
                                        </div>
                                        <button className="btn btn-danger" onClick={resetToDefaults}>
                                            Reset Settings
                                        </button>
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

export default Settings;