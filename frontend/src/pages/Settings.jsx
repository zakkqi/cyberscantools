// frontend/src/pages/Settings.jsx
import React from 'react';
import '../styles/Settings.css';

const Settings = () => {
    return (
<div class="settings-container">
  <div class="page-header">
    <div class="header-content">
      <h1>⚙️ Settings</h1>
      <p>Configure your CyberScan Tools preferences and security settings</p>
    </div>
    <div class="header-actions">
      <button class="btn btn-success">
        <i class="icon-save"></i>
        Save All Changes
      </button>
      <button class="btn btn-outline">
        <i class="icon-refresh-cw"></i>
        Reset to Defaults
      </button>
    </div>
  </div>

  <div class="settings-content">
    <div class="settings-nav">
      <div class="nav-item active" data-section="general">
        <i class="icon-settings"></i>
        <span>General</span>
      </div>
      <div class="nav-item" data-section="scanning">
        <i class="icon-search"></i>
        <span>Scanning</span>
      </div>
      <div class="nav-item" data-section="security">
        <i class="icon-shield"></i>
        <span>Security</span>
      </div>
      <div class="nav-item" data-section="notifications">
        <i class="icon-bell"></i>
        <span>Notifications</span>
      </div>
      <div class="nav-item" data-section="integrations">
        <i class="icon-link"></i>
        <span>Integrations</span>
      </div>
      <div class="nav-item" data-section="advanced">
        <i class="icon-code"></i>
        <span>Advanced</span>
      </div>
    </div>

    <div class="settings-panels">
      
      <div class="settings-panel active" id="general">
        <div class="panel-header">
          <h2>General Settings</h2>
          <p>Basic application preferences and display options</p>
        </div>
        
        <div class="settings-groups">
          <div class="settings-group">
            <h3>Application Preferences</h3>
            
            <div class="setting-item">
              <div class="setting-label">
                <label>Theme</label>
                <p>Choose your preferred color scheme</p>
              </div>
              <div class="setting-control">
                <select class="form-select">
                  <option value="light">Light Theme</option>
                  <option value="dark">Dark Theme</option>
                  <option value="auto">Auto (System)</option>
                </select>
              </div>
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <label>Language</label>
                <p>Select your preferred language</p>
              </div>
              <div class="setting-control">
                <select class="form-select">
                  <option value="en">English</option>
                  <option value="id">Bahasa Indonesia</option>
                  <option value="es">Español</option>
                </select>
              </div>
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <label>Timezone</label>
                <p>Set your local timezone</p>
              </div>
              <div class="setting-control">
                <select class="form-select">
                  <option value="Asia/Jakarta">Asia/Jakarta (WIB)</option>
                  <option value="UTC">UTC</option>
                  <option value="America/New_York">America/New_York (EST)</option>
                </select>
              </div>
            </div>
          </div>

          <div class="settings-group">
            <h3>Dashboard Configuration</h3>
            
            <div class="setting-item">
              <div class="setting-label">
                <label>Auto-refresh Dashboard</label>
                <p>Automatically refresh dashboard data</p>
              </div>
              <div class="setting-control">
                <label class="toggle-switch">
                  <input type="checkbox" checked />
                  <span class="toggle-slider"></span>
                </label>
              </div>
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <label>Refresh Interval</label>
                <p>How often to refresh data (seconds)</p>
              </div>
              <div class="setting-control">
                <input type="number" class="form-input" value="30" min="10" max="300" />
              </div>
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <label>Show Advanced Metrics</label>
                <p>Display detailed technical metrics</p>
              </div>
              <div class="setting-control">
                <label class="toggle-switch">
                  <input type="checkbox" />
                  <span class="toggle-slider"></span>
                </label>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="settings-panel" id="scanning">
        <div class="panel-header">
          <h2>Scanning Configuration</h2>
          <p>Configure default scanning behavior and parameters</p>
        </div>
        
        <div class="settings-groups">
          <div class="settings-group">
            <h3>Default Scan Parameters</h3>
            
            <div class="setting-item">
              <div class="setting-label">
                <label>Scan Timeout (seconds)</label>
                <p>Maximum time to wait for scan completion</p>
              </div>
              <div class="setting-control">
                <input type="number" class="form-input" value="300" min="60" max="3600" />
              </div>
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <label>Concurrent Threads</label>
                <p>Number of parallel scanning threads</p>
              </div>
              <div class="setting-control">
                <input type="number" class="form-input" value="5" min="1" max="20" />
              </div>
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <label>Scan Intensity</label>
                <p>Level of scan thoroughness</p>
              </div>
              <div class="setting-control">
                <select class="form-select">
                  <option value="light">Light (Fast)</option>
                  <option value="normal" selected>Normal</option>
                  <option value="intensive">Intensive (Thorough)</option>
                </select>
              </div>
            </div>
          </div>

          <div class="settings-group">
            <h3>Scanner Modules</h3>
            <p>Enable or disable specific scanning modules</p>
            
            <div class="scanner-modules">
              <div class="module-item">
                <div class="module-info">
                  <div class="module-icon blue">
                    <i class="icon-wifi"></i>
                  </div>
                  <div class="module-details">
                    <h4>Port Scanner</h4>
                    <p>Scan for open network ports</p>
                  </div>
                </div>
                <label class="toggle-switch">
                  <input type="checkbox" checked />
                  <span class="toggle-slider"></span>
                </label>
              </div>

              <div class="module-item">
                <div class="module-info">
                  <div class="module-icon green">
                    <i class="icon-lock"></i>
                  </div>
                  <div class="module-details">
                    <h4>SSL/TLS Scanner</h4>
                    <p>Check SSL certificate security</p>
                  </div>
                </div>
                <label class="toggle-switch">
                  <input type="checkbox" checked />
                  <span class="toggle-slider"></span>
                </label>
              </div>

              <div class="module-item">
                <div class="module-info">
                  <div class="module-icon red">
                    <i class="icon-globe"></i>
                  </div>
                  <div class="module-details">
                    <h4>Web Vulnerability Scanner</h4>
                    <p>OWASP Top 10 vulnerability detection</p>
                  </div>
                </div>
                <label class="toggle-switch">
                  <input type="checkbox" checked />
                  <span class="toggle-slider"></span>
                </label>
              </div>

              <div class="module-item">
                <div class="module-info">
                  <div class="module-icon purple">
                    <i class="icon-search"></i>
                  </div>
                  <div class="module-details">
                    <h4>Subdomain Scanner</h4>
                    <p>Discover subdomains and DNS records</p>
                  </div>
                </div>
                <label class="toggle-switch">
                  <input type="checkbox" checked />
                  <span class="toggle-slider"></span>
                </label>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="settings-panel" id="security">
        <div class="panel-header">
          <h2>Security & Access Control</h2>
          <p>Manage authentication, authorization, and security policies</p>
        </div>
        
        <div class="settings-groups">
          <div class="settings-group">
            <h3>Authentication Settings</h3>
            
            <div class="setting-item">
              <div class="setting-label">
                <label>Two-Factor Authentication</label>
                <p>Add an extra layer of security to your account</p>
              </div>
              <div class="setting-control">
                <button class="btn btn-primary">Enable 2FA</button>
              </div>
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <label>Session Timeout</label>
                <p>Automatically logout after inactivity (minutes)</p>
              </div>
              <div class="setting-control">
                <input type="number" class="form-input" value="60" min="15" max="480" />
              </div>
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <label>Concurrent Sessions</label>
                <p>Maximum number of simultaneous sessions</p>
              </div>
              <div class="setting-control">
                <input type="number" class="form-input" value="3" min="1" max="10" />
              </div>
            </div>
          </div>

          <div class="settings-group">
            <h3>API Security</h3>
            
            <div class="setting-item">
              <div class="setting-label">
                <label>API Access</label>
                <p>Enable API access for external integrations</p>
              </div>
              <div class="setting-control">
                <label class="toggle-switch">
                  <input type="checkbox" checked />
                  <span class="toggle-slider"></span>
                </label>
              </div>
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <label>API Rate Limit</label>
                <p>Maximum API requests per hour</p>
              </div>
              <div class="setting-control">
                <input type="number" class="form-input" value="1000" min="100" max="10000" />
              </div>
            </div>

            <div class="api-keys">
              <h4>API Keys</h4>
              <div class="api-key-item">
                <div class="key-info">
                  <code>sk_live_4f6a7b8c9d0e1f2g3h4i5j6k</code>
                  <span class="key-status active">Active</span>
                </div>
                <div class="key-actions">
                  <button class="btn btn-sm btn-outline">Regenerate</button>
                  <button class="btn btn-sm btn-danger">Revoke</button>
                </div>
              </div>
              <button class="btn btn-outline">Generate New API Key</button>
            </div>
          </div>
        </div>
      </div>

      <div class="settings-panel" id="notifications">
        <div class="panel-header">
          <h2>Notification Settings</h2>
          <p>Configure alerts and notification preferences</p>
        </div>
        
        <div class="settings-groups">
          <div class="settings-group">
            <h3>Email Notifications</h3>
            
            <div class="notification-item">
              <div class="notification-info">
                <h4>High Severity Vulnerabilities</h4>
                <p>Immediate alerts for critical security issues</p>
              </div>
              <label class="toggle-switch">
                <input type="checkbox" checked />
                <span class="toggle-slider"></span>
              </label>
            </div>

            <div class="notification-item">
              <div class="notification-info">
                <h4>Scan Completion</h4>
                <p>Notify when scans finish successfully</p>
              </div>
              <label class="toggle-switch">
                <input type="checkbox" checked />
                <span class="toggle-slider"></span>
              </label>
            </div>

            <div class="notification-item">
              <div class="notification-info">
                <h4>Weekly Security Report</h4>
                <p>Summary of security status and trends</p>
              </div>
              <label class="toggle-switch">
                <input type="checkbox" />
                <span class="toggle-slider"></span>
              </label>
            </div>
          </div>

          <div class="settings-group">
            <h3>Notification Channels</h3>
            
            <div class="setting-item">
              <div class="setting-label">
                <label>Email Address</label>
                <p>Primary email for notifications</p>
              </div>
              <div class="setting-control">
                <input type="email" class="form-input" value="user@example.com" />
              </div>
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <label>Slack Webhook URL</label>
                <p>Send notifications to Slack channel</p>
              </div>
              <div class="setting-control">
                <input type="url" class="form-input" placeholder="https://hooks.slack.com/services/..." />
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="settings-panel" id="advanced">
        <div class="panel-header">
          <h2>Advanced Configuration</h2>
          <p>Expert settings for advanced users</p>
        </div>
        
        <div class="settings-groups">
          <div class="settings-group">
            <h3>System Settings</h3>
            
            <div class="setting-item">
              <div class="setting-label">
                <label>Debug Mode</label>
                <p>Enable detailed logging for troubleshooting</p>
              </div>
              <div class="setting-control">
                <label class="toggle-switch">
                  <input type="checkbox" />
                  <span class="toggle-slider"></span>
                </label>
              </div>
            </div>

            <div class="setting-item">
              <div class="setting-label">
                <label>Data Retention</label>
                <p>How long to keep scan results (days)</p>
              </div>
              <div class="setting-control">
                <input type="number" class="form-input" value="90" min="7" max="365" />
              </div>
            </div>
          </div>

          <div class="settings-group danger-zone">
            <h3>⚠️ Danger Zone</h3>
            
            <div class="danger-actions">
              <div class="danger-item">
                <div class="danger-info">
                  <h4>Clear All Scan Data</h4>
                  <p>Permanently delete all scan results and history</p>
                </div>
                <button class="btn btn-danger">Clear Data</button>
              </div>

              <div class="danger-item">
                <div class="danger-info">
                  <h4>Reset Configuration</h4>
                  <p>Reset all settings to factory defaults</p>
                </div>
                <button class="btn btn-danger">Reset Settings</button>
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