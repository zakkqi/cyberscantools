// frontend/src/components/auth/Login.jsx
import React, { useState, useEffect } from 'react';
import { useNavigate, Link, useLocation } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { loginUser } from '../../store/authSlice';
import '../../styles/Auth.css';

const Login = () => {
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    rememberMe: false
  });
  const [showPassword, setShowPassword] = useState(false);
 
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const location = useLocation();
 
  const { loading, error, isAuthenticated } = useSelector(state => state.auth);
 
  // Redirect if already logged in
  useEffect(() => {
    if (isAuthenticated) {
      // Redirect to the page they were trying to access or dashboard
      const from = location.state?.from?.pathname || '/dashboard';
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, navigate, location]);
 
  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData({
      ...formData,
      [name]: type === 'checkbox' ? checked : value
    });
  };
 
  const handleSubmit = (e) => {
    e.preventDefault();
    const { rememberMe, ...loginData } = formData;
    dispatch(loginUser(loginData));
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };
 
  return (
    <div className="auth-page">
      <div className="auth-container">
        {/* Brand Section */}
        <div className="auth-brand">
          <div className="brand-logo">
            <h1>🔒 CyberScan</h1>
          </div>
          <div className="tagline">
            Advanced Security Scanner Tools for Modern Applications
          </div>
          <div className="features">
            <div className="feature-item">
              <span className="feature-icon">🛡️</span>
              <span>Comprehensive Vulnerability Assessment</span>
            </div>
            <div className="feature-item">
              <span className="feature-icon">🔍</span>
              <span>Multi-Layer Security Scanning</span>
            </div>
            <div className="feature-item">
              <span className="feature-icon">📊</span>
              <span>Real-time Security Analytics</span>
            </div>
            <div className="feature-item">
              <span className="feature-icon">⚡</span>
              <span>Automated Threat Detection</span>
            </div>
            <div className="feature-item">
              <span className="feature-icon">🔐</span>
              <span>Enterprise-Grade Security</span>
            </div>
          </div>
        </div>
        
        {/* Login Card */}
        <div className="auth-card">
          <div className="auth-header">
            <h2>Welcome Back</h2>
            <p>Sign in to your CyberScan Tools account to continue your security journey</p>
          </div>
         
          {error && (
            <div className="auth-error">
              {error}
            </div>
          )}
         
          <form onSubmit={handleSubmit} className="auth-form">
            {/* Username/Email Field */}
            <div className="form-group">
              <label htmlFor="username">Username or Email *</label>
              <div className="input-with-icon">
                <input
                  type="text"
                  id="username"
                  name="username"
                  value={formData.username}
                  onChange={handleChange}
                  placeholder="Enter your username or email"
                  required
                  disabled={loading}
                  autoComplete="username"
                />
                <span className="icon">👤</span>
              </div>
            </div>
           
            {/* Password Field */}
            <div className="form-group">
              <label htmlFor="password">Password *</label>
              <div className="input-with-icon">
                <input
                  type={showPassword ? 'text' : 'password'}
                  id="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="Enter your password"
                  required
                  disabled={loading}
                  autoComplete="current-password"
                />
                <span className="icon">🔒</span>
                <button
                  type="button"
                  onClick={togglePasswordVisibility}
                  style={{
                    position: 'absolute',
                    right: '12px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    fontSize: '14px',
                    color: '#6b7280',
                    zIndex: 1
                  }}
                  disabled={loading}
                >
                  {showPassword ? '👁️' : '👁️‍🗨️'}
                </button>
              </div>
            </div>
            
            {/* Form Options */}
            <div className="form-options">
              <div className="checkbox-wrapper">
                <input
                  type="checkbox"
                  id="rememberMe"
                  name="rememberMe"
                  checked={formData.rememberMe}
                  onChange={handleChange}
                  disabled={loading}
                />
                <label htmlFor="rememberMe">Remember me</label>
              </div>
              
              <Link to="/forgot-password" className="forgot-password">
                Forgot password?
              </Link>
            </div>
            
            {/* Submit Button */}
            <button
              type="submit"
              className="auth-button"
              disabled={loading}
            >
              {loading && <span className="spinner"></span>}
              {loading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>
          
          {/* Divider */}
          <div style={{
            display: 'flex',
            alignItems: 'center',
            margin: '24px 0',
            fontSize: '14px',
            color: '#6b7280'
          }}>
            <hr style={{ flex: 1, border: 'none', borderTop: '1px solid #e5e7eb' }} />
            <span style={{ padding: '0 16px' }}>or</span>
            <hr style={{ flex: 1, border: 'none', borderTop: '1px solid #e5e7eb' }} />
          </div>
          
          {/* Demo Account Info */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(79, 70, 229, 0.05) 0%, rgba(79, 70, 229, 0.1) 100%)',
            padding: '16px',
            borderRadius: '12px',
            border: '1px solid rgba(79, 70, 229, 0.1)',
            marginBottom: '24px'
          }}>
            <div style={{ 
              fontSize: '14px', 
              fontWeight: '600', 
              color: '#4f46e5',
              marginBottom: '8px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px'
            }}>
              🚀 Demo Account
            </div>
            <div style={{ fontSize: '13px', color: '#6b7280', lineHeight: '1.5' }}>
              <strong>Username:</strong> demo<br />
              <strong>Password:</strong> demo123<br />
              <em>Try our platform with full access to all features</em>
            </div>
          </div>
         
          {/* Footer */}
          <div className="auth-footer">
            Don't have an account?{' '}
            <Link to="/register">Create your account</Link>
          </div>
          
          {/* Additional Links */}
          <div style={{
            textAlign: 'center',
            marginTop: '16px',
            fontSize: '12px',
            color: '#9ca3af'
          }}>
            <Link 
              to="/help" 
              style={{ 
                color: '#6b7280', 
                textDecoration: 'none',
                marginRight: '16px'
              }}
            >
              Need Help?
            </Link>
            <Link 
              to="/contact" 
              style={{ 
                color: '#6b7280', 
                textDecoration: 'none' 
              }}
            >
              Contact Support
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;