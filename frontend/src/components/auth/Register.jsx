// frontend/src/components/auth/Register.jsx
import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { registerUser } from '../../store/authSlice';
import '../../styles/Auth.css';

const Register = () => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    first_name: '',
    last_name: '',
    acceptTerms: false
  });
  const [passwordError, setPasswordError] = useState('');
  const [passwordStrength, setPasswordStrength] = useState('');
  
  const dispatch = useDispatch();
  const navigate = useNavigate();
  
  const { loading, error, isAuthenticated } = useSelector(state => state.auth);
  
  // Redirect if already logged in
  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard', { replace: true });
    }
  }, [isAuthenticated, navigate]);
  
  // Password strength checker
  const checkPasswordStrength = (password) => {
    if (password.length === 0) return '';
    if (password.length < 6) return 'Very Weak';
    if (password.length < 8) return 'Weak';
    
    let score = 0;
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^a-zA-Z0-9]/.test(password)) score++;
    
    if (score < 2) return 'Weak';
    if (score < 3) return 'Medium';
    if (score < 4) return 'Strong';
    return 'Very Strong';
  };
  
  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    
    setFormData({
      ...formData,
      [name]: type === 'checkbox' ? checked : value
    });
    
    // Clear password error when typing
    if (name === 'password' || name === 'confirmPassword') {
      setPasswordError('');
    }
    
    // Check password strength
    if (name === 'password') {
      setPasswordStrength(checkPasswordStrength(value));
    }
  };
  
  const validateForm = () => {
    // Password validation
    if (formData.password !== formData.confirmPassword) {
      setPasswordError('Passwords do not match');
      return false;
    }
    
    if (formData.password.length < 8) {
      setPasswordError('Password must be at least 8 characters long');
      return false;
    }
    
    if (!formData.acceptTerms) {
      setPasswordError('You must accept the terms and conditions');
      return false;
    }
    
    return true;
  };
  
  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (!validateForm()) return;
    
    // Register user (without confirmPassword and acceptTerms)
    const { confirmPassword, acceptTerms, ...userData } = formData;
    dispatch(registerUser(userData));
  };
  
  const getPasswordStrengthColor = () => {
    switch (passwordStrength) {
      case 'Very Weak': return '#ef4444';
      case 'Weak': return '#f59e0b';
      case 'Medium': return '#3b82f6';
      case 'Strong': return '#10b981';
      case 'Very Strong': return '#059669';
      default: return '#9ca3af';
    }
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
          </div>
        </div>
        
        {/* Registration Card */}
        <div className="auth-card register">
          <div className="auth-header">
            <h2>Create Your Account</h2>
            <p>Join CyberScan Tools to start securing your applications with advanced scanning capabilities</p>
          </div>
          
          {(error || passwordError) && (
            <div className="auth-error">
              {passwordError || error}
            </div>
          )}
          
          <form onSubmit={handleSubmit} className="auth-form">
            {/* Name Fields */}
            <div className="form-row">
              <div className="form-group">
                <label htmlFor="first_name">First Name</label>
                <div className="input-with-icon">
                  <input
                    type="text"
                    id="first_name"
                    name="first_name"
                    value={formData.first_name}
                    onChange={handleChange}
                    placeholder="Enter your first name"
                    disabled={loading}
                  />
                  <span className="icon">👤</span>
                </div>
              </div>
              
              <div className="form-group">
                <label htmlFor="last_name">Last Name</label>
                <div className="input-with-icon">
                  <input
                    type="text"
                    id="last_name"
                    name="last_name"
                    value={formData.last_name}
                    onChange={handleChange}
                    placeholder="Enter your last name"
                    disabled={loading}
                  />
                  <span className="icon">👤</span>
                </div>
              </div>
            </div>
            
            {/* Username Field */}
            <div className="form-group">
              <label htmlFor="username">Username *</label>
              <div className="input-with-icon">
                <input
                  type="text"
                  id="username"
                  name="username"
                  value={formData.username}
                  onChange={handleChange}
                  placeholder="Choose a unique username"
                  required
                  disabled={loading}
                  minLength="3"
                />
                <span className="icon">@</span>
              </div>
            </div>
            
            {/* Email Field */}
            <div className="form-group">
              <label htmlFor="email">Email Address *</label>
              <div className="input-with-icon">
                <input
                  type="email"
                  id="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  placeholder="Enter your email address"
                  required
                  disabled={loading}
                />
                <span className="icon">📧</span>
              </div>
            </div>
            
            {/* Password Field */}
            <div className="form-group">
              <label htmlFor="password">Password *</label>
              <div className="input-with-icon">
                <input
                  type="password"
                  id="password"
                  name="password"
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="Create a strong password"
                  required
                  disabled={loading}
                  minLength="8"
                />
                <span className="icon">🔒</span>
              </div>
              {formData.password && (
                <div className="password-requirements">
                  <div style={{ 
                    display: 'flex', 
                    justifyContent: 'space-between', 
                    alignItems: 'center',
                    marginBottom: '4px'
                  }}>
                    <span>Password Strength:</span>
                    <span style={{ 
                      color: getPasswordStrengthColor(),
                      fontWeight: 'bold'
                    }}>
                      {passwordStrength}
                    </span>
                  </div>
                  <div style={{
                    height: '4px',
                    backgroundColor: '#e5e7eb',
                    borderRadius: '2px',
                    overflow: 'hidden',
                    marginBottom: '8px'
                  }}>
                    <div style={{
                      height: '100%',
                      backgroundColor: getPasswordStrengthColor(),
                      width: passwordStrength === 'Very Weak' ? '20%' :
                             passwordStrength === 'Weak' ? '40%' :
                             passwordStrength === 'Medium' ? '60%' :
                             passwordStrength === 'Strong' ? '80%' :
                             passwordStrength === 'Very Strong' ? '100%' : '0%',
                      transition: 'width 0.3s ease'
                    }}></div>
                  </div>
                  <small>
                    Password must contain at least 8 characters with uppercase, lowercase, numbers, and special characters
                  </small>
                </div>
              )}
            </div>
            
            {/* Confirm Password Field */}
            <div className="form-group">
              <label htmlFor="confirmPassword">Confirm Password *</label>
              <div className="input-with-icon">
                <input
                  type="password"
                  id="confirmPassword"
                  name="confirmPassword"
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  placeholder="Confirm your password"
                  required
                  disabled={loading}
                />
                <span className="icon">🔐</span>
              </div>
              {formData.confirmPassword && formData.password !== formData.confirmPassword && (
                <div style={{ color: '#ef4444', fontSize: '0.75rem', marginTop: '0.25rem' }}>
                  Passwords do not match
                </div>
              )}
              {formData.confirmPassword && formData.password === formData.confirmPassword && formData.password.length > 0 && (
                <div style={{ color: '#10b981', fontSize: '0.75rem', marginTop: '0.25rem' }}>
                  ✓ Passwords match
                </div>
              )}
            </div>
            
            {/* Terms and Conditions */}
            <div className="terms-checkbox">
              <input
                type="checkbox"
                id="acceptTerms"
                name="acceptTerms"
                checked={formData.acceptTerms}
                onChange={handleChange}
                required
                disabled={loading}
              />
              <label htmlFor="acceptTerms">
                I agree to the{' '}
                <Link to="/terms" target="_blank">Terms of Service</Link>
                {' '}and{' '}
                <Link to="/privacy" target="_blank">Privacy Policy</Link>
              </label>
            </div>
            
            {/* Submit Button */}
            <button 
              type="submit" 
              className="auth-button"
              disabled={loading || !formData.acceptTerms}
            >
              {loading && <span className="spinner"></span>}
              {loading ? 'Creating Account...' : 'Create Account'}
            </button>
          </form>
          
          {/* Footer */}
          <div className="auth-footer">
            Already have an account?{' '}
            <Link to="/login">Sign in to your account</Link>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Register;