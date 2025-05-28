// frontend/src/pages/Register.jsx
import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { registerUser } from '../store/authSlice';
import Logo from '../components/layout/Logo';
import '../styles/Auth.css';

const Register = () => {
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        password: '',
        confirmPassword: '',
        first_name: '',
        last_name: ''
    });
    const [passwordError, setPasswordError] = useState('');
    const [agreeToTerms, setAgreeToTerms] = useState(false);
    
    const navigate = useNavigate();
    const dispatch = useDispatch();
    const { loading, error, isAuthenticated } = useSelector(state => state.auth);
    
    useEffect(() => {
        // Redirect if already logged in
        if (isAuthenticated) {
            navigate('/dashboard');
        }
    }, [isAuthenticated, navigate]);
    
    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
        
        // Clear password error when typing
        if (e.target.name === 'password' || e.target.name === 'confirmPassword') {
            setPasswordError('');
        }
    };
    
    const validatePassword = () => {
        if (formData.password !== formData.confirmPassword) {
            setPasswordError('Passwords do not match');
            return false;
        }
        
        if (formData.password.length < 8) {
            setPasswordError('Password must be at least 8 characters long');
            return false;
        }
        
        return true;
    };
    
    const handleSubmit = (e) => {
        e.preventDefault();
        
        // Validate passwords
        if (!validatePassword()) {
            return;
        }
        
        // Validate terms agreement
        if (!agreeToTerms) {
            setPasswordError('You must agree to the terms and conditions');
            return;
        }
        
        // Register user (without confirmPassword)
        const { confirmPassword, ...userData } = formData;
        dispatch(registerUser(userData));
    };
    
    return (
        <div className="auth-page">
            <div className="auth-container">
                <div className="auth-brand">
                    <Logo />
                    <h1>CyberScan Tools</h1>
                    <p className="tagline">Advanced Security Scanning Platform</p>
                </div>
                
                <div className="auth-card register">
                    <div className="auth-header">
                        <h2>Create Account</h2>
                        <p>Join CyberScan Tools to secure your applications</p>
                    </div>
                    
                    {(error || passwordError) && (
                        <div className="auth-error">
                            <span className="error-icon">⚠️</span>
                            <span>{passwordError || error}</span>
                        </div>
                    )}
                    
                    <form onSubmit={handleSubmit} className="auth-form">
                        <div className="form-row">
                            <div className="form-group">
                                <label htmlFor="first_name">First Name</label>
                                <input
                                    type="text"
                                    id="first_name"
                                    name="first_name"
                                    placeholder="First name"
                                    value={formData.first_name}
                                    onChange={handleChange}
                                />
                            </div>
                            
                            <div className="form-group">
                                <label htmlFor="last_name">Last Name</label>
                                <input
                                    type="text"
                                    id="last_name"
                                    name="last_name"
                                    placeholder="Last name"
                                    value={formData.last_name}
                                    onChange={handleChange}
                                />
                            </div>
                        </div>
                        
                        <div className="form-group">
                            <label htmlFor="username">Username</label>
                            <input
                                type="text"
                                id="username"
                                name="username"
                                placeholder="Choose a username"
                                value={formData.username}
                                onChange={handleChange}
                                required
                            />
                        </div>
                        
                        <div className="form-group">
                            <label htmlFor="email">Email</label>
                            <input
                                type="email"
                                id="email"
                                name="email"
                                placeholder="Your email address"
                                value={formData.email}
                                onChange={handleChange}
                                required
                            />
                        </div>
                        
                        <div className="form-group">
                            <label htmlFor="password">Password</label>
                            <input
                                type="password"
                                id="password"
                                name="password"
                                placeholder="Create a password"
                                value={formData.password}
                                onChange={handleChange}
                                required
                                minLength="8"
                            />
                            <div className="password-requirements">
                                Must be at least 8 characters
                            </div>
                        </div>
                        
                        <div className="form-group">
                            <label htmlFor="confirmPassword">Confirm Password</label>
                            <input
                                type="password"
                                id="confirmPassword"
                                name="confirmPassword"
                                placeholder="Confirm your password"
                                value={formData.confirmPassword}
                                onChange={handleChange}
                                required
                            />
                        </div>
                        
                        <div className="form-group terms-checkbox">
                            <input
                                type="checkbox"
                                id="terms"
                                checked={agreeToTerms}
                                onChange={() => setAgreeToTerms(!agreeToTerms)}
                            />
                            <label htmlFor="terms">
                                I agree to the <Link to="/terms">Terms of Service</Link> and <Link to="/privacy">Privacy Policy</Link>
                            </label>
                        </div>
                        
                        <button 
                            type="submit" 
                            className="auth-button"
                            disabled={loading}
                        >
                            {loading ? (
                                <>
                                    <span className="spinner"></span>
                                    Creating Account...
                                </>
                            ) : (
                                'Create Account'
                            )}
                        </button>
                    </form>
                    
                    <div className="auth-footer">
                        Already have an account? <Link to="/login">Sign in</Link>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Register;