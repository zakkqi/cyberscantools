// frontend/src/pages/Login.jsx
import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useDispatch, useSelector } from 'react-redux';
import { loginUser } from '../store/authSlice';
import Logo from '../components/layout/Logo';
import '../styles/Auth.css';

const Login = () => {
    const [credentials, setCredentials] = useState({
        username: '',
        password: ''
    });
    const [rememberMe, setRememberMe] = useState(false);
    
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
        setCredentials({
            ...credentials,
            [e.target.name]: e.target.value
        });
    };
    
    const handleSubmit = (e) => {
        e.preventDefault();
        dispatch(loginUser(credentials));
    };
    
    return (
        <div className="auth-page">
            <div className="auth-container">
                <div className="auth-brand">
                    <Logo />
                    <h1>CyberScan Tools</h1>
                    <p className="tagline">Advanced Security Scanning Platform</p>
                </div>
                
                <div className="auth-card">
                    <div className="auth-header">
                        <h2>Log In</h2>
                        <p>Welcome back! Please enter your credentials to access your account.</p>
                    </div>
                    
                    {error && (
                        <div className="auth-error">
                            <span className="error-icon">⚠️</span>
                            <span>{error}</span>
                        </div>
                    )}
                    
                    <form onSubmit={handleSubmit} className="auth-form">
                        <div className="form-group">
                            <label htmlFor="username">Username or Email</label>
                            <div className="input-with-icon">
                                <i className="icon user-icon">👤</i>
                                <input
                                    type="text"
                                    id="username"
                                    name="username"
                                    placeholder="Enter your username or email"
                                    value={credentials.username}
                                    onChange={handleChange}
                                    required
                                />
                            </div>
                        </div>
                        
                        <div className="form-group">
                            <label htmlFor="password">Password</label>
                            <div className="input-with-icon">
                                <i className="icon password-icon">🔒</i>
                                <input
                                    type="password"
                                    id="password"
                                    name="password"
                                    placeholder="Enter your password"
                                    value={credentials.password}
                                    onChange={handleChange}
                                    required
                                />
                            </div>
                        </div>
                        
                        <div className="form-options">
                            <div className="checkbox-wrapper">
                                <input
                                    type="checkbox"
                                    id="remember-me"
                                    checked={rememberMe}
                                    onChange={() => setRememberMe(!rememberMe)}
                                />
                                <label htmlFor="remember-me">Remember me</label>
                            </div>
                            <Link to="/forgot-password" className="forgot-password">
                                Forgot password?
                            </Link>
                        </div>
                        
                        <button 
                            type="submit" 
                            className="auth-button"
                            disabled={loading}
                        >
                            {loading ? (
                                <>
                                    <span className="spinner"></span>
                                    Logging in...
                                </>
                            ) : (
                                'Log In'
                            )}
                        </button>
                    </form>
                    
                    <div className="auth-footer">
                        Don't have an account? <Link to="/register">Sign up</Link>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default Login;