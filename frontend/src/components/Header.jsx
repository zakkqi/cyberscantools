// frontend/src/components/Header.jsx
import React from 'react';
import { useDispatch, useSelector } from 'react-redux';
import { useNavigate } from 'react-router-dom';
import { logout } from '../store/authSlice';

const Header = () => {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const { user } = useSelector(state => state.auth);
    
    const handleLogout = () => {
        dispatch(logout());
        navigate('/login');
    };
    
    return (
        <header className="app-header">
            <div className="header-title">
                <h1>CyberScan Tools</h1>
            </div>
            
            <div className="header-actions">
                {/* Tambahkan tombol atau fitur lain di sini */}
                
                <div className="user-dropdown">
                    <div className="user-info">
                        <span className="user-avatar">
                            {user?.first_name?.[0] || user?.username?.[0] || '👤'}
                        </span>
                        <span className="user-name">{user?.username || 'User'}</span>
                        <span className="dropdown-icon">▼</span>
                    </div>
                    
                    <div className="dropdown-menu">
                        <a href="/settings" className="dropdown-item">Settings</a>
                        <a href="/profile" className="dropdown-item">Profile</a>
                        <div className="dropdown-divider"></div>
                        <button 
                            className="dropdown-item logout-button" 
                            onClick={handleLogout}
                        >
                            Logout
                        </button>
                    </div>
                </div>
            </div>
        </header>
    );
};

export default Header;