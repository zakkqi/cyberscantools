// frontend/src/components/Sidebar.jsx
import React from 'react';
import { NavLink } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { logout } from '../store/authSlice';
import { 
    FaHome, 
    FaSearch, 
    FaHistory, 
    FaChartBar, 
    FaCog,
    FaSignOutAlt 
} from 'react-icons/fa';

const Sidebar = () => {
    const dispatch = useDispatch();
    
    const handleLogout = () => {
        dispatch(logout());
    };
    
    return (
        <div className="sidebar">
            <div className="logo-container">
                <div className="logo">
                    <span className="logo-icon">🛡️</span>
                    <h2>CyberScan Tools</h2>
                </div>
            </div>
            
            <nav className="sidebar-nav">
                <ul>
                    <li>
                        <NavLink to="/dashboard" className={({isActive}) => isActive ? 'active' : ''}>
                            <FaHome />
                            <span>Dashboard</span>
                        </NavLink>
                    </li>
                    <li>
                        <NavLink to="/new-scan" className={({isActive}) => isActive ? 'active' : ''}>
                            <FaSearch />
                            <span>New Scan</span>
                        </NavLink>
                    </li>
                    <li>
                        <NavLink to="/scan-history" className={({isActive}) => isActive ? 'active' : ''}>
                            <FaHistory />
                            <span>Scan History</span>
                        </NavLink>
                    </li>
                    <li>
                        <NavLink to="/reports" className={({isActive}) => isActive ? 'active' : ''}>
                            <FaChartBar />
                            <span>Reports</span>
                        </NavLink>
                    </li>
                    <li>
                        <NavLink to="/settings" className={({isActive}) => isActive ? 'active' : ''}>
                            <FaCog />
                            <span>Settings</span>
                        </NavLink>
                    </li>
                </ul>
            </nav>
            
            <div className="sidebar-footer">
                <button className="logout-button" onClick={handleLogout}>
                    <FaSignOutAlt />
                    <span>Logout</span>
                </button>
            </div>
        </div>
    );
};

export default Sidebar;