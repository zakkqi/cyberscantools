// frontend/src/components/layout/Layout.jsx
import React from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from '../Sidebar';
import Header from '../Header';

const Layout = () => {
    return (
        <div className="app-container">
            <Sidebar />
            <div className="main-content">
                <Header />
                <main className="main-outlet">
                    <Outlet />
                </main>
            </div>
        </div>
    );
};

export default Layout;