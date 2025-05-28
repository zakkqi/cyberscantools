// frontend/src/components/layout/Logo.jsx
import React from 'react';

const Logo = () => {
    return (
        <div className="logo">
            <svg width="48" height="48" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M24 4C12.96 4 4 12.96 4 24C4 35.04 12.96 44 24 44C35.04 44 44 35.04 44 24C44 12.96 35.04 4 24 4ZM24 40C15.18 40 8 32.82 8 24C8 15.18 15.18 8 24 8C32.82 8 40 15.18 40 24C40 32.82 32.82 40 24 40Z" fill="#3182CE"/>
                <path d="M24 12C17.4 12 12 17.4 12 24C12 30.6 17.4 36 24 36C30.6 36 36 30.6 36 24C36 17.4 30.6 12 24 12ZM24 32C19.6 32 16 28.4 16 24C16 19.6 19.6 16 24 16C28.4 16 32 19.6 32 24C32 28.4 28.4 32 24 32Z" fill="#4299E1"/>
                <path d="M24 20C22.9 20 22 20.9 22 22V30C22 31.1 22.9 32 24 32C25.1 32 26 31.1 26 30V22C26 20.9 25.1 20 24 20Z" fill="#2B6CB0"/>
                <path d="M24 16C22.9 16 22 16.9 22 18C22 19.1 22.9 20 24 20C25.1 20 26 19.1 26 18C26 16.9 25.1 16 24 16Z" fill="#2B6CB0"/>
            </svg>
        </div>
    );
};

export default Logo;