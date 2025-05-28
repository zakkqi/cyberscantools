// frontend/src/pages/VirusTotalPage.jsx
import React from 'react';
import { Typography, Card } from 'antd';
import VirusTotalScanner from '../components/scanners/VirusTotalScanner';
import '../styles/VirusTotalScanner.css';

const { Title } = Typography;

const VirusTotalPage = () => {
  return (
    <div className="virustotal-page">
      <div className="page-header">
        <Title level={2}>VirusTotal Scanner</Title>
        <p className="page-description">
          Gunakan VirusTotal untuk memeriksa file dan URL mencurigakan menggunakan lebih dari 70 mesin anti-virus.
        </p>
      </div>
      
      <VirusTotalScanner />
    </div>
  );
};

export default VirusTotalPage;