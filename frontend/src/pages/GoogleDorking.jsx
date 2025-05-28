// frontend/src/pages/GoogleDorking.jsx
import React, { useState } from 'react';
import { Card, Row, Col, Spin, Alert } from 'antd';
import { SearchOutlined, EyeOutlined, DownloadOutlined } from '@ant-design/icons';
import GoogleDorkingScanner from '../components/scanners/GoogleDorkingScanner';
import GoogleDorkingResults from '../components/scanners/GoogleDorkingResults';
import { useScannerIntegration } from '../hooks/useScannerIntegration';
import '../styles/GoogleDorkingScanner.css';

const GoogleDorking = () => {
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [target, setTarget] = useState('');

  // Use scanner integration hook
  const { handleGoogleDorkingScanComplete } = useScannerIntegration();

  const handleScanComplete = (scanResults) => {
    console.log('Google Dorking scan completed:', scanResults);
    
    // Set results for display
    setResults(scanResults);
    setLoading(false);
    setError(null);
    
    // Save to history using the integration hook
    const standardizedResult = {
      scannerType: 'google_dorking',
      target: scanResults.target || target,
      status: 'completed',
      timestamp: new Date().toISOString(),
      results: scanResults.results || scanResults,
      summary: {
        total_found: scanResults.results?.length || 0,
        dorks_used: scanResults.dorks_used || 0,
        unique_domains: getUniqueDomains(scanResults.results || [])
      },
      metadata: {
        scan_type: 'google_dorking',
        total_dorks: scanResults.total_dorks || 0
      }
    };
    
    handleGoogleDorkingScanComplete(standardizedResult);
  };

  const handleScanStart = (scanTarget) => {
    console.log('Google Dorking scan started for:', scanTarget);
    setLoading(true);
    setResults(null);
    setError(null);
    setTarget(scanTarget);
  };

  const handleScanError = (errorMessage) => {
    console.error('Google Dorking scan failed:', errorMessage);
    setError(errorMessage);
    setLoading(false);
    
    // Save failed scan to history
    const failedResult = {
      scannerType: 'google_dorking',
      target: target,
      status: 'failed',
      timestamp: new Date().toISOString(),
      error: errorMessage,
      results: [],
      summary: {
        total_found: 0,
        dorks_used: 0,
        unique_domains: 0
      }
    };
    
    handleGoogleDorkingScanComplete(failedResult);
  };

  // Helper function to count unique domains
  const getUniqueDomains = (results) => {
    if (!Array.isArray(results)) return 0;
    
    const domains = new Set();
    results.forEach(result => {
      try {
        const url = new URL(result.link || result.url || '');
        domains.add(url.hostname);
      } catch (e) {
        // Invalid URL, skip
      }
    });
    
    return domains.size;
  };

  return (
    <div className="google-dorking-page" style={{ padding: '24px' }}>
      <Row gutter={[24, 24]}>
        <Col span={24}>
          <Card
            title={
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <SearchOutlined style={{ color: '#1890ff' }} />
                Google Dorking Scanner
              </div>
            }
            extra={
              <div style={{ fontSize: '14px', color: '#666' }}>
                Advanced Google search techniques for information gathering
              </div>
            }
          >
            <GoogleDorkingScanner
              onScanStart={handleScanStart}
              onScanComplete={handleScanComplete}
              onScanError={handleScanError}
              loading={loading}
            />
          </Card>
        </Col>

        {error && (
          <Col span={24}>
            <Alert
              message="Scan Error"
              description={error}
              type="error"
              showIcon
              closable
              onClose={() => setError(null)}
            />
          </Col>
        )}

        {loading && (
          <Col span={24}>
            <Card>
              <div style={{ textAlign: 'center', padding: '40px' }}>
                <Spin size="large" />
                <div style={{ marginTop: '16px', fontSize: '16px', color: '#666' }}>
                  Performing Google dorking scan for <strong>{target}</strong>...
                </div>
                <div style={{ marginTop: '8px', fontSize: '14px', color: '#999' }}>
                  This may take a few minutes
                </div>
              </div>
            </Card>
          </Col>
        )}

        {results && results.results && results.results.length > 0 && (
          <Col span={24}>
            <Card
              title={
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <EyeOutlined style={{ color: '#52c41a' }} />
                  Scan Results
                </div>
              }
              extra={
                <div style={{ fontSize: '14px', color: '#666' }}>
                  Found {results.results.length} results
                </div>
              }
            >
              <GoogleDorkingResults 
                results={results.results} 
                target={results.target || target}
              />
            </Card>
          </Col>
        )}

        {results && (!results.results || results.results.length === 0) && !loading && (
          <Col span={24}>
            <Card>
              <div style={{ textAlign: 'center', padding: '40px' }}>
                <SearchOutlined style={{ fontSize: '48px', color: '#d9d9d9' }} />
                <div style={{ marginTop: '16px', fontSize: '16px', color: '#666' }}>
                  No results found for <strong>{target}</strong>
                </div>
                <div style={{ marginTop: '8px', fontSize: '14px', color: '#999' }}>
                  Try adjusting your search terms or dorks
                </div>
              </div>
            </Card>
          </Col>
        )}
      </Row>
    </div>
  );
};

export default GoogleDorking;