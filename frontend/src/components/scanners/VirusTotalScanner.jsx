// frontend/src/components/scanners/VirusTotalScanner.jsx 
import React, { useState, useEffect } from 'react';
import { 
  Button, Form, Input, Upload, message, Card, Spin, Alert, 
  Progress, Space, Tag, Tooltip, Row, Col, Divider, Typography 
} from 'antd';
import { 
  UploadOutlined, LinkOutlined, SafetyOutlined, 
  FileTextOutlined, GlobalOutlined, ReloadOutlined, SearchOutlined,
  InfoCircleOutlined, CloudUploadOutlined, ScanOutlined, ArrowLeftOutlined
} from '@ant-design/icons';

// Import API utility
import api from '../../utils/api';

// Import history service
import { historyService } from '../../services/historyService';

// Import the VirusTotal-style results component
import VirusTotalResults from './VirusTotalResults';

// Import CSS
import '../../styles/VirusTotalScanner.css';

const { Title, Paragraph, Text } = Typography;

const VirusTotalScanner = ({ onBack }) => {
  const [form] = Form.useForm();
  
  // State management
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [activeTab, setActiveTab] = useState('file');
  const [fileList, setFileList] = useState([]);
  const [analysisId, setAnalysisId] = useState(null);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [target, setTarget] = useState(null);
  const [pollingInterval, setPollingInterval] = useState(null);
  const [progress, setProgress] = useState(0);
  const [startTime, setStartTime] = useState(null);
  const [searchType, setSearchType] = useState(null);

  // Cleanup pada unmount
  useEffect(() => {
    return () => {
      if (pollingInterval) {
        clearInterval(pollingInterval);
      }
    };
  }, [pollingInterval]);

  // Mulai polling ketika mendapatkan analysisId
  useEffect(() => {
    if (analysisId && scanning) {
      startPolling(analysisId);
    }
  }, [analysisId, scanning]);

  // Fungsi untuk mendeteksi tipe input
  const detectInputType = (input) => {
    const cleanInput = input.trim().toLowerCase();
    
    // Hash patterns
    const md5Pattern = /^[a-f0-9]{32}$/i;
    const sha1Pattern = /^[a-f0-9]{40}$/i;
    const sha256Pattern = /^[a-f0-9]{64}$/i;
    
    // IP patterns
    const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const ipv6Pattern = /^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$/i;
    
    // URL pattern
    const urlPattern = /^https?:\/\/.+/i;
    
    // Domain pattern
    const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
    
    if (md5Pattern.test(cleanInput)) return { type: 'md5', value: cleanInput };
    if (sha1Pattern.test(cleanInput)) return { type: 'sha1', value: cleanInput };
    if (sha256Pattern.test(cleanInput)) return { type: 'sha256', value: cleanInput };
    if (urlPattern.test(input)) return { type: 'url', value: input };
    if (ipv4Pattern.test(cleanInput)) return { type: 'ip', value: cleanInput };
    if (ipv6Pattern.test(cleanInput)) return { type: 'ipv6', value: cleanInput };
    if (domainPattern.test(cleanInput)) return { type: 'domain', value: cleanInput };
    
    return { type: 'unknown', value: input };
  };

  // Fungsi untuk normalisasi URL (opsional, hanya untuk tampilan)
  const normalizeUrl = (url) => {
    if (!url) return url;
    
    const trimmedUrl = url.trim();
    
    // Jika sudah ada protokol, return as is
    if (trimmedUrl.match(/^https?:\/\//i)) {
      return trimmedUrl;
    }
    
    // Jika tidak ada protokol dan terlihat seperti URL, tambahkan https://
    if (trimmedUrl.includes('.') && !trimmedUrl.includes(' ')) {
      return `https://${trimmedUrl}`;
    }
    
    // Untuk input lainnya (hash, IP, dll), return as is
    return trimmedUrl;
  };

  // Scan URL dengan VirusTotal
  const scanUrl = async (values) => {
    try {
      setLoading(true);
      setError(null);
      setResults(null);
      
      // Gunakan input user langsung tanpa modifikasi
      const userInput = values.url.trim();
      setTarget(userInput);
      setProgress(0);
      
      message.loading({ content: 'Submitting URL for analysis...', key: 'scanning' });
      
      const response = await api.runVirusTotalUrlScan(userInput);
      
      if (response.success) {
        message.success({ content: 'URL submitted successfully', key: 'scanning' });
        setAnalysisId(response.analysis_id);
        setScanning(true);
        setProgress(10);
      } else {
        message.error({ content: `Failed: ${response.message}`, key: 'scanning' });
        setError(response.message || 'Failed to scan URL');
      }
    } catch (error) {
      console.error('URL scan error:', error);
      message.error({ content: `Error occurred: ${error.message}`, key: 'scanning' });
      setError(error.message || 'Error occurred while scanning URL');
    } finally {
      setLoading(false);
    }
  };

  // Scan file dengan VirusTotal
  const scanFile = async () => {
    if (fileList.length === 0) {
      message.error('Please select a file first');
      return;
    }

    try {
      setLoading(true);
      setError(null);
      setResults(null);
      setTarget(fileList[0].name);
      setProgress(0);
      
      message.loading({ content: 'Uploading file for analysis...', key: 'scanning' });
      
      const fileToScan = fileList[0].originFileObj || fileList[0];
      
      if (!fileToScan) {
        throw new Error('Invalid file');
      }
      
      const response = await api.runVirusTotalFileScan(fileToScan);
      
      if (response.success) {
        message.success({ content: 'File uploaded successfully', key: 'scanning' });
        setAnalysisId(response.analysis_id);
        setScanning(true);
        setProgress(10);
      } else {
        message.error({ content: `Failed: ${response.message}`, key: 'scanning' });
        setError(response.message || 'Failed to scan file');
      }
    } catch (error) {
      console.error('File scan error:', error);
      message.error({ content: `Error occurred: ${error.message}`, key: 'scanning' });
      setError(error.message || 'Error occurred while scanning file');
    } finally {
      setLoading(false);
    }
  };

  // Search function untuk hash, domain, IP - Universal approach
  const searchQuery = async (values) => {
    try {
      setLoading(true);
      setError(null);
      setResults(null);
      setProgress(0);
      
      const queryInput = values.query;
      const detectedType = detectInputType(queryInput);
      setSearchType(detectedType.type);
      setTarget(detectedType.value);
      
      message.loading({ content: `Searching for ${detectedType.type}: ${detectedType.value}...`, key: 'scanning' });
      
      let response;
      
      // Try universal search first (if backend supports it)
      try {
        if (api.runVirusTotalSearch) {
          response = await api.runVirusTotalSearch(detectedType.value);
        } else {
          throw new Error('Universal search not available');
        }
      } catch (universalError) {
        console.log('Universal search failed, trying specific methods:', universalError);
        
        // Fallback to specific methods based on detected type
        try {
          switch (detectedType.type) {
            case 'url':
              response = await api.runVirusTotalUrlScan(detectedType.value);
              break;
            case 'domain':
              if (api.runVirusTotalDomainScan) {
                response = await api.runVirusTotalDomainScan(detectedType.value);
              } else {
                // Try as URL with https prefix
                const domainAsUrl = detectedType.value.includes('://') ? detectedType.value : `https://${detectedType.value}`;
                response = await api.runVirusTotalUrlScan(domainAsUrl);
              }
              break;
            case 'ip':
            case 'ipv6':
              if (api.runVirusTotalIpScan) {
                response = await api.runVirusTotalIpScan(detectedType.value);
              } else {
                // Try as URL with http prefix
                const ipAsUrl = `http://${detectedType.value}`;
                response = await api.runVirusTotalUrlScan(ipAsUrl);
              }
              break;
            case 'md5':
            case 'sha1':
            case 'sha256':
              if (api.runVirusTotalHashScan) {
                response = await api.runVirusTotalHashScan(detectedType.value);
              } else {
                throw new Error('Hash scanning not implemented. Please use the URL scan for hash lookup or contact support.');
              }
              break;
            default:
              // For unknown types, try URL scan
              response = await api.runVirusTotalUrlScan(detectedType.value);
          }
        } catch (specificError) {
          console.error('Specific scan method failed:', specificError);
          throw new Error(`Unable to scan ${detectedType.type}: ${specificError.message}`);
        }
      }
      
      if (response && response.success) {
        message.success({ content: `${detectedType.type} search submitted successfully`, key: 'scanning' });
        setAnalysisId(response.analysis_id);
        setScanning(true);
        setProgress(10);
      } else {
        const errorMsg = response?.message || `Failed to search ${detectedType.type}`;
        message.error({ content: `Failed: ${errorMsg}`, key: 'scanning' });
        setError(errorMsg);
      }
    } catch (error) {
      console.error('Search error:', error);
      const errorMessage = error.message || 'Error occurred while searching';
      message.error({ content: `Error occurred: ${errorMessage}`, key: 'scanning' });
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  // Fungsi polling untuk mengecek hasil analisis
  const startPolling = (id) => {
    if (pollingInterval) {
      clearInterval(pollingInterval);
    }

    let pollCount = 0;
    const maxPolls = 60;

    const interval = setInterval(async () => {
      try {
        pollCount++;
        setProgress(Math.min(10 + (pollCount * 1.5), 95));
        
        const response = await api.getVirusTotalScanStatus(id);
        
        if (response.success) {
          if (response.status === 'completed') {
            const realResults = {
              malicious: response.results.malicious || 0,
              suspicious: response.results.suspicious || 0,
              harmless: response.results.harmless || 0,
              undetected: response.results.undetected || 0,
              total_engines: response.results.total_engines || 0,
              scan_date: response.results.scan_date || Math.floor(Date.now() / 1000),
              target: target,
              scan_id: id,
              search_type: searchType || activeTab,
              detailed_results: response.results.detailed_results || response.results.scans || {}
            };
            
            setResults(realResults);
            setScanning(false);
            setProgress(100);
            
            clearInterval(interval);
            setPollingInterval(null);
            
            saveToHistory(id, realResults);
            
            message.success({ content: 'Analysis completed!', key: 'scanning' });
          } else if (response.status === 'queued') {
            message.info({ content: 'Analysis queued...', key: 'scanning', duration: 2 });
          } else if (response.status === 'in-progress') {
            message.info({ content: 'Analysis in progress...', key: 'scanning', duration: 2 });
          }
        } else {
          throw new Error(response.message || 'Failed to get analysis status');
        }
        
        if (pollCount >= maxPolls) {
          throw new Error('Timeout: Analysis taking too long');
        }
        
      } catch (error) {
        console.error('Polling error:', error);
        message.error({ content: `Error occurred: ${error.message}`, key: 'scanning' });
        setError(error.message || 'Error occurred while checking scan status');
        setScanning(false);
        setProgress(0);
        clearInterval(interval);
        setPollingInterval(null);
      }
    }, 5000);

    setPollingInterval(interval);
  };

  // Simpan hasil scan ke history
  const saveToHistory = (scanId, results) => {
    try {
      if (!results || results.total_engines === 0) {
        console.log('No valid results to save');
        return;
      }

      const vulnerabilitiesFound = (results.malicious || 0) + (results.suspicious || 0);
      
      const scanData = {
        id: Date.now(),
        target: target,
        scannerType: 'virustotal',
        status: 'completed',
        timestamp: new Date().toISOString(),
        duration: `${Math.floor((Date.now() - startTime) / 1000)}s`,
        vulnerabilitiesFound: vulnerabilitiesFound,
        findings: generateFindings(results),
        results: results,
        metadata: {
          scanId: scanId,
          scanType: results.search_type || activeTab,
          analysis_date: new Date().toISOString()
        }
      };
      
      const existingHistory = JSON.parse(localStorage.getItem('scanHistory') || '[]');
      existingHistory.unshift(scanData);
      localStorage.setItem('scanHistory', JSON.stringify(existingHistory));
      
      historyService.saveScanResult(scanData);
      console.log('VirusTotal scan saved to history');
    } catch (error) {
      console.error('Error saving scan to history:', error);
    }
  };

  // Generate findings from real results only
  const generateFindings = (results) => {
    const findings = [];
    const scanType = results.search_type || activeTab;
    
    if (results.malicious > 0) {
      findings.push({
        title: `Malicious Content Detected`,
        riskLevel: 'critical',
        description: `${results.malicious} out of ${results.total_engines} engines detected this ${scanType} as malicious`,
        recommendation: `Avoid this ${scanType} and investigate further`
      });
    }
    
    if (results.suspicious > 0) {
      findings.push({
        title: `Suspicious Content Detected`,
        riskLevel: 'high',
        description: `${results.suspicious} out of ${results.total_engines} engines flagged this ${scanType} as suspicious`,
        recommendation: `Exercise caution when accessing this ${scanType}`
      });
    }
    
    return findings;
  };

  // Handler untuk submit form
  const handleSubmit = (values) => {
    setStartTime(Date.now());
    if (activeTab === 'url') {
      scanUrl(values);
    } else if (activeTab === 'search') {
      searchQuery(values);
    } else {
      scanFile();
    }
  };

  // Props untuk upload file
  const uploadProps = {
    beforeUpload: (file) => {
      const isLt50M = file.size / 1024 / 1024 < 50;
      if (!isLt50M) {
        message.error('File must be smaller than 50MB');
        return false;
      }
      
      setFileList([{
        uid: file.uid,
        name: file.name,
        status: 'done',
        originFileObj: file
      }]);
      
      return false;
    },
    fileList,
    onRemove: () => {
      setFileList([]);
    },
    maxCount: 1,
    accept: "*",
  };

  // Handler tab change
  const onTabChange = (key) => {
    setActiveTab(key);
    setError(null);
    setResults(null);
    setScanning(false);
    setAnalysisId(null);
    setTarget(null);
    setFileList([]);
    setProgress(0);
    setSearchType(null);
    form.resetFields();
    
    if (pollingInterval) {
      clearInterval(pollingInterval);
      setPollingInterval(null);
    }
  };

  // Retry function
  const handleRetry = () => {
    if (activeTab === 'url') {
      const values = form.getFieldsValue();
      if (values.url) {
        setStartTime(Date.now());
        scanUrl(values);
      }
    } else if (activeTab === 'search') {
      const values = form.getFieldsValue();
      if (values.query) {
        setStartTime(Date.now());
        searchQuery(values);
      }
    } else {
      if (fileList.length > 0) {
        setStartTime(Date.now());
        scanFile();
      }
    }
  };

  // Input change handler untuk search tab
  const handleSearchInputChange = (e) => {
    const value = e.target.value;
    if (value && value.trim()) {
      const detected = detectInputType(value);
      setSearchType(detected.type);
    } else {
      setSearchType(null);
    }
  };

  // Render search type indicator
  const renderSearchTypeIndicator = () => {
    if (!searchType || searchType === 'unknown') return null;
    
    const typeColors = {
      'md5': 'purple',
      'sha1': 'purple',
      'sha256': 'purple',
      'url': 'blue',
      'domain': 'green',
      'ip': 'orange',
      'ipv6': 'orange'
    };
    
    const typeLabels = {
      'md5': 'MD5 Hash',
      'sha1': 'SHA1 Hash',
      'sha256': 'SHA256 Hash',
      'url': 'URL',
      'domain': 'Domain',
      'ip': 'IPv4 Address',
      'ipv6': 'IPv6 Address'
    };
    
    return (
      <div className="search-type-indicator">
        <Tag color={typeColors[searchType]} icon={<InfoCircleOutlined />}>
          Detected: {typeLabels[searchType]}
        </Tag>
      </div>
    );
  };

  return (
    <div className="virustotal-scanner-container">
      {/* Back Button */}
      {onBack && (
        <div className="back-button-container" style={{ marginBottom: '20px' }}>
          <Button 
            type="default" 
            icon={<ArrowLeftOutlined />} 
            onClick={onBack}
            size="large"
          >
            Back to scanner selection
          </Button>
        </div>
      )}

      {/* Header Section */}
      <div className="scanner-header">
        <div className="header-background">
          <Title level={2} className="header-title">
            VirusTotal Scanner
          </Title>
          <Paragraph className="header-description">
            Analyse suspicious files, domains, IPs and URLs to detect malware and other breaches, 
            automatically share them with the security community.
          </Paragraph>
        </div>
      </div>

      {/* Main Content */}
      <div className="scanner-content">
        <Row justify="center">
          <Col xs={24} sm={24} md={22} lg={20} xl={18} xxl={16}>
            
            {/* Tab Navigation */}
            <Card className="tab-navigation-card">
              <div className="tab-buttons">
                <Button 
                  type={activeTab === 'file' ? 'primary' : 'text'}
                  size="large"
                  icon={<FileTextOutlined />}
                  onClick={() => onTabChange('file')}
                  className={`tab-button ${activeTab === 'file' ? 'active' : ''}`}
                >
                  FILE
                </Button>
                <Button 
                  type={activeTab === 'url' ? 'primary' : 'text'}
                  size="large"
                  icon={<GlobalOutlined />}
                  onClick={() => onTabChange('url')}
                  className={`tab-button ${activeTab === 'url' ? 'active' : ''}`}
                >
                  URL
                </Button>
                <Button 
                  type={activeTab === 'search' ? 'primary' : 'text'}
                  size="large"
                  icon={<SearchOutlined />}
                  onClick={() => onTabChange('search')}
                  className={`tab-button ${activeTab === 'search' ? 'active' : ''}`}
                >
                  SEARCH
                </Button>
              </div>
            </Card>

            {/* Tab Content */}
            <Card className="tab-content-card">
              {/* File Tab */}
              {activeTab === 'file' && (
                <div className="tab-content file-tab">
                  <div className="tab-icon">
                    <FileTextOutlined />
                  </div>
                  <Title level={3}>Upload File for Analysis</Title>
                  <Paragraph>
                    Select a file to analyze for malware and security threats.
                    Maximum file size: 50MB
                  </Paragraph>
                  
                  <div className="upload-section">
                    <Upload.Dragger 
                      {...uploadProps} 
                      disabled={loading || scanning}
                      className="file-upload-dragger"
                    >
                      <p className="ant-upload-drag-icon">
                        <CloudUploadOutlined style={{ fontSize: 48, color: '#1890ff' }} />
                      </p>
                      <p className="ant-upload-text">
                        Click or drag file to this area to upload
                      </p>
                      <p className="ant-upload-hint">
                        Support for single file upload. File size must be less than 50MB.
                      </p>
                    </Upload.Dragger>
                    
                    {fileList.length > 0 && (
                      <div className="file-selected">
                        <Row align="middle" justify="space-between">
                          <Col>
                            <Text strong>{fileList[0].name}</Text>
                          </Col>
                          <Col>
                            <Button 
                              type="primary" 
                              icon={<ScanOutlined />}
                              onClick={() => handleSubmit({})} 
                              loading={loading}
                              disabled={scanning}
                              size="large"
                            >
                              {loading ? 'Uploading...' : 'Scan File'}
                            </Button>
                          </Col>
                        </Row>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* URL Tab */}
              {activeTab === 'url' && (
                <div className="tab-content url-tab">
                  <div className="tab-icon">
                    <GlobalOutlined />
                  </div>
                  <Title level={3}>Scan URL</Title>
                  <Paragraph>
                    Enter any URL to check for malicious content and security threats.
                    VirusTotal will handle any format you provide.
                  </Paragraph>
                  
                  <Form
                    form={form}
                    onFinish={handleSubmit}
                    disabled={loading || scanning}
                    layout="vertical"
                    className="url-form"
                  >
                    <Form.Item
                      name="url"
                      label="URL to scan"
                      rules={[
                        { required: true, message: 'Please enter a URL' },
                        { whitespace: true, message: 'URL cannot be empty' }
                      ]}
                      extra="Enter any URL format - VirusTotal will process it automatically"
                    >
                      <Input 
                        placeholder="Enter any URL (e.g., google.com, https://example.com, http://test.org)" 
                        disabled={loading || scanning}
                        size="large"
                        prefix={<LinkOutlined />}
                      />
                    </Form.Item>
                    
                    <Form.Item>
                      <Button 
                        type="primary" 
                        htmlType="submit" 
                        icon={<ScanOutlined />}
                        loading={loading}
                        disabled={scanning}
                        size="large"
                        block
                      >
                        {loading ? 'Submitting...' : 'Scan URL'}
                      </Button>
                    </Form.Item>
                  </Form>
                </div>
              )}

              {/* Search Tab */}
              {activeTab === 'search' && (
                <div className="tab-content search-tab">
                  <div className="tab-icon">
                    <SearchOutlined />
                  </div>
                  <Title level={3}>Search Analysis</Title>
                  <Paragraph>
                    Search for a hash, domain, IP address, URL or gain additional context
                    and threat landscape visibility.
                  </Paragraph>
                  
                  <Form
                    form={form}
                    onFinish={handleSubmit}
                    disabled={loading || scanning}
                    layout="vertical"
                    className="search-form"
                  >
                    <Form.Item
                      name="query"
                      label="Search term"
                      rules={[
                        { required: true, message: 'Please enter search term' }
                      ]}
                    >
                      <Input 
                        placeholder="URL, IP address, domain, or file hash" 
                        disabled={loading || scanning}
                        size="large"
                        prefix={<SearchOutlined />}
                        onChange={handleSearchInputChange}
                      />
                    </Form.Item>
                    
                    {renderSearchTypeIndicator()}
                    
                    <Form.Item>
                      <Button 
                        type="primary" 
                        htmlType="submit" 
                        icon={<ScanOutlined />}
                        loading={loading}
                        disabled={scanning}
                        size="large"
                        block
                      >
                        {loading ? 'Searching...' : 'Search'}
                      </Button>
                    </Form.Item>
                  </Form>
                  
                  <div className="search-examples">
                    <Text type="secondary">Examples:</Text>
                    <div className="example-tags">
                      <Tag 
                        onClick={() => form.setFieldsValue({query: 'google.com'})} 
                        className="example-tag"
                      >
                        google.com
                      </Tag>
                      <Tag 
                        onClick={() => form.setFieldsValue({query: '8.8.8.8'})} 
                        className="example-tag"
                      >
                        8.8.8.8
                      </Tag>
                      <Tag 
                        onClick={() => form.setFieldsValue({query: 'example.com'})} 
                        className="example-tag"
                      >
                        example.com
                      </Tag>
                      <Tag 
                        onClick={() => form.setFieldsValue({query: 'd41d8cd98f00b204e9800998ecf8427e'})} 
                        className="example-tag"
                      >
                        MD5 Hash
                      </Tag>
                    </div>
                  </div>
                </div>
              )}

              {/* Terms Notice */}
              <div className="terms-notice">
                <Text type="secondary" style={{ fontSize: '12px' }}>
                  By submitting data above, you are agreeing to our Terms of Service and Privacy Notice, 
                  and to the sharing of your submission with the security community. 
                  Please do not submit any personal information.
                </Text>
              </div>
            </Card>

            {/* Error Display */}
            {error && (
              <Alert 
                message="Scan Error" 
                description={error} 
                type="error" 
                showIcon 
                closable
                className="error-alert"
                onClose={() => setError(null)}
                action={
                  <Button size="small" onClick={handleRetry} disabled={loading || scanning}>
                    <ReloadOutlined /> Retry
                  </Button>
                }
              />
            )}

            {/* Scanning Progress */}
            {scanning && (
              <Card className="scanning-progress-card">
                <div className="scanning-content">
                  <Row gutter={24} align="middle">
                    <Col xs={24} sm={6} className="scanning-icon">
                      <Spin size="large" />
                    </Col>
                    <Col xs={24} sm={18}>
                      <Title level={4} className="scanning-title">
                        Analysing {searchType || activeTab}: {target}
                      </Title>
                      <Paragraph className="scanning-description">
                        This may take a few minutes. Please wait while we analyze your submission...
                      </Paragraph>
                      <Progress 
                        percent={progress} 
                        status="active"
                        strokeColor={{
                          '0%': '#1890ff',
                          '100%': '#52c41a',
                        }}
                        className="scanning-progress"
                      />
                    </Col>
                  </Row>
                </div>
              </Card>
            )}

            {/* Results Display */}
            {results && (
              <div className="results-section">
                <Divider>
                  <Title level={3}>
                    <SafetyOutlined /> Analysis Results
                  </Title>
                </Divider>
                <VirusTotalResults results={results} />
              </div>
            )}

          </Col>
        </Row>
      </div>
    </div>
  );
};

export default VirusTotalScanner;