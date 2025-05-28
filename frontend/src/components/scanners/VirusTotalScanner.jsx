// frontend/src/components/scanners/VirusTotalScanner.jsx

import React, { useState, useEffect } from 'react';
import { 
  Button, Form, Input, Upload, message, Card, Spin, Tabs, Alert, 
  Progress, Divider, Table, Tag, Row, Col, Tooltip, Space 
} from 'antd';
import { 
  UploadOutlined, LinkOutlined, SafetyOutlined, CheckCircleOutlined, 
  CloseCircleOutlined, WarningOutlined, QuestionOutlined, 
  FileTextOutlined, GlobalOutlined, ReloadOutlined, InfoCircleOutlined 
} from '@ant-design/icons';

// Import API utility
import api from '../../utils/api';

// Import history service
import { historyService } from '../../services/historyService';

const VirusTotalScanner = () => {
  const [form] = Form.useForm();
  
  // State management
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [activeTab, setActiveTab] = useState('url');
  const [fileList, setFileList] = useState([]);
  const [analysisId, setAnalysisId] = useState(null);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [target, setTarget] = useState(null);
  const [pollingInterval, setPollingInterval] = useState(null);
  const [progress, setProgress] = useState(0);

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

  // Scan URL dengan VirusTotal
  const scanUrl = async (values) => {
    const startTime = Date.now();
    
    try {
      setLoading(true);
      setError(null);
      setResults(null);
      setTarget(values.url);
      setProgress(0);
      
      message.loading({ content: 'Mengirim URL untuk analisis...', key: 'scanning' });
      
      const response = await api.runVirusTotalUrlScan(values.url);
      
      if (response.success) {
        message.success({ content: 'URL berhasil dikirim untuk analisis', key: 'scanning' });
        setAnalysisId(response.analysis_id);
        setScanning(true);
        setProgress(10);
      } else {
        message.error({ content: `Gagal: ${response.message}`, key: 'scanning' });
        setError(response.message || 'Gagal memindai URL');
      }
    } catch (error) {
      console.error('URL scan error:', error);
      message.error({ content: `Terjadi kesalahan: ${error.message}`, key: 'scanning' });
      setError(error.message || 'Terjadi kesalahan saat memindai URL');
    } finally {
      setLoading(false);
    }
  };

  // Scan file dengan VirusTotal - FIXED: Proper file handling
  const scanFile = async () => {
    if (fileList.length === 0) {
      message.error('Silakan pilih file terlebih dahulu');
      return;
    }

    const startTime = Date.now();
    
    try {
      setLoading(true);
      setError(null);
      setResults(null);
      setTarget(fileList[0].name);
      setProgress(0);
      
      message.loading({ content: 'Mengirim file untuk analisis...', key: 'scanning' });
      
      // FIXED: Use the original file object, not originFileObj
      const fileToScan = fileList[0].originFileObj || fileList[0];
      
      // Additional validation
      if (!fileToScan) {
        throw new Error('File tidak valid');
      }
      
      console.log('File to scan:', {
        name: fileToScan.name,
        size: fileToScan.size,
        type: fileToScan.type
      });
      
      const response = await api.runVirusTotalFileScan(fileToScan);
      
      if (response.success) {
        message.success({ content: 'File berhasil dikirim untuk analisis', key: 'scanning' });
        setAnalysisId(response.analysis_id);
        setScanning(true);
        setProgress(10);
      } else {
        message.error({ content: `Gagal: ${response.message}`, key: 'scanning' });
        setError(response.message || 'Gagal memindai file');
      }
    } catch (error) {
      console.error('File scan error:', error);
      message.error({ content: `Terjadi kesalahan: ${error.message}`, key: 'scanning' });
      setError(error.message || 'Terjadi kesalahan saat memindai file');
    } finally {
      setLoading(false);
    }
  };

  // Fungsi polling untuk mengecek hasil analisis
  const startPolling = (id) => {
    // Clear polling interval sebelumnya
    if (pollingInterval) {
      clearInterval(pollingInterval);
    }

    let pollCount = 0;
    const maxPolls = 60; // Maximum 5 minutes (60 * 5 seconds)

    // Mulai polling baru
    const interval = setInterval(async () => {
      try {
        pollCount++;
        setProgress(Math.min(10 + (pollCount * 1.5), 95)); // Gradual progress
        
        const response = await api.getVirusTotalScanStatus(id);
        
        if (response.success) {
          if (response.status === 'completed') {
            setResults(response.results);
            setScanning(false);
            setProgress(100);
            
            // Hentikan polling
            clearInterval(interval);
            setPollingInterval(null);
            
            // Simpan hasil ke history
            saveToHistory(id, response.results);
            
            message.success({ content: 'Analisis selesai!', key: 'scanning' });
          } else if (response.status === 'queued') {
            message.info({ content: 'Analisis dalam antrian...', key: 'scanning', duration: 2 });
          } else if (response.status === 'in-progress') {
            message.info({ content: 'Analisis sedang berlangsung...', key: 'scanning', duration: 2 });
          }
        } else {
          throw new Error(response.message || 'Gagal mendapatkan status analisis');
        }
        
        // Stop polling after maximum attempts
        if (pollCount >= maxPolls) {
          throw new Error('Timeout: Analisis membutuhkan waktu terlalu lama');
        }
        
      } catch (error) {
        console.error('Polling error:', error);
        message.error({ content: `Terjadi kesalahan: ${error.message}`, key: 'scanning' });
        setError(error.message || 'Terjadi kesalahan saat mengecek status pemindaian');
        setScanning(false);
        setProgress(0);
        clearInterval(interval);
        setPollingInterval(null);
      }
    }, 5000); // Cek setiap 5 detik

    setPollingInterval(interval);
  };

  // Simpan hasil scan ke history
  const saveToHistory = (scanId, results) => {
    try {
      const scanData = {
        scannerType: 'virustotal',
        target: target,
        status: 'completed',
        results: results,
        metadata: {
          scanId: scanId,
          scanType: activeTab,
          analysis_date: new Date().toISOString()
        }
      };
      
      historyService.saveScanResult(scanData);
      console.log('VirusTotal scan saved to history');
    } catch (error) {
      console.error('Error saving scan to history:', error);
    }
  };

  // Handler untuk submit form
  const handleSubmit = (values) => {
    if (activeTab === 'url') {
      scanUrl(values);
    } else {
      scanFile();
    }
  };

  // Props untuk upload file - FIXED: Better file handling
  const uploadProps = {
    beforeUpload: (file) => {
      // Validate file size (50MB limit)
      const isLt50M = file.size / 1024 / 1024 < 50;
      if (!isLt50M) {
        message.error('File harus kurang dari 50MB');
        return false;
      }
      
      // Validate file type (optional - you can remove this if you want to accept any file type)
      console.log('File info:', {
        name: file.name,
        size: file.size,
        type: file.type
      });
      
      setFileList([{
        uid: file.uid,
        name: file.name,
        status: 'done',
        originFileObj: file
      }]);
      
      return false; // Prevent automatic upload
    },
    fileList,
    onRemove: () => {
      setFileList([]);
    },
    maxCount: 1,
    accept: "*", // Accept any file type
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
    form.resetFields();
    
    // Clear any running polling
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
        scanUrl(values);
      }
    } else {
      if (fileList.length > 0) {
        scanFile();
      }
    }
  };

  // Tab items configuration
  const tabItems = [
    {
      key: 'url',
      label: (
        <span>
          <GlobalOutlined />
          Scan URL
        </span>
      ),
      children: (
        <Card bordered={false} className="tab-content">
          <Form
            form={form}
            layout="vertical"
            onFinish={handleSubmit}
            disabled={loading || scanning}
          >
            <Form.Item
              name="url"
              label="URL untuk Scan"
              rules={[
                { required: true, message: 'Silakan masukkan URL' },
                { type: 'url', message: 'Format URL tidak valid' }
              ]}
            >
              <Input 
                prefix={<LinkOutlined />} 
                placeholder="https://example.com" 
                disabled={loading || scanning}
                size="large"
              />
            </Form.Item>
            
            <Form.Item>
              <Space>
                <Button 
                  type="primary" 
                  htmlType="submit" 
                  loading={loading}
                  disabled={scanning}
                  size="large"
                  icon={<SafetyOutlined />}
                >
                  {loading ? 'Mengirim...' : 'Scan URL'}
                </Button>
                
                {error && (
                  <Button 
                    onClick={handleRetry}
                    icon={<ReloadOutlined />}
                    disabled={loading || scanning}
                  >
                    Coba Lagi
                  </Button>
                )}
              </Space>
            </Form.Item>
          </Form>
        </Card>
      )
    },
    {
      key: 'file',
      label: (
        <span>
          <FileTextOutlined />
          Scan File
        </span>
      ),
      children: (
        <Card bordered={false} className="tab-content">
          <Form layout="vertical" disabled={loading || scanning}>
            <Form.Item
              label="File untuk Scan"
              extra="Ukuran file maksimal 50MB. Semua jenis file didukung."
            >
              <Upload.Dragger {...uploadProps} disabled={loading || scanning}>
                <p className="ant-upload-drag-icon">
                  <UploadOutlined />
                </p>
                <p className="ant-upload-text">
                  Klik atau drag file ke area ini untuk upload
                </p>
                <p className="ant-upload-hint">
                  Mendukung semua jenis file dengan ukuran maksimal 50MB
                </p>
              </Upload.Dragger>
            </Form.Item>
            
            <Form.Item>
              <Space>
                <Button 
                  type="primary" 
                  onClick={() => handleSubmit({})} 
                  loading={loading}
                  disabled={scanning || fileList.length === 0}
                  size="large"
                  icon={<SafetyOutlined />}
                >
                  {loading ? 'Mengirim...' : 'Scan File'}
                </Button>
                
                {error && (
                  <Button 
                    onClick={handleRetry}
                    icon={<ReloadOutlined />}
                    disabled={loading || scanning || fileList.length === 0}
                  >
                    Coba Lagi
                  </Button>
                )}
              </Space>
            </Form.Item>
          </Form>
        </Card>
      )
    }
  ];

  // Render hasil scan
  const renderResults = () => {
    if (!results) return null;

    const { malicious, suspicious, harmless, undetected, total_engines, scan_date } = results;
    const detectionRate = total_engines > 0 ? ((malicious + suspicious) / total_engines) * 100 : 0;
    const isMalicious = malicious > 0;
    const isSuspicious = suspicious > 0;

    // Determine overall status
    let overallStatus = 'success';
    let statusText = 'Tidak Terdeteksi Berbahaya';
    let statusDescription = `${activeTab === 'url' ? 'URL' : 'File'} ini tidak terdeteksi berbahaya oleh mesin anti-virus.`;

    if (isMalicious) {
      overallStatus = 'error';
      statusText = 'Terdeteksi Berbahaya!';
      statusDescription = `${activeTab === 'url' ? 'URL' : 'File'} ini terdeteksi berbahaya oleh ${malicious} dari ${total_engines} mesin anti-virus.`;
    } else if (isSuspicious) {
      overallStatus = 'warning';
      statusText = 'Terdeteksi Mencurigakan';
      statusDescription = `${activeTab === 'url' ? 'URL' : 'File'} ini terdeteksi mencurigakan oleh ${suspicious} dari ${total_engines} mesin anti-virus.`;
    }

    return (
      <Card 
        title={
          <Space>
            <SafetyOutlined />
            {`Hasil Analisis VirusTotal: ${target}`}
          </Space>
        } 
        className="results-card" 
        style={{ marginTop: 20 }}
      >
        <Alert
          message={statusText}
          description={statusDescription}
          type={overallStatus}
          showIcon
          style={{ marginBottom: 20 }}
          action={
            <Tooltip title="Informasi lebih lanjut">
              <Button size="small" icon={<InfoCircleOutlined />} />
            </Tooltip>
          }
        />
        
        <Row gutter={[16, 16]} className="summary-stats">
          <Col xs={24} sm={12} md={6}>
            <Card bordered={false} className="stat-card malicious">
              <div className="stat-header">
                <CloseCircleOutlined className="stat-icon" />
                <h4>Berbahaya</h4>
              </div>
              <div className="stat-value">
                <span className="stat-number">{malicious}</span>
                <span className="stat-percentage">({((malicious/total_engines)*100).toFixed(1)}%)</span>
              </div>
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card bordered={false} className="stat-card suspicious">
              <div className="stat-header">
                <WarningOutlined className="stat-icon" />
                <h4>Mencurigakan</h4>
              </div>
              <div className="stat-value">
                <span className="stat-number">{suspicious}</span>
                <span className="stat-percentage">({((suspicious/total_engines)*100).toFixed(1)}%)</span>
              </div>
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card bordered={false} className="stat-card harmless">
              <div className="stat-header">
                <CheckCircleOutlined className="stat-icon" />
                <h4>Tidak Berbahaya</h4>
              </div>
              <div className="stat-value">
                <span className="stat-number">{harmless}</span>
                <span className="stat-percentage">({((harmless/total_engines)*100).toFixed(1)}%)</span>
              </div>
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card bordered={false} className="stat-card undetected">
              <div className="stat-header">
                <QuestionOutlined className="stat-icon" />
                <h4>Tidak Terdeteksi</h4>
              </div>
              <div className="stat-value">
                <span className="stat-number">{undetected}</span>
                <span className="stat-percentage">({((undetected/total_engines)*100).toFixed(1)}%)</span>
              </div>
            </Card>
          </Col>
        </Row>
        
        <div className="detection-summary">
          <Row gutter={[24, 24]} align="middle">
            <Col xs={24} md={12}>
              <div className="progress-section">
                <h4>Tingkat Deteksi Keseluruhan</h4>
                <Progress 
                  type="circle" 
                  percent={Math.round(detectionRate)} 
                  status={isMalicious ? "exception" : (isSuspicious ? "active" : "success")}
                  format={(percent) => `${percent}%`}
                  width={120}
                  strokeWidth={8}
                />
              </div>
            </Col>
            <Col xs={24} md={12}>
              <div className="scan-info">
                <h4>Informasi Scan</h4>
                <ul className="scan-details">
                  <li><strong>Tanggal scan:</strong> {new Date(scan_date * 1000).toLocaleString()}</li>
                  <li><strong>Total mesin:</strong> {total_engines}</li>
                  <li><strong>Target:</strong> {target}</li>
                  <li><strong>Jenis scan:</strong> {activeTab === 'url' ? 'URL' : 'File'}</li>
                </ul>
              </div>
            </Col>
          </Row>
        </div>
        
        {results.detailed_results && (
          <>
            <Divider orientation="left">Detail Hasil per Engine</Divider>
            <VirusTotalDetailedResults results={results} />
          </>
        )}
      </Card>
    );
  };

  return (
    <div className="virustotal-scanner">
      <Card 
        title={
          <div className="scanner-header">
            <SafetyOutlined className="scanner-icon" />
            <div>
              <h3>VirusTotal Scanner</h3>
              <p>Leverasi VirusTotal's multi-engine scanning untuk deteksi malicious files dan URLs</p>
            </div>
          </div>
        } 
        className="scanner-card"
      >
        {error && (
          <Alert 
            message="Error" 
            description={error} 
            type="error" 
            showIcon 
            closable
            style={{ marginBottom: 16 }}
            onClose={() => setError(null)}
          />
        )}
        
        <Tabs 
          activeKey={activeTab} 
          onChange={onTabChange}
          items={tabItems}
          size="large"
          className="scanner-tabs"
        />
        
        {scanning && (
          <Card className="scanning-indicator" bordered={false}>
            <div className="scanning-content">
              <Spin size="large" />
              <div className="scanning-text">
                <h4>Sedang melakukan scan pada {activeTab === 'url' ? 'URL' : 'file'}: {target}</h4>
                <p>Ini mungkin membutuhkan beberapa menit. Mohon tunggu...</p>
                <Progress 
                  percent={progress} 
                  status="active"
                  strokeColor={{
                    '0%': '#108ee9',
                    '100%': '#87d068',
                  }}
                />
              </div>
            </div>
          </Card>
        )}
      </Card>
      
      {renderResults()}
    </div>
  );
};

// Sub-komponen untuk menampilkan hasil detail
const VirusTotalDetailedResults = ({ results }) => {
  if (!results || !results.detailed_results) {
    return null;
  }

  const getStatusColor = (result) => {
    switch (result?.toLowerCase()) {
      case 'malicious':
        return 'error';
      case 'suspicious':
        return 'warning';
      case 'harmless':
        return 'success';
      default:
        return 'default';
    }
  };

  const getStatusIcon = (result) => {
    switch (result?.toLowerCase()) {
      case 'malicious':
        return <CloseCircleOutlined style={{ color: '#ff4d4f' }} />;
      case 'suspicious':
        return <WarningOutlined style={{ color: '#faad14' }} />;
      case 'harmless':
        return <CheckCircleOutlined style={{ color: '#52c41a' }} />;
      default:
        return <QuestionOutlined style={{ color: '#d9d9d9' }} />;
    }
  };

  // Persiapkan data untuk tabel
  const tableData = Object.entries(results.detailed_results).map(([engineName, engineResult], index) => ({
    key: index,
    engine: engineName,
    category: engineResult.category || 'undetected',
    result: engineResult.result || '-',
    method: engineResult.method || '-',
    update: engineResult.engine_update || '-',
  }));

  const columns = [
    {
      title: 'Mesin Anti-Virus',
      dataIndex: 'engine',
      key: 'engine',
      sorter: (a, b) => a.engine.localeCompare(b.engine),
      width: 200,
      fixed: 'left',
    },
    {
      title: 'Hasil',
      dataIndex: 'category',
      key: 'category',
      render: (category) => (
        <Tag icon={getStatusIcon(category)} color={getStatusColor(category)}>
          {category.toUpperCase()}
        </Tag>
      ),
      filters: [
        { text: 'Berbahaya', value: 'malicious' },
        { text: 'Mencurigakan', value: 'suspicious' },
        { text: 'Tidak Berbahaya', value: 'harmless' },
        { text: 'Tidak Terdeteksi', value: 'undetected' },
      ],
      onFilter: (value, record) => record.category === value,
      sorter: (a, b) => a.category.localeCompare(b.category),
      width: 120,
    },
    {
      title: 'Deteksi',
      dataIndex: 'result',
      key: 'result',
      ellipsis: true,
      width: 200,
    },
    {
      title: 'Metode',
      dataIndex: 'method',
      key: 'method',
      width: 100,
    },
    {
      title: 'Update Terakhir',
      dataIndex: 'update',
      key: 'update',
      width: 150,
    },
  ];

  return (
    <div className="detailed-results">
      <Table
        dataSource={tableData}
        columns={columns}
        pagination={{ 
          pageSize: 10,
          showSizeChanger: true,
          showQuickJumper: true,
          showTotal: (total, range) => `${range[0]}-${range[1]} dari ${total} engine`
        }}
        scroll={{ x: 800 }}
        size="small"
        className="results-table"
      />
    </div>
  );
};

export default VirusTotalScanner;