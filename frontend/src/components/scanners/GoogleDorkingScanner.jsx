import React, { useState, useEffect } from 'react';
import { Button, Form, Input, Card, List, Typography, Tag, Alert, Space, Tabs, Row, Col, Statistic, Divider, Progress, Spin, Slider, InputNumber } from 'antd';
import { LoadingOutlined } from '@ant-design/icons';
import axios from 'axios';
import '../../styles/GoogleDorkingScanner.css';

const { Title, Text, Paragraph } = Typography;
const { TextArea } = Input;
const { TabPane } = Tabs;

const GoogleDorkingScanner = () => {
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentDork, setCurrentDork] = useState('');
  const [results, setResults] = useState([]);
  const [scanResponse, setScanResponse] = useState(null);
  const [error, setError] = useState(null);
  const [form] = Form.useForm();
  const [numPages, setNumPages] = useState(3); // Default 3 halaman

  // Dork presets umum untuk Google Dorking
  const commonDorks = [
    "inurl:admin",
    "filetype:pdf",
    "intitle:\"index of\"",
    "intext:password",
    "site:example.com ext:php | ext:asp | ext:aspx | ext:jsp | ext:html | ext:htm | ext:cf | ext:pl",
    "inurl:wp-content",
    "intitle:\"Login Page\"",
    "inurl:config"
  ];

  // Loading icon kustom
  const antIcon = <LoadingOutlined style={{ fontSize: 24 }} spin />;

  const onFinish = async (values) => {
    setLoading(true);
    setProgress(0);
    setCurrentDork('');
    setError(null);
    setResults([]);
    setScanResponse(null);

    try {
      // Parse dorks dari text area, satu per baris
      const dorksList = values.dorks.split('\n').filter(dork => dork.trim() !== '');
      const totalDorks = dorksList.length;
      
      // Simulasi progres untuk pengalaman user yang lebih baik
      let progressInterval;
      progressInterval = setInterval(() => {
        setProgress(prev => {
          if (prev >= 99) {
            clearInterval(progressInterval);
            return 99;
          }
          return prev + 1;
        });
      }, (totalDorks * numPages * 1000) / 100); // Distribusikan progress secara merata
      
      const response = await axios.post('http://localhost:5000/api/scan/google-dorking', {
        target: values.target,
        scan_options: {
          dorks: dorksList,
          num_pages: numPages // Kirim jumlah halaman yang diinginkan
        }
      });

      // Bersihkan interval
      clearInterval(progressInterval);
      setProgress(100);

      if (response.data.status === 'success' || response.data.status === 'partial') {
        setResults(response.data.results);
        setScanResponse(response.data);
        if (response.data.status === 'partial' && response.data.errors.length > 0) {
          setError(`Scan completed with some errors: ${response.data.errors[0].error}`);
        }
      } else {
        setError('Scan failed. Please try again.');
      }
    } catch (err) {
      setError(`Error: ${err.message}`);
    } finally {
      // Tambahkan delay kecil agar user bisa melihat 100% di progress bar
      setTimeout(() => {
        setLoading(false);
        setProgress(0);
      }, 500);
    }
  };

  const fillCommonDorks = () => {
    form.setFieldsValue({
      dorks: commonDorks.join('\n')
    });
  };

  // Helper function untuk mendapatkan warna berdasarkan risk level
  const getRiskColor = (riskLevel) => {
    switch(riskLevel) {
      case 'critical': return '#cf1322';
      case 'high': return '#fa8c16';
      case 'medium': return '#1890ff';
      case 'low': return '#52c41a';
      default: return '#8c8c8c';
    }
  };

  // Komponen Loading State
  const LoadingState = ({ progress, dork }) => (
    <div className="loading-state">
      <Spin indicator={antIcon} />
      <Progress percent={progress} status="active" style={{ margin: '20px 0' }} />
      <div className="loading-text">
        <Text>Scanning target domain...</Text>
        {dork && <Text type="secondary">Current dork: {dork}</Text>}
      </div>
    </div>
  );

  // Komponen untuk menampilkan summary visual dengan progress bars
  const SectorSummaryVisual = ({ sectorSummary }) => {
    if (!sectorSummary || !sectorSummary.sorted_sectors) {
      return null;
    }

    const totalResults = results.length;

    return (
      <div>
        <Title level={4}>Distribusi Hasil Berdasarkan Sektor</Title>
        <Row gutter={[16, 16]}>
          {sectorSummary.sorted_sectors.map(([sector, count]) => {
            if (count === 0) return null;
            
            const riskLevel = sectorSummary.risk_levels[sector];
            const riskColor = getRiskColor(riskLevel);
            const percentage = (count / totalResults) * 100;
            
            return (
              <Col span={24} key={sector}>
                <div style={{ marginBottom: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <Text strong style={{ textTransform: 'uppercase' }}>{sector.replace('_', ' ')}</Text>
                    <div>
                      <Tag color={riskColor}>{riskLevel.toUpperCase()}</Tag>
                      <Text>{count} hasil ({percentage.toFixed(1)}%)</Text>
                    </div>
                  </div>
                  <Progress 
                    percent={percentage} 
                    showInfo={false}
                    strokeColor={riskColor}
                    strokeWidth={20}
                    style={{ marginBottom: 4 }}
                  />
                </div>
              </Col>
            );
          })}
        </Row>
      </div>
    );
  };

  // Komponen untuk menampilkan domain analysis visual
  const DomainSummaryVisual = ({ domainSummary }) => {
    if (!domainSummary || !domainSummary.domains) {
      return null;
    }

    const totalResults = results.length;
    const domains = Object.entries(domainSummary.domains)
      .sort(([_, countA], [__, countB]) => countB - countA)
      .slice(0, 10); // Top 10 domains

    return (
      <div>
        <Title level={4}>Top 10 Domains ({domainSummary.total_domains} domains ditemukan)</Title>
        <Row gutter={[16, 16]}>
          {domains.map(([domain, count]) => {
            const percentage = (count / totalResults) * 100;
            
            return (
              <Col span={24} key={domain}>
                <div style={{ marginBottom: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <Text strong>{domain}</Text>
                    <Text>{count} hasil ({percentage.toFixed(1)}%)</Text>
                  </div>
                  <Progress 
                    percent={percentage} 
                    showInfo={false}
                    strokeColor="#1890ff"
                    strokeWidth={20}
                    style={{ marginBottom: 4 }}
                  />
                </div>
              </Col>
            );
          })}
        </Row>
      </div>
    );
  };

  // Stats Cards untuk ringkasan cepat
  const SummaryStatsCards = ({ scanResponse }) => {
    if (!scanResponse || !scanResponse.sector_summary || !scanResponse.sector_summary.sorted_sectors) {
      return null;
    }
    
    const topSector = scanResponse.sector_summary.sorted_sectors.length > 0 ? 
      scanResponse.sector_summary.sorted_sectors[0][0] : '';
    
    const topSectorCount = scanResponse.sector_summary.sorted_sectors.length > 0 ? 
      scanResponse.sector_summary.sorted_sectors[0][1] : 0;
    
    const totalDomains = scanResponse.domain_summary ? scanResponse.domain_summary.total_domains : 0;
    
    const totalSectors = Object.values(scanResponse.sector_summary.sector_counts || {})
      .filter(count => count > 0).length;

    return (
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} md={6}>
          <Card size="small">
            <Statistic 
              title="Total Findings" 
              value={results.length} 
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card size="small">
            <Statistic 
              title="Total Sectors" 
              value={totalSectors} 
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card size="small">
            <Statistic 
              title="Total Domains" 
              value={totalDomains} 
              valueStyle={{ color: '#722ed1' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card size="small">
            <Statistic 
              title={`Top Sector`} 
              value={topSector.replace('_', ' ')} 
              suffix={`(${topSectorCount})`}
              valueStyle={{ color: getRiskColor('critical') }}
            />
          </Card>
        </Col>
      </Row>
    );
  };

  // Pagination Info
  const PaginationInfo = ({ paginationInfo }) => {
    if (!paginationInfo) return null;

    return (
      <Card size="small" title="Pagination Information" style={{ marginTop: 16 }}>
        <Row gutter={16}>
          <Col span={8}>
            <Statistic title="Pages per Dork" value={paginationInfo.total_pages_requested} />
          </Col>
          <Col span={8}>
            <Statistic title="Results per Page" value={paginationInfo.max_results_per_page} />
          </Col>
          <Col span={8}>
            <Statistic 
              title="Max Potential Results" 
              value={paginationInfo.max_potential_results} 
              suffix={`(${results.length} actual)`}
            />
          </Col>
        </Row>
      </Card>
    );
  };

  return (
    <div className="google-dorking-scanner">
      <Title level={2}>Google Dorking Scanner</Title>
      <Paragraph>
        Find exposed information using Google search operators
      </Paragraph>

      <Card title="Scan Configuration" className="scan-config">
        <Form
          form={form}
          name="google_dorking"
          onFinish={onFinish}
          layout="vertical"
        >
          <Form.Item
            name="target"
            label="Target Domain"
            rules={[{ required: true, message: 'Please enter target domain' }]}
          >
            <Input placeholder="example.com" />
          </Form.Item>

          <Form.Item
            name="dorks"
            label="Google Dorks (one per line)"
            rules={[{ required: true, message: 'Please enter at least one dork' }]}
          >
            <TextArea
              rows={6}
              placeholder="inurl:admin&#10;filetype:pdf&#10;intext:password"
            />
          </Form.Item>

          <Form.Item label="Number of Pages per Dork">
            <Row>
              <Col span={16}>
                <Slider
                  min={1}
                  max={10}
                  onChange={value => setNumPages(value)}
                  value={numPages}
                />
              </Col>
              <Col span={6} offset={2}>
                <InputNumber
                  min={1}
                  max={10}
                  style={{ width: '100%' }}
                  value={numPages}
                  onChange={value => setNumPages(value)}
                />
              </Col>
            </Row>
            <Text type="secondary">
              Each page can return up to 10 results. More pages = more comprehensive results but slower scan.
            </Text>
          </Form.Item>

          <Form.Item>
            <Space>
              <Button type="primary" htmlType="submit" loading={loading}>
                Start Scan
              </Button>
              <Button onClick={fillCommonDorks}>
                Fill Common Dorks
              </Button>
            </Space>
          </Form.Item>
        </Form>
      </Card>

      {loading && (
        <Card className="loading-card">
          <LoadingState progress={progress} dork={currentDork} />
        </Card>
      )}

      {error && (
        <Alert
          message="Error"
          description={error}
          type="error"
          showIcon
          className="result-alert"
        />
      )}

      {results.length > 0 && scanResponse && (
        <>
          <Card title="Scan Results Summary" className="scan-summary">
            <SummaryStatsCards scanResponse={scanResponse} />
            
            {scanResponse.pagination_info && (
              <PaginationInfo paginationInfo={scanResponse.pagination_info} />
            )}
            
            <Divider />
            
            <Tabs defaultActiveKey="sectors">
              <TabPane tab="Sector Analysis" key="sectors">
                <SectorSummaryVisual sectorSummary={scanResponse.sector_summary} />
              </TabPane>
              <TabPane tab="Domain Analysis" key="domains">
                <DomainSummaryVisual domainSummary={scanResponse.domain_summary} />
              </TabPane>
            </Tabs>
          </Card>

          <Card title="Scan Results" className="scan-results">
            <Tabs defaultActiveKey="all">
              <TabPane tab={`All Results (${results.length})`} key="all">
                <List
                  itemLayout="vertical"
                  dataSource={results}
                  pagination={{
                    pageSize: 10,
                    showSizeChanger: true,
                    pageSizeOptions: ['10', '20', '50', '100'],
                  }}
                  renderItem={item => (
                    <List.Item
                      extra={
                        <Space>
                          <Tag color="blue">{item.dork}</Tag>
                          {item.page && <Tag color="purple">Page {item.page}</Tag>}
                          {item.sector && (
                            <Tag color={getRiskColor(scanResponse.sector_summary.risk_levels[item.sector])}>
                              {item.sector.replace('_', ' ')}
                            </Tag>
                          )}
                        </Space>
                      }
                    >
                      <List.Item.Meta
                        title={<a href={item.link} target="_blank" rel="noopener noreferrer">{item.title}</a>}
                        description={item.link}
                      />
                      <div>{item.snippet}</div>
                    </List.Item>
                  )}
                />
              </TabPane>
              
              {scanResponse.sector_results && Object.entries(scanResponse.sector_results).map(([sector, sectorResults]) => (
                sectorResults.length > 0 && (
                  <TabPane tab={`${sector.replace('_', ' ')} (${sectorResults.length})`} key={`sector-${sector}`}>
                    <List
                      itemLayout="vertical"
                      dataSource={sectorResults}
                      pagination={{
                        pageSize: 10,
                        showSizeChanger: true,
                        pageSizeOptions: ['10', '20', '50', '100'],
                      }}
                      renderItem={item => (
                        <List.Item
                          extra={
                            <Space>
                              <Tag color="blue">{item.dork}</Tag>
                              {item.page && <Tag color="purple">Page {item.page}</Tag>}
                            </Space>
                          }
                        >
                          <List.Item.Meta
                            title={<a href={item.link} target="_blank" rel="noopener noreferrer">{item.title}</a>}
                            description={item.link}
                          />
                          <div>{item.snippet}</div>
                        </List.Item>
                      )}
                    />
                  </TabPane>
                )
              ))}
            </Tabs>
          </Card>
        </>
      )}
    </div>
  );
};

export default GoogleDorkingScanner;