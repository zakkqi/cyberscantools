// frontend/src/components/scanners/VirusTotalResults.jsx
import React, { useState } from 'react';
import { 
  Card, Table, Tag, Collapse, Typography, Row, Col, Divider, 
  Statistic, Progress, Badge, Space, Button, Tooltip, Input 
} from 'antd';
import { 
  CheckCircleOutlined, CloseCircleOutlined, WarningOutlined, 
  QuestionOutlined, SafetyOutlined, BugOutlined, DashboardOutlined,
  InfoCircleOutlined, SearchOutlined, FilterOutlined
} from '@ant-design/icons';

const { Panel } = Collapse;
const { Title, Text, Paragraph } = Typography;
const { Search } = Input;

const VirusTotalResults = ({ results }) => {
  const [filteredData, setFilteredData] = useState(null);
  const [searchText, setSearchText] = useState('');

  if (!results || !results.detailed_results) {
    return null;
  }

  const getStatusColor = (result) => {
    switch (result) {
      case 'malicious':
        return '#ff4d4f';
      case 'suspicious':
        return '#faad14';
      case 'harmless':
        return '#52c41a';
      case 'undetected':
        return '#d9d9d9';
      default:
        return '#d9d9d9';
    }
  };

  const getStatusIcon = (result) => {
    switch (result) {
      case 'malicious':
        return <CloseCircleOutlined style={{ color: '#ff4d4f' }} />;
      case 'suspicious':
        return <WarningOutlined style={{ color: '#faad14' }} />;
      case 'harmless':
        return <CheckCircleOutlined style={{ color: '#52c41a' }} />;
      case 'undetected':
        return <QuestionOutlined style={{ color: '#d9d9d9' }} />;
      default:
        return <QuestionOutlined style={{ color: '#d9d9d9' }} />;
    }
  };

  const getStatusText = (result) => {
    switch (result) {
      case 'malicious':
        return 'Malicious';
      case 'suspicious':
        return 'Suspicious';
      case 'harmless':
        return 'Clean';
      case 'undetected':
        return 'Undetected';
      default:
        return 'Unknown';
    }
  };

  // Persiapkan data untuk tabel
  const tableData = Object.entries(results.detailed_results).map(([engineName, engineResult], index) => ({
    key: index,
    engine: engineName,
    category: engineResult.category || 'undetected',
    result: engineResult.result || '-',
    method: engineResult.method || '-',
    update: engineResult.engine_update || engineResult.engine_version || '-',
    version: engineResult.engine_version || '-'
  }));

  // Filter data berdasarkan search
  const handleSearch = (value) => {
    setSearchText(value);
    if (!value) {
      setFilteredData(null);
      return;
    }
    
    const filtered = tableData.filter(item =>
      item.engine.toLowerCase().includes(value.toLowerCase()) ||
      item.result.toLowerCase().includes(value.toLowerCase()) ||
      item.category.toLowerCase().includes(value.toLowerCase())
    );
    setFilteredData(filtered);
  };

  const displayData = filteredData || tableData;

  const columns = [
    {
      title: 'Anti-Virus Engine',
      dataIndex: 'engine',
      key: 'engine',
      sorter: (a, b) => a.engine.localeCompare(b.engine),
      width: '25%',
      render: (text) => <Text strong>{text}</Text>
    },
    {
      title: 'Detection Result',
      dataIndex: 'category',
      key: 'category',
      render: (category, record) => (
        <Space>
          <Badge 
            status={category === 'malicious' ? 'error' : 
                   category === 'suspicious' ? 'warning' : 
                   category === 'harmless' ? 'success' : 'default'} 
          />
          <Tag 
            icon={getStatusIcon(category)} 
            color={category === 'malicious' ? 'error' : 
                   category === 'suspicious' ? 'warning' : 
                   category === 'harmless' ? 'success' : 'default'}
          >
            {getStatusText(category)}
          </Tag>
          {record.result && record.result !== '-' && (
            <Text type="secondary" style={{ fontSize: '12px' }}>
              {record.result}
            </Text>
          )}
        </Space>
      ),
      filters: [
        { text: 'Malicious', value: 'malicious' },
        { text: 'Suspicious', value: 'suspicious' },
        { text: 'Clean', value: 'harmless' },
        { text: 'Undetected', value: 'undetected' },
      ],
      onFilter: (value, record) => record.category === value,
      sorter: (a, b) => a.category.localeCompare(b.category),
      width: '40%'
    },
    {
      title: 'Method',
      dataIndex: 'method',
      key: 'method',
      width: '20%',
      render: (text) => text === '-' ? <Text type="secondary">-</Text> : <Text>{text}</Text>
    },
    {
      title: 'Last Update',
      dataIndex: 'update',
      key: 'update',
      width: '15%',
      render: (text) => text === '-' ? <Text type="secondary">-</Text> : <Text>{text}</Text>
    }
  ];

  // Hitung statistik
  const totalEngines = results.total_engines;
  const maliciousPercent = totalEngines > 0 ? (results.malicious / totalEngines) * 100 : 0;
  const suspiciousPercent = totalEngines > 0 ? (results.suspicious / totalEngines) * 100 : 0;
  const harmlessPercent = totalEngines > 0 ? (results.harmless / totalEngines) * 100 : 0;
  const undetectedPercent = totalEngines > 0 ? (results.undetected / totalEngines) * 100 : 0;

  // Determine overall risk level
  const getRiskLevel = () => {
    if (results.malicious > 0) return { level: 'High Risk', color: '#ff4d4f', icon: <BugOutlined /> };
    if (results.suspicious > 0) return { level: 'Medium Risk', color: '#faad14', icon: <WarningOutlined /> };
    return { level: 'Low Risk', color: '#52c41a', icon: <SafetyOutlined /> };
  };

  const riskInfo = getRiskLevel();

  return (
    <div className="virustotal-results">
      {/* Overall Summary Card */}
      <Card className="summary-card">
        <Row gutter={[24, 24]} align="middle">
          <Col xs={24} sm={12}>
            <div className="risk-summary">
              <div className="risk-icon" style={{ color: riskInfo.color }}>
                {riskInfo.icon}
              </div>
              <div className="risk-info">
                <Title level={3} style={{ color: riskInfo.color, margin: 0 }}>
                  {riskInfo.level}
                </Title>
                <Text type="secondary">
                  Based on {totalEngines} security vendors
                </Text>
              </div>
            </div>
          </Col>
          <Col xs={24} sm={12}>
            <div className="scan-info">
              <Paragraph>
                <Text strong>Target:</Text> {results.target || 'Unknown'}
              </Paragraph>
              <Paragraph>
                <Text strong>Scan Date:</Text> {new Date(results.scan_date * 1000).toLocaleString()}
              </Paragraph>
              <Paragraph>
                <Text strong>Analysis ID:</Text> {results.scan_id || 'N/A'}
              </Paragraph>
            </div>
          </Col>
        </Row>
      </Card>

      {/* Detection Statistics */}
      <Card title={<><DashboardOutlined /> Detection Statistics</>} className="stats-card">
        <Row gutter={[16, 16]}>
          <Col xs={12} sm={6}>
            <Card className="stat-item malicious-stat">
              <Statistic
                title="Malicious"
                value={results.malicious}
                suffix={`/ ${totalEngines}`}
                valueStyle={{ color: '#ff4d4f' }}
                prefix={<CloseCircleOutlined />}
              />
              <Progress 
                percent={maliciousPercent} 
                strokeColor="#ff4d4f" 
                showInfo={false}
                size="small"
              />
              <Text type="secondary">{maliciousPercent.toFixed(1)}%</Text>
            </Card>
          </Col>
          <Col xs={12} sm={6}>
            <Card className="stat-item suspicious-stat">
              <Statistic
                title="Suspicious"
                value={results.suspicious}
                suffix={`/ ${totalEngines}`}
                valueStyle={{ color: '#faad14' }}
                prefix={<WarningOutlined />}
              />
              <Progress 
                percent={suspiciousPercent} 
                strokeColor="#faad14" 
                showInfo={false}
                size="small"
              />
              <Text type="secondary">{suspiciousPercent.toFixed(1)}%</Text>
            </Card>
          </Col>
          <Col xs={12} sm={6}>
            <Card className="stat-item clean-stat">
              <Statistic
                title="Clean"
                value={results.harmless}
                suffix={`/ ${totalEngines}`}
                valueStyle={{ color: '#52c41a' }}
                prefix={<CheckCircleOutlined />}
              />
              <Progress 
                percent={harmlessPercent} 
                strokeColor="#52c41a" 
                showInfo={false}
                size="small"
              />
              <Text type="secondary">{harmlessPercent.toFixed(1)}%</Text>
            </Card>
          </Col>
          <Col xs={12} sm={6}>
            <Card className="stat-item undetected-stat">
              <Statistic
                title="Undetected"
                value={results.undetected}
                suffix={`/ ${totalEngines}`}
                valueStyle={{ color: '#d9d9d9' }}
                prefix={<QuestionOutlined />}
              />
              <Progress 
                percent={undetectedPercent} 
                strokeColor="#d9d9d9" 
                showInfo={false}
                size="small"
              />
              <Text type="secondary">{undetectedPercent.toFixed(1)}%</Text>
            </Card>
          </Col>
        </Row>
      </Card>

      {/* Detection Details */}
      <Card 
        title={
          <Space>
            <FilterOutlined />
            Detection Details
            <Badge count={displayData.length} style={{ backgroundColor: '#1890ff' }} />
          </Space>
        }
        extra={
          <Search
            placeholder="Search engines or results"
            allowClear
            style={{ width: 250 }}
            onSearch={handleSearch}
            onChange={(e) => !e.target.value && handleSearch('')}
          />
        }
        className="details-card"
      >
        <Table
          dataSource={displayData}
          columns={columns}
          pagination={{ 
            pageSize: 10,
            showSizeChanger: true,
            showQuickJumper: true,
            showTotal: (total, range) => 
              `${range[0]}-${range[1]} of ${total} engines`
          }}
          scroll={{ x: 'max-content' }}
          size="small"
          className="detection-table"
        />
      </Card>

      {/* Additional Information */}
      <Collapse className="additional-info" ghost>
        <Panel 
          header={
            <Space>
              <InfoCircleOutlined />
              Additional Information
            </Space>
          } 
          key="1"
        >
          <Row gutter={[16, 16]}>
            <Col xs={24} sm={8}>
              <Card size="small">
                <Statistic
                  title="Total Engines"
                  value={totalEngines}
                  prefix={<SafetyOutlined />}
                />
              </Card>
            </Col>
            <Col xs={24} sm={8}>
              <Card size="small">
                <Statistic
                  title="Detection Rate"
                  value={((results.malicious + results.suspicious) / totalEngines * 100).toFixed(1)}
                  suffix="%"
                  valueStyle={{ 
                    color: (results.malicious + results.suspicious) > 0 ? '#ff4d4f' : '#52c41a' 
                  }}
                  prefix={<DashboardOutlined />}
                />
              </Card>
            </Col>
            <Col xs={24} sm={8}>
              <Card size="small">
                <Statistic
                  title="Reputation Score"
                  value={(harmlessPercent).toFixed(1)}
                  suffix="%"
                  valueStyle={{ color: harmlessPercent > 70 ? '#52c41a' : harmlessPercent > 40 ? '#faad14' : '#ff4d4f' }}
                  prefix={<CheckCircleOutlined />}
                />
              </Card>
            </Col>
          </Row>
          
          <Divider />
          
          <div className="scan-metadata">
            <Title level={5}>Scan Metadata</Title>
            <Row gutter={[16, 8]}>
              <Col span={8}>
                <Text strong>Scan Type:</Text>
              </Col>
              <Col span={16}>
                <Text>{results.search_type || 'file'}</Text>
              </Col>
              <Col span={8}>
                <Text strong>Analysis Date:</Text>
              </Col>
              <Col span={16}>
                <Text>{new Date(results.scan_date * 1000).toLocaleString()}</Text>
              </Col>
              <Col span={8}>
                <Text strong>Target:</Text>
              </Col>
              <Col span={16}>
                <Text code>{results.target}</Text>
              </Col>
            </Row>
          </div>
        </Panel>
      </Collapse>
    </div>
  );
};

export default VirusTotalResults;