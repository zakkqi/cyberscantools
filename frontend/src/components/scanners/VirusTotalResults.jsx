// frontend/src/components/scanners/VirusTotalResults.jsx
import React from 'react';
import { Card, Table, Tag, Collapse, Typography, Row, Col, Divider } from 'antd';
import { CheckCircleOutlined, CloseCircleOutlined, WarningOutlined, QuestionOutlined } from '@ant-design/icons';

const { Panel } = Collapse;
const { Title, Text } = Typography;

const VirusTotalResults = ({ results }) => {
  if (!results || !results.detailed_results) {
    return null;
  }

  const getStatusColor = (result) => {
    switch (result) {
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
    switch (result) {
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
    },
    {
      title: 'Deteksi',
      dataIndex: 'result',
      key: 'result',
    },
    {
      title: 'Metode',
      dataIndex: 'method',
      key: 'method',
    },
    {
      title: 'Update Terakhir',
      dataIndex: 'update',
      key: 'update',
    },
  ];

  // Hitung persentase dari setiap kategori
  const totalEngines = results.total_engines;
  const maliciousPercent = (results.malicious / totalEngines) * 100;
  const suspiciousPercent = (results.suspicious / totalEngines) * 100;
  const harmlessPercent = (results.harmless / totalEngines) * 100;
  const undetectedPercent = (results.undetected / totalEngines) * 100;

  return (
    <Card title="Detail Hasil Analisis VirusTotal" className="result-details-card">
      <Row gutter={16} className="summary-stats">
        <Col span={6}>
          <Card bordered={false} className="stat-card malicious">
            <Title level={4}>Berbahaya</Title>
            <div className="stat-value">
              <Title level={2}>{results.malicious}</Title>
              <Text type="secondary">({maliciousPercent.toFixed(1)}%)</Text>
            </div>
          </Card>
        </Col>
        <Col span={6}>
          <Card bordered={false} className="stat-card suspicious">
            <Title level={4}>Mencurigakan</Title>
            <div className="stat-value">
              <Title level={2}>{results.suspicious}</Title>
              <Text type="secondary">({suspiciousPercent.toFixed(1)}%)</Text>
            </div>
          </Card>
        </Col>
        <Col span={6}>
          <Card bordered={false} className="stat-card harmless">
            <Title level={4}>Tidak Berbahaya</Title>
            <div className="stat-value">
              <Title level={2}>{results.harmless}</Title>
              <Text type="secondary">({harmlessPercent.toFixed(1)}%)</Text>
            </div>
          </Card>
        </Col>
        <Col span={6}>
          <Card bordered={false} className="stat-card undetected">
            <Title level={4}>Tidak Terdeteksi</Title>
            <div className="stat-value">
              <Title level={2}>{results.undetected}</Title>
              <Text type="secondary">({undetectedPercent.toFixed(1)}%)</Text>
            </div>
          </Card>
        </Col>
      </Row>

      <Divider orientation="left">Detail Hasil per Engine</Divider>
      
      <Table
        dataSource={tableData}
        columns={columns}
        pagination={{ pageSize: 10 }}
        scroll={{ x: 'max-content' }}
      />

      <Collapse className="additional-info" ghost>
        <Panel header="Informasi Tambahan" key="1">
          <p>
            <strong>Tanggal Scan:</strong> {new Date(results.scan_date * 1000).toLocaleString()}
          </p>
          <p>
            <strong>Total Mesin:</strong> {results.total_engines}
          </p>
          <p>
            <strong>Skor Reputasi:</strong> {((results.harmless / totalEngines) * 100).toFixed(1)}% positif
          </p>
        </Panel>
      </Collapse>
    </Card>
  );
};

export default VirusTotalResults;