// frontend/src/components/scanners/GoogleDorkingResults.jsx
import React, { useState } from 'react';
import { Card, List, Typography, Tag, Button, Tabs, Row, Col, Statistic, Progress, Alert } from 'antd';
import { 
  FileTextOutlined, 
  LinkOutlined, 
  DownloadOutlined,
  PieChartOutlined,
  GlobalOutlined,
  ExclamationCircleOutlined
} from '@ant-design/icons';

const { Title, Text, Paragraph } = Typography;
const { TabPane } = Tabs;

const GoogleDorkingResults = ({ results, target }) => {
  const [activeTab, setActiveTab] = useState('all');

  if (!results || !results.results || results.results.length === 0) {
    return (
      <Alert
        message="No Results Found"
        description="No results were found for the specified target and dorks. Try different dorks or check if the target domain is accessible."
        type="info"
        showIcon
        style={{ margin: '20px 0' }}
      />
    );
  }

  // Group results by dork
  const groupedResults = {};
  results.results.forEach(result => {
    if (!groupedResults[result.dork]) {
      groupedResults[result.dork] = [];
    }
    groupedResults[result.dork].push(result);
  });

  // Group results by sector if available
  const sectorResults = results.sector_results || {};
  const sectorSummary = results.sector_summary || {};

  const exportToCsv = () => {
    let csvContent = "Dork,Title,URL,Snippet,Sector,Page\n";
   
    results.results.forEach(item => {
      const title = `"${(item.title || '').replace(/"/g, '""')}"`;
      const url = `"${item.link || ''}"`;
      const snippet = `"${(item.snippet || '').replace(/"/g, '""')}"`;
      const dork = `"${(item.dork || '').replace(/"/g, '""')}"`;
      const sector = `"${item.sector || 'unknown'}"`;
      const page = item.page || 1;
     
      csvContent += `${dork},${title},${url},${snippet},${sector},${page}\n`;
    });
   
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', `google_dorking_results_${target}_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getSectorColor = (sector) => {
    const colors = {
      'pemerintah': 'red',
      'rumah_sakit': 'blue',
      'universitas': 'green',
      'bumn': 'orange',
      'bank': 'purple',
      'kepolisian': 'cyan',
      'militer': 'magenta',
      'pengadilan': 'gold',
      'lainnya': 'default'
    };
    return colors[sector] || 'default';
  };

  const getRiskColor = (riskLevel) => {
    const colors = {
      'critical': '#ff4d4f',
      'high': '#ff7a45', 
      'medium': '#ffa940',
      'low': '#52c41a',
      'info': '#1890ff'
    };
    return colors[riskLevel] || '#d9d9d9';
  };

  return (
    <div className="dorking-results">
      <Card
        title={<Title level={3}>🔍 Google Dorking Results for {target}</Title>}
        extra={
          <Button 
            type="primary" 
            icon={<DownloadOutlined />}
            onClick={exportToCsv}
          >
            Export to CSV
          </Button>
        }
      >
        {/* Summary Statistics */}
        <Row gutter={16} style={{ marginBottom: 24 }}>
          <Col span={6}>
            <Statistic
              title="Total Results"
              value={results.results.length}
              prefix={<FileTextOutlined />}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Dorks Used"
              value={results.summary?.total_dorks || Object.keys(groupedResults).length}
              prefix={<PieChartOutlined />}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Unique Domains"
              value={results.summary?.domain_summary?.total_domains || 0}
              prefix={<GlobalOutlined />}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="Success Rate"
              value={results.summary?.successful_dorks && results.summary?.total_dorks ? 
                Math.round((results.summary.successful_dorks / results.summary.total_dorks) * 100) : 0}
              suffix="%"
              prefix={<ExclamationCircleOutlined />}
            />
          </Col>
        </Row>

        {/* Error Summary */}
        {results.errors && results.errors.length > 0 && (
          <Alert
            message={`${results.errors.length} dork(s) encountered errors`}
            description="Some dorks failed to execute. Check the detailed results below."
            type="warning"
            showIcon
            style={{ marginBottom: 16 }}
          />
        )}

        <Tabs activeKey={activeTab} onChange={setActiveTab}>
          {/* All Results Tab */}
          <TabPane tab={`All Results (${results.results.length})`} key="all">
            {Object.entries(groupedResults).map(([dork, dorkResults]) => (
              <Card
                key={dork}
                type="inner"
                title={
                  <div>
                    <Tag color="blue" style={{ fontFamily: 'monospace', fontSize: '12px' }}>
                      {dork}
                    </Tag>
                    <span style={{ marginLeft: 8 }}>({dorkResults.length} results)</span>
                  </div>
                }
                style={{ marginBottom: 16 }}
              >
                <List
                  itemLayout="vertical"
                  dataSource={dorkResults}
                  renderItem={item => (
                    <List.Item
                      actions={[
                        <Button 
                          type="link" 
                          icon={<LinkOutlined />} 
                          href={item.link} 
                          target="_blank"
                          rel="noopener noreferrer"
                        >
                          Open Link
                        </Button>
                      ]}
                    >
                      <List.Item.Meta
                        title={
                          <div>
                            <a href={item.link} target="_blank" rel="noopener noreferrer">
                              {item.title}
                            </a>
                            {item.sector && (
                              <Tag 
                                color={getSectorColor(item.sector)} 
                                style={{ marginLeft: 8 }}
                              >
                                {item.sector}
                              </Tag>
                            )}
                            {item.page && (
                              <Tag color="default" style={{ marginLeft: 4 }}>
                                Page {item.page}
                              </Tag>
                            )}
                          </div>
                        }
                        description={
                          <Text type="secondary" style={{ fontSize: '12px' }}>
                            {item.link}
                          </Text>
                        }
                      />
                      <div>{item.snippet}</div>
                    </List.Item>
                  )}
                />
              </Card>
            ))}
          </TabPane>

          {/* Sector Results Tab */}
          {Object.keys(sectorResults).length > 0 && (
            <TabPane tab="By Sector" key="sectors">
              <Row gutter={16} style={{ marginBottom: 16 }}>
                {Object.entries(sectorSummary.sector_counts || {}).map(([sector, count]) => {
                  const riskLevel = sectorSummary.risk_levels?.[sector] || 'info';
                  return (
                    <Col span={6} key={sector}>
                      <Card size="small">
                        <Statistic
                          title={sector.replace('_', ' ').toUpperCase()}
                          value={count}
                          valueStyle={{ color: getRiskColor(riskLevel) }}
                        />
                        <Progress
                          percent={Math.round((count / results.results.length) * 100)}
                          size="small"
                          strokeColor={getRiskColor(riskLevel)}
                        />
                        <Tag color={getSectorColor(sector)} size="small">
                          {riskLevel.toUpperCase()}
                        </Tag>
                      </Card>
                    </Col>
                  );
                })}
              </Row>

              {Object.entries(sectorResults).map(([sector, sectorData]) => {
                if (!sectorData || sectorData.length === 0) return null;
                
                return (
                  <Card
                    key={sector}
                    type="inner"
                    title={
                      <div>
                        <Tag color={getSectorColor(sector)}>
                          {sector.replace('_', ' ').toUpperCase()}
                        </Tag>
                        <span>({sectorData.length} results)</span>
                        {sectorSummary.risk_levels?.[sector] && (
                          <Tag 
                            color={getRiskColor(sectorSummary.risk_levels[sector])}
                            style={{ marginLeft: 8 }}
                          >
                            {sectorSummary.risk_levels[sector].toUpperCase()} RISK
                          </Tag>
                        )}
                      </div>
                    }
                    style={{ marginBottom: 16 }}
                  >
                    <List
                      itemLayout="vertical"
                      dataSource={sectorData}
                      renderItem={item => (
                        <List.Item
                          actions={[
                            <Button 
                              type="link" 
                              icon={<LinkOutlined />} 
                              href={item.link} 
                              target="_blank"
                              rel="noopener noreferrer"
                            >
                              Open Link
                            </Button>
                          ]}
                        >
                          <List.Item.Meta
                            title={<a href={item.link} target="_blank" rel="noopener noreferrer">{item.title}</a>}
                            description={item.link}
                          />
                          <div>{item.snippet}</div>
                        </List.Item>
                      )}
                    />
                  </Card>
                );
              })}
            </TabPane>
          )}

          {/* Domain Analysis Tab */}
          {results.summary?.domain_summary && (
            <TabPane tab="Domain Analysis" key="domains">
              <Card title="Top Domains">
                <List
                  dataSource={Object.entries(results.summary.domain_summary.domains || {})}
                  renderItem={([domain, count]) => (
                    <List.Item>
                      <List.Item.Meta
                        title={domain}
                        description={`${count} result(s) found`}
                      />
                      <Progress
                        percent={Math.round((count / results.results.length) * 100)}
                        size="small"
                        style={{ width: 200 }}
                      />
                    </List.Item>
                  )}
                />
              </Card>
            </TabPane>
          )}
        </Tabs>

        {/* Pagination Info */}
        {results.pagination_info && (
          <Card type="inner" size="small" style={{ marginTop: 16 }}>
            <Text type="secondary">
              Pagination: {results.pagination_info.total_pages_requested} pages per dork, 
              up to {results.pagination_info.max_results_per_page} results per page
            </Text>
          </Card>
        )}
      </Card>
    </div>
  );
};

export default GoogleDorkingResults;