// frontend/src/pages/ScanResultsPage.jsx
import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useSelector } from 'react-redux';
import api from '../utils/api';
import VirusTotalResults from '../components/scanners/VirusTotalResults';
import PortScanner from '../components/scanners/PortScanner';
import SSLResults from '../components/scanners/SSLResults';
import SubdomainResults from '../components/scanners/SubdomainResults';
import GoogleDorkingResults from '../components/scanners/GoogleDorkingResults';
import PoisoningResults from '../components/scanners/PoisoningResults';
import WebVulnerabilityScanner from '../components/scanners/WebVulnerabilityScanner';

import { 
  Box, 
  Typography, 
  Paper, 
  Button, 
  CircularProgress, 
  LinearProgress,
  Alert,
  Divider,
  Container,
  IconButton
} from '@mui/material';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';

const ScanResultsPage = () => {
  const { scanId } = useParams();
  const navigate = useNavigate();
  
  const [isLoading, setIsLoading] = useState(true);
  const [scanData, setScanData] = useState(null);
  const [error, setError] = useState(null);

  // Debug info
  const [debug, setDebug] = useState({
    scanId: scanId,
    attempts: 0
  });
  
  useEffect(() => {
    const fetchScanResult = async () => {
      try {
        setIsLoading(true);
        console.log(`Fetching scan result for scanId: ${scanId}`);
        
        let response = null;
        
        // Pertama coba endpoint VirusTotal
        try {
          console.log("Attempting to fetch from VirusTotal status endpoint");
          response = await api.getVirusTotalScanStatus(scanId);
          console.log("VirusTotal scan data received:", response);
          
          if (response && response.success) {
            // Pastikan data memiliki format yang konsisten
            let processedData = {
              scan_id: response.scan_id || scanId,
              scan_type: response.scan_type || 'virustotal_url',
              target: response.target || 'Unknown Target',
              status: response.status || 'completed',
              results: response.data || response.results || {},
              created_at: response.created_at || new Date().toISOString(),
              completed_at: response.completed_at || new Date().toISOString()
            };
            
            console.log("Setting scan data:", processedData);
            setScanData(processedData);
          } else {
            console.error("Invalid response from VirusTotal API");
            throw new Error("Invalid response format");
          }
        } catch (err) {
          console.error("Error fetching VirusTotal scan:", err);
          
          // Coba endpoint lain jika tersedia
          console.log("Attempting to fetch from generic scan history");
          try {
            const historyScan = await api.getScanDetails(scanId);
            console.log("History scan data:", historyScan);
            if (historyScan) {
              setScanData(historyScan);
            } else {
              setError("Scan not found in history");
            }
          } catch (historyErr) {
            console.error("Error fetching from scan history:", historyErr);
            setError("Failed to retrieve scan data from any source");
          }
        }
        
        // Update debug info
        setDebug(prev => ({
          ...prev,
          attempts: prev.attempts + 1,
          lastResponse: response ? 'success' : 'failed',
          timestamp: new Date().toISOString()
        }));
        
      } catch (err) {
        console.error("Error fetching scan results:", err);
        setError(err.response?.data?.error || "Failed to load scan results");
      } finally {
        setIsLoading(false);
      }
    };
    
    if (scanId) {
      fetchScanResult();
    }
  }, [scanId]);
  
  const renderResults = () => {
    if (!scanData) {
      console.log("No scan data to render");
      return null;
    }
    
    console.log("Rendering results for scan type:", scanData.scan_type);
    
    const scanType = scanData.scan_type;
    
    switch (scanType) {
      case 'port_scanner':
        return <PortScanner results={scanData.results} loading={isLoading} />;
      case 'ssl_scanner':
        return <SSLResults results={scanData.results} loading={isLoading} />;
      case 'web_scanner':
        return <WebVulnerabilityScanner results={scanData.results} loading={isLoading} />;
      case 'subdomain_scanner':
        return <SubdomainResults results={scanData.results} loading={isLoading} />;
      case 'google_dorking_scanner':
        return <GoogleDorkingResults results={scanData.results} loading={isLoading} />;
      case 'poisoning_scanner':
        return <PoisoningResults results={scanData.results} loading={isLoading} />;
      case 'virustotal_url':
      case 'virustotal_file':
        console.log("Rendering VirusTotal results with data:", scanData.results);
        return <VirusTotalResults results={scanData.results} loading={isLoading} />;
      default:
        console.log("Using fallback results component for type:", scanType);
        return (
          <Paper sx={{ p: 3, mb: 2 }}>
            <Typography variant="h6">Scan Results</Typography>
            <Divider sx={{ my: 2 }} />
            <Typography variant="body1">
              Raw results for scan type: {scanType}
            </Typography>
            <Box sx={{ mt: 2, p: 2, bgcolor: '#f5f5f5', borderRadius: 1, overflow: 'auto', maxHeight: '400px' }}>
              <pre>{JSON.stringify(scanData.results, null, 2)}</pre>
            </Box>
          </Paper>
        );
    }
  };
  
  if (isLoading) {
    return (
      <Container maxWidth="lg" sx={{ mt: 3 }}>
        <Box display="flex" flexDirection="column" alignItems="center" justifyContent="center" minHeight="50vh">
          <CircularProgress />
          <Typography variant="h6" sx={{ mt: 2 }}>Loading scan results...</Typography>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            Scan ID: {scanId}
          </Typography>
        </Box>
      </Container>
    );
  }
  
  if (error) {
    return (
      <Container maxWidth="lg" sx={{ mt: 3 }}>
        <Paper sx={{ p: 3 }}>
          <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>
          <Typography variant="body2" sx={{ mb: 2 }}>
            Debug info: Scan ID {scanId}, Attempts: {debug.attempts}, 
            Last attempt: {debug.timestamp}
          </Typography>
          <Button 
            variant="contained"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate('/scan-history')}
          >
            Back to Scan History
          </Button>
        </Paper>
      </Container>
    );
  }
  
  if (!scanData) {
    return (
      <Container maxWidth="lg" sx={{ mt: 3 }}>
        <Paper sx={{ p: 3 }}>
          <Alert severity="warning">Scan not found</Alert>
          <Typography variant="body2" sx={{ mt: 2, mb: 2 }}>
            Debug info: Scan ID {scanId}, Attempts: {debug.attempts}, 
            Last attempt: {debug.timestamp}
          </Typography>
          <Button 
            variant="contained"
            startIcon={<ArrowBackIcon />}
            onClick={() => navigate('/scan-history')}
            sx={{ mt: 2 }}
          >
            Back to Scan History
          </Button>
        </Paper>
      </Container>
    );
  }
  
  if (scanData.status === 'running') {
    return (
      <Container maxWidth="lg" sx={{ mt: 3 }}>
        <Paper sx={{ p: 3 }}>
          <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
            <Typography variant="h5">Scan in Progress</Typography>
            <IconButton onClick={() => navigate('/scan-history')}>
              <ArrowBackIcon />
            </IconButton>
          </Box>
          
          <Divider sx={{ mb: 3 }} />
          
          <Box sx={{ mb: 2 }}>
            <Typography variant="subtitle1" gutterBottom>
              <strong>Target:</strong> {scanData.target}
            </Typography>
            <Typography variant="subtitle2" gutterBottom>
              <strong>Scan Type:</strong> {scanData.scan_type.replace('_', ' ').toUpperCase()}
            </Typography>
          </Box>
          
          <Box sx={{ mb: 3 }}>
            <LinearProgress />
            <Typography variant="body2" align="center" sx={{ mt: 1 }}>
              Your scan is being processed. This might take a few minutes.
            </Typography>
          </Box>
          
          <Button variant="outlined" onClick={() => window.location.reload()}>
            Refresh Status
          </Button>
        </Paper>
      </Container>
    );
  }
  
  if (scanData.status === 'failed') {
    return (
      <Container maxWidth="lg" sx={{ mt: 3 }}>
        <Paper sx={{ p: 3 }}>
          <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
            <Typography variant="h5">Scan Failed</Typography>
            <IconButton onClick={() => navigate('/scan-history')}>
              <ArrowBackIcon />
            </IconButton>
          </Box>
          
          <Divider sx={{ mb: 3 }} />
          
          <Alert severity="error" sx={{ mb: 3 }}>
            {scanData.error || "An unknown error occurred during the scan"}
          </Alert>
          
          <Box sx={{ mb: 3 }}>
            <Typography variant="subtitle1" gutterBottom>
              <strong>Target:</strong> {scanData.target}
            </Typography>
            <Typography variant="subtitle2" gutterBottom>
              <strong>Scan Type:</strong> {scanData.scan_type.replace('_', ' ').toUpperCase()}
            </Typography>
            <Typography variant="body2" gutterBottom>
              <strong>Started:</strong> {new Date(scanData.created_at).toLocaleString()}
            </Typography>
          </Box>
          
          <Button 
            variant="contained"
            onClick={() => navigate('/new-scan')}
          >
            Start New Scan
          </Button>
        </Paper>
      </Container>
    );
  }
  
  // Scan completed successfully
  return (
    <Container maxWidth="lg" sx={{ mt: 3 }}>
      <Box mb={3}>
        <Button 
          variant="outlined"
          startIcon={<ArrowBackIcon />}
          onClick={() => navigate('/scan-history')}
        >
          Back to Scan History
        </Button>
      </Box>
      
      <Paper sx={{ p: 3, mb: 2 }}>
        <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
          <Typography variant="h5">Scan Details</Typography>
        </Box>
        
        <Divider sx={{ mb: 2 }} />
        
        <Box sx={{ mb: 3 }}>
          <Typography variant="subtitle1" gutterBottom>
            <strong>Target:</strong> {scanData.target}
          </Typography>
          <Typography variant="subtitle2" gutterBottom>
            <strong>Scan Type:</strong> {scanData.scan_type.replace('_', ' ').toUpperCase()}
          </Typography>
          <Typography variant="body2" gutterBottom>
            <strong>Started:</strong> {new Date(scanData.created_at).toLocaleString()}
          </Typography>
          {scanData.completed_at && (
            <Typography variant="body2" gutterBottom>
              <strong>Completed:</strong> {new Date(scanData.completed_at).toLocaleString()}
            </Typography>
          )}
        </Box>
      </Paper>
      
      {renderResults()}
    </Container>
  );
};

export default ScanResultsPage;