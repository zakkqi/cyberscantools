// frontend/src/store/scanSlice.js (tambahkan bagian VirusTotal)
import { createSlice } from '@reduxjs/toolkit';

const scanSlice = createSlice({
  name: 'scan',
  initialState: {
    activeScan: null,
    scanHistory: [],
    // Tambahkan state untuk VirusTotal
    virusTotal: {
      loading: false,
      error: null,
      target: null,
      scanType: null,
      analysisId: null,
      results: null,
      scanning: false
    }
  },
  reducers: {
    // Reducer untuk web scanning
    startScan: (state, action) => {
      state.activeScan = {
        scanId: action.payload.scanId,
        target: action.payload.target,
        scanner: action.payload.scanner,
        progress: 0,
        phase: 'Initializing',
        status: 'running',
        error: null,
        results: null
      };
    },
    updateScanProgress: (state, action) => {
      if (state.activeScan && state.activeScan.scanId === action.payload.scanId) {
        state.activeScan.progress = action.payload.progress;
        state.activeScan.phase = action.payload.phase;
      }
    },
    completeScan: (state, action) => {
      if (state.activeScan && state.activeScan.scanId === action.payload.scanId) {
        state.activeScan.status = 'completed';
        state.activeScan.progress = 100;
        state.activeScan.results = action.payload.results;
        
        // Add to history
        state.scanHistory.unshift({
          id: state.activeScan.scanId,
          timestamp: new Date().toISOString(),
          target: state.activeScan.target,
          scanner: state.activeScan.scanner,
          results: action.payload.results
        });
        
        // Keep only last 50 items
        if (state.scanHistory.length > 50) {
          state.scanHistory.pop();
        }
      }
    },
    scanError: (state, action) => {
      if (state.activeScan && state.activeScan.scanId === action.payload.scanId) {
        state.activeScan.status = 'error';
        state.activeScan.error = action.payload.error;
      }
    },
    
    // Reducer untuk VirusTotal scanning
    startVirusTotalScan: (state, action) => {
      state.virusTotal = {
        loading: true,
        error: null,
        target: action.payload.target,
        scanType: action.payload.type,
        analysisId: null,
        results: null,
        scanning: true
      };
    },
    updateVirusTotalProgress: (state, action) => {
      state.virusTotal.loading = false;
      state.virusTotal.analysisId = action.payload.analysisId;
      state.virusTotal.status = action.payload.status;
    },
    completeVirusTotalScan: (state, action) => {
      state.virusTotal.scanning = false;
      state.virusTotal.loading = false;
      state.virusTotal.results = action.payload.results;
    },
    virusTotalScanError: (state, action) => {
      state.virusTotal.scanning = false;
      state.virusTotal.loading = false;
      state.virusTotal.error = action.payload.error;
    },
    resetVirusTotal: (state) => {
      state.virusTotal = {
        loading: false,
        error: null,
        target: null,
        scanType: null,
        analysisId: null,
        results: null,
        scanning: false
      };
    }
  }
});

export const { 
  startScan, 
  updateScanProgress, 
  completeScan, 
  scanError,
  startVirusTotalScan,
  updateVirusTotalProgress,
  completeVirusTotalScan,
  virusTotalScanError,
  resetVirusTotal
} = scanSlice.actions;

export default scanSlice.reducer;