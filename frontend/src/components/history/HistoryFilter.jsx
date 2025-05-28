// frontend/src/components/history/HistoryFilter.jsx
import React from 'react';
import { FaSearch } from 'react-icons/fa';

const HistoryFilter = ({ onFilterChange, currentFilters }) => {
  const handleChange = (e) => {
    const { name, value } = e.target;
    onFilterChange({
      ...currentFilters,
      [name]: value
    });
  };

  const handleClear = () => {
    onFilterChange({});
  };

  return (
    <div className="history-filter card">
      <div className="filter-grid">
        <div className="filter-item">
          <label>Target</label>
          <div className="search-input">
            <FaSearch />
            <input
              type="text"
              name="target"
              placeholder="Search by target..."
              value={currentFilters.target || ''}
              onChange={handleChange}
            />
          </div>
        </div>
        
        <div className="filter-item">
          <label>Scan Type</label>
          <select
            name="scanType"
            value={currentFilters.scanType || ''}
            onChange={handleChange}
          >
            <option value="">All Types</option>
            <option value="port">Port Scan</option>
            <option value="ssl">SSL Scan</option>
            <option value="web">Web Scan</option>
            <option value="subdomain">Subdomain Scan</option>
          </select>
        </div>
        
        <div className="filter-item">
          <label>Status</label>
          <select
            name="status"
            value={currentFilters.status || ''}
            onChange={handleChange}
          >
            <option value="">All Status</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </div>
        
        <div className="filter-item">
          <label>Date From</label>
          <input
            type="date"
            name="dateFrom"
            value={currentFilters.dateFrom || ''}
            onChange={handleChange}
          />
        </div>
        
        <div className="filter-item">
          <label>Date To</label>
          <input
            type="date"
            name="dateTo"
            value={currentFilters.dateTo || ''}
            onChange={handleChange}
          />
        </div>
        
        <div className="filter-item filter-actions">
          <button 
            className="btn btn-secondary"
            onClick={handleClear}
          >
            Clear Filters
          </button>
        </div>
      </div>
    </div>
  );
};

export default HistoryFilter;