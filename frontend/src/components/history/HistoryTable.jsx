// frontend/src/components/history/HistoryTable.jsx
import React from 'react';
import { FaEye, FaTrash, FaRedo, FaSort, FaSortUp, FaSortDown } from 'react-icons/fa';

const HistoryTable = ({ history, onDelete, onViewDetails, onSort, sortBy, sortOrder }) => {
  const formatDate = (dateString) => {
    const date = new Date(dateString);
    return date.toLocaleString();
  };

  const getScanTypeLabel = (type) => {
    const labels = {
      'port': 'Port Scan',
      'ssl': 'SSL Scan',
      'web': 'Web Scan',
      'subdomain': 'Subdomain Scan'
    };
    return labels[type] || type;
  };

  const getStatusBadge = (status) => {
    const badges = {
      'completed': 'badge-success',
      'failed': 'badge-danger',
      'cancelled': 'badge-warning'
    };
    return badges[status] || 'badge-secondary';
  };

  const getSortIcon = (field) => {
    if (sortBy !== field) return <FaSort />;
    return sortOrder === 'asc' ? <FaSortUp /> : <FaSortDown />;
  };

  return (
    <div className="history-table-container">
      <table className="history-table">
        <thead>
          <tr>
            <th onClick={() => onSort('timestamp')} className="sortable">
              Date {getSortIcon('timestamp')}
            </th>
            <th onClick={() => onSort('target')} className="sortable">
              Target {getSortIcon('target')}
            </th>
            <th onClick={() => onSort('scanType')} className="sortable">
              Type {getSortIcon('scanType')}
            </th>
            <th>Status</th>
            <th>Duration</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {history.map((scan) => (
            <tr key={scan.id}>
              <td>{formatDate(scan.timestamp)}</td>
              <td className="target-cell">{scan.target}</td>
              <td>{getScanTypeLabel(scan.scanType)}</td>
              <td>
                <span className={`badge ${getStatusBadge(scan.status)}`}>
                  {scan.status}
                </span>
              </td>
              <td>{scan.duration || '-'}</td>
              <td className="actions-cell">
                <button
                  className="btn-icon"
                  onClick={() => onViewDetails(scan)}
                  title="View Details"
                >
                  <FaEye />
                </button>
                <button
                  className="btn-icon btn-danger"
                  onClick={() => onDelete(scan.id)}
                  title="Delete"
                >
                  <FaTrash />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};

export default HistoryTable;