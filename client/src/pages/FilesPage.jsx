import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import apiClient from '../utils/api';
import './FilesPage.css';

function FilesPage() {
  const [files, setFiles] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  const currentUserId = localStorage.getItem('userId');
  const currentUsername = localStorage.getItem('username');

  useEffect(() => {
    // Check if user is logged in
    if (!localStorage.getItem('authToken')) {
      navigate('/login');
      return;
    }
  }, [navigate]);

  const handleFileSelect = (e) => {
    setSelectedFile(e.target.files[0]);
  };

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!selectedFile || !currentUserId) return;

    setLoading(true);
    setError('');

    try {
      // Generate dummy storage path (placeholder)
      const storagePath = `/uploads/${Date.now()}_${selectedFile.name}`;

      // Send only metadata to backend
      // API request includes JWT token via axios interceptor
      // senderId is automatically set from JWT token on backend
      await apiClient.post('/files/metadata', {
        receiverId: '1', // Dummy receiver ID for now
        filename: selectedFile.name,
        filesize: selectedFile.size,
        storagePath: storagePath,
        timestamp: new Date().toISOString()
      });

      // Reset form
      setSelectedFile(null);
      document.querySelector('input[type="file"]').value = '';

      // Show success message (in a real app, you'd reload the file list)
      alert('File metadata uploaded successfully!');
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to upload file metadata');
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('authToken');
    localStorage.removeItem('userId');
    localStorage.removeItem('username');
    navigate('/login');
  };

  return (
    <div className="files-page">
      <div className="files-header">
        <h2>Secure File Sharing</h2>
        <div className="user-info">
          <span>Logged in as: {currentUsername}</span>
          <button onClick={handleLogout} className="logout-btn">Logout</button>
        </div>
      </div>
      <div className="files-container">
        <div className="upload-section">
          <h3>Upload File Metadata</h3>
          <form onSubmit={handleUpload} className="upload-form">
            <div className="form-group">
              <label htmlFor="file-input">Select File</label>
              <input
                type="file"
                id="file-input"
                onChange={handleFileSelect}
                disabled={loading}
              />
              {selectedFile && (
                <div className="file-info">
                  <p><strong>Name:</strong> {selectedFile.name}</p>
                  <p><strong>Size:</strong> {(selectedFile.size / 1024).toFixed(2)} KB</p>
                </div>
              )}
            </div>
            {error && <div className="error-message">{error}</div>}
            <button type="submit" disabled={loading || !selectedFile}>
              {loading ? 'Uploading...' : 'Upload Metadata'}
            </button>
          </form>
        </div>
        <div className="files-list-section">
          <h3>File Metadata List</h3>
          <div className="files-list">
            <p className="info-text">
              File metadata will appear here after upload. 
              (Note: This is a skeleton - file list fetching will be implemented later)
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default FilesPage;

