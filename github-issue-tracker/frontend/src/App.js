import React, { useState, useEffect } from 'react';
import './App.css';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000';

function App() {
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const [username, setUsername] = useState(localStorage.getItem('username') || '');
  const [isLogin, setIsLogin] = useState(true);
  const [issues, setIssues] = useState([]);
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    title: '',
    description: '',
    status: 'Open'
  });
  const [editingIssue, setEditingIssue] = useState(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    if (token) {
      fetchIssues();
    }
  }, [token]);

  const handleInputChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleAuth = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    const endpoint = isLogin ? '/api/login' : '/api/register';
    
    try {
      const response = await fetch(`${API_URL}${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: formData.username,
          password: formData.password
        })
      });

      const data = await response.json();

      if (response.ok) {
        if (isLogin) {
          setToken(data.token);
          setUsername(data.username);
          localStorage.setItem('token', data.token);
          localStorage.setItem('username', data.username);
          setSuccess('Login successful!');
          setFormData({ ...formData, username: '', password: '' });
        } else {
          setSuccess('Registration successful! Please login.');
          setIsLogin(true);
          setFormData({ ...formData, username: '', password: '' });
        }
      } else {
        setError(data.error || 'Authentication failed');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    }
  };

  const fetchIssues = async () => {
    try {
      const response = await fetch(`${API_URL}/api/issues`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const data = await response.json();
        setIssues(data);
      } else if (response.status === 401) {
        handleLogout();
      }
    } catch (err) {
      setError('Failed to fetch issues');
    }
  };

  const handleCreateIssue = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    try {
      const response = await fetch(`${API_URL}/api/issues`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          title: formData.title,
          description: formData.description,
          status: formData.status
        })
      });

      const data = await response.json();

      if (response.ok) {
        setSuccess('Issue created successfully!');
        setFormData({ ...formData, title: '', description: '', status: 'Open' });
        fetchIssues();
      } else {
        setError(data.error || 'Failed to create issue');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    }
  };

  const handleUpdateIssue = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    try {
      const response = await fetch(`${API_URL}/api/issues/${editingIssue.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({
          title: formData.title,
          description: formData.description,
          status: formData.status
        })
      });

      const data = await response.json();

      if (response.ok) {
        setSuccess('Issue updated successfully!');
        setEditingIssue(null);
        setFormData({ ...formData, title: '', description: '', status: 'Open' });
        fetchIssues();
      } else {
        setError(data.error || 'Failed to update issue');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    }
  };

  const handleDeleteIssue = async (issueId) => {
    if (!window.confirm('Are you sure you want to delete this issue?')) {
      return;
    }

    setError('');
    setSuccess('');

    try {
      const response = await fetch(`${API_URL}/api/issues/${issueId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        setSuccess('Issue deleted successfully!');
        fetchIssues();
      } else {
        setError('Failed to delete issue');
      }
    } catch (err) {
      setError('Network error. Please try again.');
    }
  };

  const handleEditClick = (issue) => {
    setEditingIssue(issue);
    setFormData({
      ...formData,
      title: issue.title,
      description: issue.description,
      status: issue.status
    });
  };

  const handleCancelEdit = () => {
    setEditingIssue(null);
    setFormData({ ...formData, title: '', description: '', status: 'Open' });
  };

  const handleLogout = () => {
    setToken('');
    setUsername('');
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    setIssues([]);
    setFormData({
      username: '',
      password: '',
      title: '',
      description: '',
      status: 'Open'
    });
  };

  if (!token) {
    return (
      <div className="App">
        <div className="auth-container">
          <h1>GitHub Issue Tracker</h1>
          <div className="auth-toggle">
            <button 
              className={isLogin ? 'active' : ''} 
              onClick={() => setIsLogin(true)}
            >
              Login
            </button>
            <button 
              className={!isLogin ? 'active' : ''} 
              onClick={() => setIsLogin(false)}
            >
              Register
            </button>
          </div>

          {error && <div className="error-message">{error}</div>}
          {success && <div className="success-message">{success}</div>}

          <form onSubmit={handleAuth} className="auth-form">
            <div className="form-group">
              <label>Username:</label>
              <input
                type="text"
                name="username"
                value={formData.username}
                onChange={handleInputChange}
                required
                maxLength="80"
              />
            </div>
            <div className="form-group">
              <label>Password:</label>
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleInputChange}
                required
                minLength="6"
              />
            </div>
            <button type="submit" className="btn-primary">
              {isLogin ? 'Login' : 'Register'}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="App">
      <header className="app-header">
        <h1>GitHub Issue Tracker</h1>
        <div className="user-info">
          <span>Welcome, {username}!</span>
          <button onClick={handleLogout} className="btn-secondary">Logout</button>
        </div>
      </header>

      {error && <div className="error-message">{error}</div>}
      {success && <div className="success-message">{success}</div>}

      <div className="main-container">
        <div className="issue-form-container">
          <h2>{editingIssue ? 'Edit Issue' : 'Create New Issue'}</h2>
          <form onSubmit={editingIssue ? handleUpdateIssue : handleCreateIssue} className="issue-form">
            <div className="form-group">
              <label>Title:</label>
              <input
                type="text"
                name="title"
                value={formData.title}
                onChange={handleInputChange}
                required
                maxLength="200"
                placeholder="Enter issue title"
              />
            </div>
            <div className="form-group">
              <label>Description:</label>
              <textarea
                name="description"
                value={formData.description}
                onChange={handleInputChange}
                required
                maxLength="1000"
                rows="4"
                placeholder="Describe the issue"
              />
            </div>
            <div className="form-group">
              <label>Status:</label>
              <select
                name="status"
                value={formData.status}
                onChange={handleInputChange}
              >
                <option value="Open">Open</option>
                <option value="In Progress">In Progress</option>
                <option value="Closed">Closed</option>
              </select>
            </div>
            <div className="form-buttons">
              <button type="submit" className="btn-primary">
                {editingIssue ? 'Update Issue' : 'Create Issue'}
              </button>
              {editingIssue && (
                <button type="button" onClick={handleCancelEdit} className="btn-secondary">
                  Cancel
                </button>
              )}
            </div>
          </form>
        </div>

        <div className="issues-container">
          <h2>All Issues ({issues.length})</h2>
          {issues.length === 0 ? (
            <p className="no-issues">No issues found. Create your first issue!</p>
          ) : (
            <div className="issues-list">
              {issues.map((issue) => (
                <div key={issue.id} className={`issue-card status-${issue.status.toLowerCase().replace(' ', '-')}`}>
                  <div className="issue-header">
                    <h3>{issue.title}</h3>
                    <span className={`status-badge ${issue.status.toLowerCase().replace(' ', '-')}`}>
                      {issue.status}
                    </span>
                  </div>
                  <p className="issue-description">{issue.description}</p>
                  <div className="issue-footer">
                    <span className="issue-date">
                      Created: {new Date(issue.created_at).toLocaleDateString()}
                    </span>
                    <div className="issue-actions">
                      <button onClick={() => handleEditClick(issue)} className="btn-edit">
                        Edit
                      </button>
                      <button onClick={() => handleDeleteIssue(issue.id)} className="btn-delete">
                        Delete
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;