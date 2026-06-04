import React, { useState } from 'react';
import axios from 'axios';

interface AnalysisResult {
  id: string;
  status: string;
  score: number;
  created_at: string;
  report_markdown?: string;
}

const SimpleURLAnalyzer: React.FC = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState('');

  const API_BASE = 'http://localhost:8001';

  const analyzeURL = async () => {
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);

    try {
      // Submit URL for analysis
      const submitResponse = await axios.post(`${API_BASE}/submit-url`, {
        url: url.trim(),
        detonate: false
      });

      const submissionId = (submitResponse.data as any).id;
      
      // Wait for processing and get report
      setTimeout(async () => {
        try {
          const reportResponse = await axios.get(`${API_BASE}/report/${submissionId}`);
          setResult(reportResponse.data as AnalysisResult);
        } catch (err) {
          setError('Failed to get analysis results');
          console.error(err);
        }
        setLoading(false);
      }, 2000);

    } catch (err: any) {
      setError(err.response?.data?.detail || 'Analysis failed');
      setLoading(false);
    }
  };

  const getRiskLevel = (score: number) => {
    if (score >= 0.8) return { level: 'HIGH RISK', color: '#dc2626' };
    if (score >= 0.5) return { level: 'MEDIUM RISK', color: '#ea580c' };
    return { level: 'LOW RISK', color: '#16a34a' };
  };

  const styles = {
    container: {
      maxWidth: '800px',
      margin: '0 auto',
      padding: '20px',
      fontFamily: 'system-ui, sans-serif'
    },
    header: {
      background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
      color: 'white',
      padding: '30px',
      borderRadius: '12px',
      marginBottom: '30px',
      textAlign: 'center' as const
    },
    card: {
      backgroundColor: 'white',
      borderRadius: '12px',
      padding: '24px',
      boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
      marginBottom: '24px',
      border: '1px solid #e5e7eb'
    },
    input: {
      width: '100%',
      padding: '12px',
      border: '2px solid #d1d5db',
      borderRadius: '8px',
      fontSize: '16px',
      marginBottom: '16px',
      outline: 'none',
      transition: 'border-color 0.2s'
    },
    button: {
      backgroundColor: '#3b82f6',
      color: 'white',
      padding: '12px 24px',
      border: 'none',
      borderRadius: '8px',
      fontSize: '16px',
      cursor: 'pointer',
      transition: 'background-color 0.2s'
    },
    error: {
      backgroundColor: '#fef2f2',
      color: '#dc2626',
      padding: '12px',
      borderRadius: '8px',
      border: '1px solid #fecaca',
      marginTop: '16px'
    },
    loading: {
      textAlign: 'center' as const,
      padding: '40px',
      color: '#6b7280'
    },
    result: {
      padding: '20px',
      borderRadius: '8px',
      marginTop: '20px'
    },
    score: {
      fontSize: '48px',
      fontWeight: 'bold',
      textAlign: 'center' as const,
      marginBottom: '16px'
    },
    report: {
      backgroundColor: '#f9fafb',
      padding: '16px',
      borderRadius: '8px',
      marginTop: '16px',
      fontFamily: 'monospace',
      fontSize: '14px',
      whiteSpace: 'pre-wrap' as const,
      overflow: 'auto',
      maxHeight: '400px'
    }
  };

  return (
    <div style={styles.container}>
      {/* Header */}
      <div style={styles.header}>
        <h1 style={{ margin: '0 0 8px 0', fontSize: '32px' }}>🛡️ Phishing Triage System</h1>
        <p style={{ margin: '0', opacity: 0.9 }}>Advanced Threat Intelligence & ML Detection</p>
      </div>

      {/* URL Input */}
      <div style={styles.card}>
        <h2 style={{ marginTop: '0', color: '#374151' }}>URL Threat Analysis</h2>
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Enter URL to analyze (e.g., http://phishing-test.com/login)"
          style={styles.input}
          onKeyPress={(e) => e.key === 'Enter' && analyzeURL()}
        />
        <button
          onClick={analyzeURL}
          disabled={loading}
          style={{
            ...styles.button,
            backgroundColor: loading ? '#9ca3af' : '#3b82f6',
            cursor: loading ? 'not-allowed' : 'pointer'
          }}
        >
          {loading ? '🔄 Analyzing...' : '🔍 Analyze URL'}
        </button>

        {error && (
          <div style={styles.error}>
            ⚠️ {error}
          </div>
        )}
      </div>

      {/* Loading State */}
      {loading && (
        <div style={styles.card}>
          <div style={styles.loading}>
            <div style={{ fontSize: '48px', marginBottom: '16px' }}>🔄</div>
            <h3>Analyzing URL...</h3>
            <p>Running ML models and threat intelligence checks</p>
          </div>
        </div>
      )}

      {/* Results */}
      {result && (
        <div style={styles.card}>
          <h3 style={{ marginTop: '0', color: '#374151' }}>Analysis Results</h3>
          
          <div style={{
            ...styles.result,
            backgroundColor: getRiskLevel(result.score).color + '20',
            border: `2px solid ${getRiskLevel(result.score).color}`
          }}>
            <div style={{
              ...styles.score,
              color: getRiskLevel(result.score).color
            }}>
              {getRiskLevel(result.score).level}
            </div>
            
            <div style={{ textAlign: 'center', marginBottom: '20px' }}>
              <div style={{ fontSize: '24px', fontWeight: 'bold', marginBottom: '8px' }}>
                {(result.score * 100).toFixed(1)}% Threat Score
              </div>
              <div style={{ color: '#6b7280' }}>
                Analysis completed at {new Date(result.created_at).toLocaleString()}
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <strong>Analyzed URL:</strong> {url}
            </div>
            <div>
              <strong>Status:</strong> <span style={{ color: '#16a34a' }}>✅ {result.status}</span>
            </div>
          </div>

          {result.report_markdown && (
            <div>
              <h4 style={{ color: '#374151', marginBottom: '12px' }}>📄 Detailed Report</h4>
              <div style={styles.report}>
                {result.report_markdown}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Demo URLs */}
      <div style={{
        ...styles.card,
        backgroundColor: '#eff6ff',
        border: '1px solid #bfdbfe'
      }}>
        <h3 style={{ marginTop: '0', color: '#1e40af' }}>🎯 Try These Demo URLs:</h3>
        <div style={{ display: 'grid', gap: '8px' }}>
          {[
            { url: 'https://www.google.com', type: 'Legitimate', color: '#16a34a' },
            { url: 'http://phishing-test.com/login', type: 'Suspicious', color: '#ea580c' },
            { url: 'http://192.168.1.1/admin/login.php', type: 'Suspicious', color: '#ea580c' },
            { url: 'https://verify-account.example-phishing.tk/update', type: 'Suspicious', color: '#ea580c' }
          ].map((demo, index) => (
            <button
              key={index}
              onClick={() => setUrl(demo.url)}
              style={{
                padding: '12px',
                backgroundColor: 'white',
                border: '1px solid #d1d5db',
                borderRadius: '8px',
                cursor: 'pointer',
                textAlign: 'left' as const,
                transition: 'border-color 0.2s'
              }}
              onMouseOver={(e) => e.currentTarget.style.borderColor = '#3b82f6'}
              onMouseOut={(e) => e.currentTarget.style.borderColor = '#d1d5db'}
            >
              <div style={{ fontFamily: 'monospace', fontSize: '14px', marginBottom: '4px' }}>
                {demo.url}
              </div>
              <div style={{ fontSize: '12px', color: demo.color, fontWeight: 'bold' }}>
                {demo.type}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Footer */}
      <div style={{
        textAlign: 'center',
        marginTop: '40px',
        padding: '20px',
        color: '#6b7280',
        borderTop: '1px solid #e5e7eb'
      }}>
        <p><strong>Built by Huy Tran</strong> - Advanced Cybersecurity & ML Engineering Project</p>
        <p>
          <a href="https://github.com/itsnothuy/Phishing-Triage" target="_blank" rel="noopener noreferrer" style={{ color: '#3b82f6' }}>
            📖 GitHub Repository
          </a>
          {' | '}
          <a href="http://localhost:8001/docs" target="_blank" rel="noopener noreferrer" style={{ color: '#3b82f6' }}>
            🔧 API Documentation
          </a>
        </p>
      </div>
    </div>
  );
};

export default SimpleURLAnalyzer;

