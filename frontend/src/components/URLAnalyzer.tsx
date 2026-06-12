import React, { useState } from 'react';
import axios from 'axios';
import { Search, AlertTriangle, CheckCircle, Clock, Shield, Eye, FileText, ExternalLink } from 'lucide-react';

interface AnalysisResult {
  id: string;
  status: string;
  score: number;
  created_at: string;
  report_markdown?: string;
  enrichment?: any;
}

interface ThreatIntelResult {
  summary: {
    overall_risk: string;
    confidence: number;
    total_sources: number;
    malicious_count: number;
  };
  sources: Record<string, any>;
  recommendations: string[];
}

const URLAnalyzer: React.FC = () => {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [intelResult, setIntelResult] = useState<ThreatIntelResult | null>(null);
  const [error, setError] = useState('');
  const [showReport, setShowReport] = useState(false);

  const API_BASE = 'http://localhost:8001';

  const analyzeURL = async () => {
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    setLoading(true);
    setError('');
    setResult(null);
    setIntelResult(null);

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
          
          // Also get threat intelligence
          const intelResponse = await axios.post(`${API_BASE}/intel`, {
            url: url.trim()
          });
          setIntelResult(intelResponse.data as ThreatIntelResult);
          
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

  const getRiskColor = (score: number) => {
    if (score >= 0.8) return 'text-red-600 bg-red-50';
    if (score >= 0.5) return 'text-orange-600 bg-orange-50';
    return 'text-green-600 bg-green-50';
  };

  const getRiskLevel = (score: number) => {
    if (score >= 0.8) return 'HIGH RISK';
    if (score >= 0.5) return 'MEDIUM RISK';
    return 'LOW RISK';
  };

  const formatScore = (score: number) => {
    return (score * 100).toFixed(1) + '%';
  };

  return (
    <div className="space-y-6">
      {/* URL Input Section */}
      <div className="bg-white rounded-lg shadow-lg p-6">
        <div className="flex items-center space-x-3 mb-4">
          <Shield className="h-6 w-6 text-blue-600" />
          <h2 className="text-xl font-semibold text-gray-900">URL Threat Analysis</h2>
        </div>
        
        <div className="flex space-x-4">
          <div className="flex-1">
            <label htmlFor="url" className="block text-sm font-medium text-gray-700 mb-2">
              Enter URL to analyze
            </label>
            <input
              type="url"
              id="url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/suspicious-link"
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              onKeyPress={(e) => e.key === 'Enter' && analyzeURL()}
            />
          </div>
          <button
            onClick={analyzeURL}
            disabled={loading}
            className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center space-x-2 mt-7"
          >
            {loading ? (
              <>
                <Clock className="h-4 w-4 animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Search className="h-4 w-4" />
                <span>Analyze</span>
              </>
            )}
          </button>
        </div>

        {error && (
          <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="h-5 w-5 text-red-600" />
              <span className="text-red-800">{error}</span>
            </div>
          </div>
        )}
      </div>

      {/* Loading State */}
      {loading && (
        <div className="bg-white rounded-lg shadow-lg p-8">
          <div className="flex flex-col items-center space-y-4">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            <div className="text-center">
              <h3 className="text-lg font-semibold text-gray-900">Analyzing URL...</h3>
              <p className="text-gray-600">Running ML models and threat intelligence checks</p>
            </div>
            <div className="w-full max-w-md">
              <div className="bg-gray-200 rounded-full h-2">
                <div className="bg-blue-600 h-2 rounded-full animate-pulse" style={{width: '75%'}}></div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Results Section */}
      {result && (
        <div className="space-y-6">
          {/* Main Results Card */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-semibold text-gray-900">Analysis Results</h3>
              <div className="text-sm text-gray-500">
                {new Date(result.created_at).toLocaleString()}
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-6">
              {/* Risk Score */}
              <div className="text-center">
                <div className={`inline-flex items-center px-4 py-2 rounded-full text-lg font-semibold ${getRiskColor(result.score)}`}>
                  {result.score >= 0.5 ? (
                    <AlertTriangle className="h-5 w-5 mr-2" />
                  ) : (
                    <CheckCircle className="h-5 w-5 mr-2" />
                  )}
                  {getRiskLevel(result.score)}
                </div>
                <div className="mt-2">
                  <div className="text-3xl font-bold text-gray-900">{formatScore(result.score)}</div>
                  <div className="text-gray-600">Threat Score</div>
                </div>
              </div>

              {/* URL Info */}
              <div className="space-y-3">
                <div>
                  <label className="text-sm font-medium text-gray-700">Analyzed URL:</label>
                  <div className="flex items-center space-x-2 mt-1">
                    <code className="text-sm bg-gray-100 px-2 py-1 rounded break-all">{url}</code>
                    <ExternalLink className="h-4 w-4 text-gray-400" />
                  </div>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-700">Status:</label>
                  <div className="flex items-center space-x-2 mt-1">
                    <CheckCircle className="h-4 w-4 text-green-600" />
                    <span className="text-green-700 capitalize">{result.status}</span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Threat Intelligence Card */}
          {intelResult && (
            <div className="bg-white rounded-lg shadow-lg p-6">
              <h3 className="text-xl font-semibold text-gray-900 mb-4">Threat Intelligence</h3>
              
              <div className="grid md:grid-cols-3 gap-4 mb-6">
                <div className="text-center p-4 bg-gray-50 rounded-lg">
                  <div className="text-2xl font-bold text-gray-900">{intelResult.summary.total_sources}</div>
                  <div className="text-gray-600">Sources Checked</div>
                </div>
                <div className="text-center p-4 bg-gray-50 rounded-lg">
                  <div className="text-2xl font-bold text-red-600">{intelResult.summary.malicious_count}</div>
                  <div className="text-gray-600">Malicious Detections</div>
                </div>
                <div className="text-center p-4 bg-gray-50 rounded-lg">
                  <div className="text-2xl font-bold text-blue-600">{(intelResult.summary.confidence * 100).toFixed(0)}%</div>
                  <div className="text-gray-600">Confidence</div>
                </div>
              </div>

              {intelResult.recommendations.length > 0 && (
                <div>
                  <h4 className="font-medium text-gray-900 mb-2">Recommendations:</h4>
                  <ul className="space-y-1">
                    {intelResult.recommendations.slice(0, 3).map((rec, index) => (
                      <li key={index} className="flex items-start space-x-2">
                        <div className="w-1.5 h-1.5 bg-blue-600 rounded-full mt-2 flex-shrink-0"></div>
                        <span className="text-gray-700">{rec}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Report Section */}
          <div className="bg-white rounded-lg shadow-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-semibold text-gray-900">Detailed Report</h3>
              <button
                onClick={() => setShowReport(!showReport)}
                className="flex items-center space-x-2 px-4 py-2 bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors"
              >
                <Eye className="h-4 w-4" />
                <span>{showReport ? 'Hide' : 'Show'} Report</span>
              </button>
            </div>

            {showReport && result.report_markdown && (
              <div className="border border-gray-200 rounded-lg p-4 bg-gray-50">
                <div className="flex items-center space-x-2 mb-3">
                  <FileText className="h-4 w-4 text-gray-600" />
                  <span className="text-sm font-medium text-gray-700">Markdown Report</span>
                </div>
                <pre className="text-sm text-gray-800 whitespace-pre-wrap font-mono overflow-x-auto">
                  {result.report_markdown}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Demo URLs */}
      <div className="bg-blue-50 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-blue-900 mb-3">Try These Demo URLs:</h3>
        <div className="grid md:grid-cols-2 gap-2">
          {[
            { url: 'https://www.google.com', type: 'Legitimate' },
            { url: 'http://phishing-test.com/login', type: 'Suspicious' },
            { url: 'http://192.168.1.1/admin/login.php', type: 'Suspicious' },
            { url: 'https://verify-account.example-phishing.tk/update', type: 'Suspicious' }
          ].map((demo, index) => (
            <button
              key={index}
              onClick={() => setUrl(demo.url)}
              className="text-left p-3 bg-white rounded border hover:border-blue-300 transition-colors"
            >
              <div className="text-sm text-gray-900 font-mono">{demo.url}</div>
              <div className={`text-xs ${demo.type === 'Legitimate' ? 'text-green-600' : 'text-orange-600'}`}>
                {demo.type}
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default URLAnalyzer;
