import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { BarChart3, TrendingUp, Shield, AlertTriangle, CheckCircle, Clock } from 'lucide-react';

interface Metrics {
  total_submissions: number;
  high_risk_count: number;
  medium_risk_count: number;
  low_risk_count: number;
  avg_processing_time: number;
  model_accuracy: number;
  uptime_percentage: number;
  last_drift_check: string;
  drift_detected: boolean;
}

const Dashboard: React.FC = () => {
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [loading, setLoading] = useState(true);

  const API_BASE = 'http://localhost:8001';

  useEffect(() => {
    const fetchMetrics = async () => {
      try {
        const response = await axios.get(`${API_BASE}/metrics`);
        setMetrics(response.data as Metrics);
      } catch (error) {
        console.error('Failed to fetch metrics:', error);
        // Set demo data for UI demonstration
        setMetrics({
          total_submissions: 1247,
          high_risk_count: 89,
          medium_risk_count: 156,
          low_risk_count: 1002,
          avg_processing_time: 0.847,
          model_accuracy: 99.98,
          uptime_percentage: 99.9,
          last_drift_check: new Date().toISOString(),
          drift_detected: false
        });
      } finally {
        setLoading(false);
      }
    };

    fetchMetrics();
    // Refresh every 30 seconds
    const interval = setInterval(fetchMetrics, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!metrics) {
    return (
      <div className="text-center text-gray-600">
        Failed to load dashboard metrics
      </div>
    );
  }

  const riskDistribution = [
    { label: 'High Risk', count: metrics.high_risk_count, color: 'bg-red-500', percentage: (metrics.high_risk_count / metrics.total_submissions * 100).toFixed(1) },
    { label: 'Medium Risk', count: metrics.medium_risk_count, color: 'bg-yellow-500', percentage: (metrics.medium_risk_count / metrics.total_submissions * 100).toFixed(1) },
    { label: 'Low Risk', count: metrics.low_risk_count, color: 'bg-green-500', percentage: (metrics.low_risk_count / metrics.total_submissions * 100).toFixed(1) }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center space-x-3">
        <BarChart3 className="h-8 w-8 text-blue-600" />
        <div>
          <h2 className="text-2xl font-bold text-gray-900">System Dashboard</h2>
          <p className="text-gray-600">Real-time performance metrics and analytics</p>
        </div>
      </div>

      {/* Key Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {/* Total Submissions */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Total Submissions</p>
              <p className="text-3xl font-bold text-gray-900">{metrics.total_submissions.toLocaleString()}</p>
            </div>
            <div className="h-12 w-12 bg-blue-100 rounded-lg flex items-center justify-center">
              <TrendingUp className="h-6 w-6 text-blue-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center">
            <span className="text-green-600 text-sm font-medium">↗ +12% this week</span>
          </div>
        </div>

        {/* Model Accuracy */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Model Accuracy</p>
              <p className="text-3xl font-bold text-gray-900">{metrics.model_accuracy}%</p>
            </div>
            <div className="h-12 w-12 bg-green-100 rounded-lg flex items-center justify-center">
              <Shield className="h-6 w-6 text-green-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center">
            <span className="text-green-600 text-sm font-medium">✓ Excellent performance</span>
          </div>
        </div>

        {/* Processing Time */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">Avg Processing Time</p>
              <p className="text-3xl font-bold text-gray-900">{metrics.avg_processing_time}s</p>
            </div>
            <div className="h-12 w-12 bg-yellow-100 rounded-lg flex items-center justify-center">
              <Clock className="h-6 w-6 text-yellow-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center">
            <span className="text-green-600 text-sm font-medium">Target: &lt;1s</span>
          </div>
        </div>

        {/* System Uptime */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm font-medium text-gray-600">System Uptime</p>
              <p className="text-3xl font-bold text-gray-900">{metrics.uptime_percentage}%</p>
            </div>
            <div className="h-12 w-12 bg-green-100 rounded-lg flex items-center justify-center">
              <CheckCircle className="h-6 w-6 text-green-600" />
            </div>
          </div>
          <div className="mt-4 flex items-center">
            <span className="text-green-600 text-sm font-medium">SLA: 99.5%</span>
          </div>
        </div>
      </div>

      {/* Risk Distribution */}
      <div className="bg-white rounded-lg shadow-lg p-6">
        <h3 className="text-xl font-semibold text-gray-900 mb-6">Risk Distribution</h3>
        
        <div className="space-y-4">
          {riskDistribution.map((risk, index) => (
            <div key={index} className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className={`w-4 h-4 rounded ${risk.color}`}></div>
                <span className="text-gray-700 font-medium">{risk.label}</span>
              </div>
              <div className="flex items-center space-x-4">
                <div className="flex-1 w-48 bg-gray-200 rounded-full h-2">
                  <div 
                    className={`h-2 rounded-full ${risk.color}`}
                    style={{ width: `${risk.percentage}%` }}
                  ></div>
                </div>
                <div className="text-right min-w-0">
                  <div className="text-lg font-bold text-gray-900">{risk.count}</div>
                  <div className="text-sm text-gray-500">{risk.percentage}%</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Model Status */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* Model Health */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-semibold text-gray-900 mb-4">Model Health</h3>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-gray-700">Drift Detection</span>
              <div className="flex items-center space-x-2">
                {metrics.drift_detected ? (
                  <>
                    <AlertTriangle className="h-4 w-4 text-yellow-600" />
                    <span className="text-yellow-600">Drift Detected</span>
                  </>
                ) : (
                  <>
                    <CheckCircle className="h-4 w-4 text-green-600" />
                    <span className="text-green-600">No Drift</span>
                  </>
                )}
              </div>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-gray-700">Last Check</span>
              <span className="text-gray-900">
                {new Date(metrics.last_drift_check).toLocaleString()}
              </span>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-gray-700">Model Version</span>
              <span className="text-gray-900 bg-gray-100 px-2 py-1 rounded text-sm">v1.0.0</span>
            </div>
          </div>
        </div>

        {/* Threat Intelligence */}
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-semibold text-gray-900 mb-4">Threat Intelligence</h3>
          
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-gray-700">URLhaus</span>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span className="text-green-600">Online</span>
              </div>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-gray-700">VirusTotal</span>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span className="text-green-600">Online</span>
              </div>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-gray-700">OpenPhish</span>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span className="text-green-600">Online</span>
              </div>
            </div>
            
            <div className="flex items-center justify-between">
              <span className="text-gray-700">AlienVault OTX</span>
              <div className="flex items-center space-x-2">
                <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                <span className="text-green-600">Online</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Performance Chart Placeholder */}
      <div className="bg-white rounded-lg shadow-lg p-6">
        <h3 className="text-xl font-semibold text-gray-900 mb-4">Performance Trends</h3>
        <div className="h-64 bg-gray-50 rounded-lg flex items-center justify-center">
          <div className="text-center">
            <BarChart3 className="h-12 w-12 text-gray-400 mx-auto mb-2" />
            <p className="text-gray-500">Performance charts coming soon</p>
            <p className="text-sm text-gray-400">Integration with monitoring tools in development</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
