/**
 * EnhancedAnalysisForm - Advanced form component with AI analysis integration
 * Replaces the basic form with AI-powered analysis capabilities
 */

import React, { useState, useCallback } from 'react';
import { AnalysisService } from './AnalysisService';
import AnalysisResultCard from './AnalysisResultCard';
import './EnhancedAnalysisForm.css';

const EnhancedAnalysisForm = ({ apiBaseUrl = 'http://localhost:8000/api/v1' }) => {
  const [analysisService] = useState(() => new AnalysisService(apiBaseUrl));
  
  // Form state
  const [address, setAddress] = useState('');
  const [addresses, setAddresses] = useState('');
  const [isBatchMode, setIsBatchMode] = useState(false);
  const [options, setOptions] = useState({
    include_recommendations: true,
    check_breach_data: true,
    deep_analysis: false,
    include_attribution: true,
    include_crime_history: true,
    explanation_level: 'standard'
  });

  // Analysis state
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState(null);
  const [apiHealth, setApiHealth] = useState(null);

  // Health check on component mount
  React.useEffect(() => {
    checkApiHealth();
  }, []);

  const checkApiHealth = async () => {
    try {
      const health = await analysisService.checkHealth();
      setApiHealth(health);
    } catch (err) {
      setApiHealth({ status: 'error', error: err.message });
    }
  };

  const handleSingleAnalysis = useCallback(async (addressToAnalyze = null) => {
    const targetAddress = addressToAnalyze || address;
    
    if (!targetAddress.trim()) {
      setError('Please enter an address to analyze');
      return;
    }

    setIsAnalyzing(true);
    setError(null);

    try {
      const result = await analysisService.analyzeAddress(targetAddress, options);
      setResults([result]);
    } catch (err) {
      setError(`Analysis failed: ${err.message}`);
      console.error('Analysis error:', err);
    } finally {
      setIsAnalyzing(false);
    }
  }, [address, options, analysisService]);

  const handleBatchAnalysis = useCallback(async () => {
    const addressList = addresses
      .split(/[\n,;]/)
      .map(addr => addr.trim())
      .filter(addr => addr.length > 0);

    if (addressList.length === 0) {
      setError('Please enter at least one address for batch analysis');
      return;
    }

    if (addressList.length > 50) {
      setError('Maximum 50 addresses allowed per batch');
      return;
    }

    setIsAnalyzing(true);
    setError(null);

    try {
      const batchResult = await analysisService.analyzeBatch(addressList, options);
      setResults(batchResult.results);
      
      if (batchResult.summary.failed > 0) {
        setError(`${batchResult.summary.failed} addresses failed to analyze`);
      }
    } catch (err) {
      setError(`Batch analysis failed: ${err.message}`);
      console.error('Batch analysis error:', err);
    } finally {
      setIsAnalyzing(false);
    }
  }, [addresses, options, analysisService]);

  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (isBatchMode) {
      handleBatchAnalysis();
    } else {
      handleSingleAnalysis();
    }
  };

  const handleOptionChange = (key, value) => {
    setOptions(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const clearResults = () => {
    setResults([]);
    setError(null);
  };

  const getApiStatusColor = () => {
    if (!apiHealth) return '#6b7280';
    if (apiHealth.status === 'healthy') return '#10b981';
    if (apiHealth.status === 'degraded') return '#f59e0b';
    return '#ef4444';
  };

  return (
    <div className="enhanced-analysis-form">
      {/* API Status Indicator */}
      <div className="api-status">
        <div 
          className="status-indicator"
          style={{ backgroundColor: getApiStatusColor() }}
        />
        <span className="status-text">
          AI Analysis API: {apiHealth?.status || 'checking...'}
        </span>
        <button 
          className="refresh-status"
          onClick={checkApiHealth}
          title="Refresh API status"
        >
          🔄
        </button>
      </div>

      {/* Main Form */}
      <form onSubmit={handleSubmit} className="analysis-form">
        <div className="form-header">
          <h2>AI-Powered Crypto Analysis</h2>
          <p>Advanced risk assessment using machine learning and multiple intelligence sources</p>
        </div>

        {/* Mode Toggle */}
        <div className="mode-toggle">
          <button
            type="button"
            className={`mode-button ${!isBatchMode ? 'active' : ''}`}
            onClick={() => setIsBatchMode(false)}
          >
            Single Address
          </button>
          <button
            type="button"
            className={`mode-button ${isBatchMode ? 'active' : ''}`}
            onClick={() => setIsBatchMode(true)}
          >
            Batch Analysis
          </button>
        </div>

        {/* Address Input */}
        <div className="input-section">
          {!isBatchMode ? (
            <div className="single-input">
              <label htmlFor="address">
                Cryptocurrency Address or Email
                <span className="required">*</span>
              </label>
              <input
                id="address"
                type="text"
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                placeholder="Enter Bitcoin, Ethereum address, or email..."
                className="address-input"
                disabled={isAnalyzing}
                autoComplete="off"
              />
            </div>
          ) : (
            <div className="batch-input">
              <label htmlFor="addresses">
                Multiple Addresses (up to 50)
                <span className="required">*</span>
              </label>
              <textarea
                id="addresses"
                value={addresses}
                onChange={(e) => setAddresses(e.target.value)}
                placeholder="Enter addresses separated by newlines, commas, or semicolons..."
                className="addresses-textarea"
                rows="6"
                disabled={isAnalyzing}
              />
              <div className="batch-info">
                {addresses ? addresses.split(/[\n,;]/).filter(a => a.trim()).length : 0} addresses entered
              </div>
            </div>
          )}
        </div>

        {/* Analysis Options */}
        <div className="options-section">
          <h3>Analysis Options</h3>
          
          <div className="options-grid">
            <label className="option-item">
              <input
                type="checkbox"
                checked={options.include_recommendations}
                onChange={(e) => handleOptionChange('include_recommendations', e.target.checked)}
                disabled={isAnalyzing}
              />
              <span>Include Recommendations</span>
            </label>

            <label className="option-item">
              <input
                type="checkbox"
                checked={options.check_breach_data}
                onChange={(e) => handleOptionChange('check_breach_data', e.target.checked)}
                disabled={isAnalyzing}
              />
              <span>Check Breach Data</span>
            </label>

            <label className="option-item">
              <input
                type="checkbox"
                checked={options.include_attribution}
                onChange={(e) => handleOptionChange('include_attribution', e.target.checked)}
                disabled={isAnalyzing}
              />
              <span>Include Attribution</span>
            </label>

            <label className="option-item">
              <input
                type="checkbox"
                checked={options.include_crime_history}
                onChange={(e) => handleOptionChange('include_crime_history', e.target.checked)}
                disabled={isAnalyzing}
              />
              <span>Include Crime History</span>
            </label>

            <label className="option-item">
              <input
                type="checkbox"
                checked={options.deep_analysis}
                onChange={(e) => handleOptionChange('deep_analysis', e.target.checked)}
                disabled={isAnalyzing}
              />
              <span>Deep Analysis (slower)</span>
            </label>
          </div>

          <div className="explanation-level">
            <label htmlFor="explanation-level">Explanation Detail Level:</label>
            <select
              id="explanation-level"
              value={options.explanation_level}
              onChange={(e) => handleOptionChange('explanation_level', e.target.value)}
              disabled={isAnalyzing}
            >
              <option value="minimal">Minimal</option>
              <option value="standard">Standard</option>
              <option value="detailed">Detailed</option>
            </select>
          </div>
        </div>

        {/* Error Display */}
        {error && (
          <div className="error-message">
            <span className="error-icon">⚠️</span>
            {error}
          </div>
        )}

        {/* Submit Button */}
        <div className="submit-section">
          <button
            type="submit"
            className="analyze-button"
            disabled={isAnalyzing || (!address && !isBatchMode) || (!addresses && isBatchMode)}
          >
            {isAnalyzing ? (
              <>
                <span className="loading-spinner" />
                {isBatchMode ? 'Analyzing Batch...' : 'Analyzing...'}
              </>
            ) : (
              <>
                🔍 {isBatchMode ? 'Analyze Batch' : 'Analyze Address'}
              </>
            )}
          </button>

          {results.length > 0 && (
            <button
              type="button"
              className="clear-button"
              onClick={clearResults}
            >
              Clear Results
            </button>
          )}
        </div>
      </form>

      {/* Results Section */}
      {results.length > 0 && (
        <div className="results-section">
          <div className="results-header">
            <h3>Analysis Results ({results.length})</h3>
            {results.length > 1 && (
              <div className="batch-summary">
                <span>Risk Distribution:</span>
                {['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map(level => {
                  const count = results.filter(r => r.risk.level === level).length;
                  return count > 0 ? (
                    <span key={level} className={`risk-count risk-${level.toLowerCase()}`}>
                      {level}: {count}
                    </span>
                  ) : null;
                })}
              </div>
            )}
          </div>

          <div className="results-list">
            {results.map((result, index) => (
              <AnalysisResultCard
                key={result.requestId || index}
                analysisResult={result}
                onReanalyze={handleSingleAnalysis}
              />
            ))}
          </div>
        </div>
      )}

      {/* Loading State */}
      {isAnalyzing && (
        <div className="loading-overlay">
          <div className="loading-content">
            <div className="loading-spinner large" />
            <h3>AI Analysis in Progress</h3>
            <p>
              {isBatchMode 
                ? 'Processing multiple addresses using machine learning models...'
                : 'Analyzing address using multiple intelligence sources...'
              }
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default EnhancedAnalysisForm;