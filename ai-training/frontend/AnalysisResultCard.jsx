/**
 * AnalysisResultCard - React component for displaying AI analysis results
 * Integrates with the Have I Been Rekt AI analysis API
 */

import React, { useState } from 'react';
import './AnalysisResultCard.css';

const AnalysisResultCard = ({ analysisResult, onReanalyze }) => {
  const [showDetails, setShowDetails] = useState(false);
  const [showRawData, setShowRawData] = useState(false);

  if (!analysisResult) {
    return null;
  }

  const { risk, meta, recommendations, explanation, attribution, crimeHistory } = analysisResult;

  const formatProcessingTime = (ms) => {
    if (ms < 1000) return `${ms}ms`;
    return `${(ms / 1000).toFixed(1)}s`;
  };

  const getPriorityClass = (priority) => {
    const classes = {
      'low': 'priority-low',
      'medium': 'priority-medium', 
      'high': 'priority-high',
      'critical': 'priority-critical'
    };
    return classes[priority?.toLowerCase()] || 'priority-medium';
  };

  return (
    <div className="analysis-result-card">
      {/* Header */}
      <div className="result-header">
        <div className="address-info">
          <h3 className="address">{analysisResult.address}</h3>
          <div className="analysis-meta">
            <span className="timestamp">
              Analyzed {meta.timestamp.toLocaleString()}
            </span>
            {meta.cached && <span className="cached-badge">Cached</span>}
            <span className="processing-time">
              {formatProcessingTime(meta.processingTime)}
            </span>
          </div>
        </div>
        
        <div className="risk-summary">
          <div 
            className="risk-score"
            style={{ color: analysisResult.getRiskColor() }}
          >
            <span className="risk-icon">{analysisResult.getRiskIcon()}</span>
            <span className="score-value">{analysisResult.getFormattedScore()}</span>
          </div>
          <div className="risk-level">{risk.level}</div>
        </div>
      </div>

      {/* Risk Assessment */}
      <div className="risk-assessment">
        <div className="risk-bar">
          <div 
            className="risk-fill"
            style={{ 
              width: `${risk.score * 100}%`,
              backgroundColor: analysisResult.getRiskColor()
            }}
          />
        </div>
        
        <div className="risk-details">
          <div className="confidence">
            Confidence: {Math.round(risk.confidence * 100)}%
          </div>
          <div className="category">
            Category: {risk.category}
          </div>
        </div>
      </div>

      {/* Primary Concerns */}
      {risk.concerns && risk.concerns.length > 0 && (
        <div className="primary-concerns">
          <h4>Primary Concerns:</h4>
          <div className="concerns-list">
            {risk.concerns.map((concern, index) => (
              <span key={index} className="concern-tag">
                {concern.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      {recommendations && recommendations.length > 0 && (
        <div className="recommendations">
          <h4>Recommended Actions:</h4>
          {recommendations.slice(0, 3).map((rec, index) => (
            <div key={index} className={`recommendation ${getPriorityClass(rec.priority)}`}>
              <div className="rec-header">
                <span className="rec-action">{rec.action.replace(/_/g, ' ')}</span>
                <span className="rec-priority">{rec.priority}</span>
              </div>
              <div className="rec-description">{rec.description}</div>
              {rec.reason && (
                <div className="rec-reason">Reason: {rec.reason}</div>
              )}
            </div>
          ))}
          
          {recommendations.length > 3 && (
            <button 
              className="show-all-recommendations"
              onClick={() => setShowDetails(!showDetails)}
            >
              {showDetails ? 'Show Less' : `Show ${recommendations.length - 3} More`}
            </button>
          )}
        </div>
      )}

      {/* Explanation */}
      {explanation && (
        <div className="explanation">
          <h4>Analysis Explanation:</h4>
          <p>{explanation}</p>
        </div>
      )}

      {/* Data Sources */}
      <div className="data-sources">
        <h4>Data Sources Checked:</h4>
        <div className="sources-grid">
          {meta.dataSources.map((source, index) => (
            <div key={index} className={`source-item ${source.found ? 'found' : 'not-found'}`}>
              <span className="source-name">{source.name.replace(/_/g, ' ')}</span>
              <span className="source-status">
                {source.found ? '✓' : '✗'}
              </span>
              {source.confidence && (
                <span className="source-confidence">
                  {Math.round(source.confidence * 100)}%
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Expandable Details */}
      {showDetails && (
        <div className="detailed-results">
          {/* All Recommendations */}
          {recommendations && recommendations.length > 3 && (
            <div className="all-recommendations">
              <h4>All Recommendations:</h4>
              {recommendations.slice(3).map((rec, index) => (
                <div key={index + 3} className={`recommendation ${getPriorityClass(rec.priority)}`}>
                  <div className="rec-header">
                    <span className="rec-action">{rec.action.replace(/_/g, ' ')}</span>
                    <span className="rec-priority">{rec.priority}</span>
                  </div>
                  <div className="rec-description">{rec.description}</div>
                  {rec.reason && (
                    <div className="rec-reason">Reason: {rec.reason}</div>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Attribution Details */}
          {attribution && (
            <div className="attribution-details">
              <h4>Address Attribution:</h4>
              <div className="attribution-content">
                {attribution.primary_attribution && (
                  <div className="primary-attribution">
                    <strong>Primary Attribution:</strong> {attribution.primary_attribution}
                  </div>
                )}
                {attribution.entity_type && (
                  <div className="entity-type">
                    <strong>Entity Type:</strong> {attribution.entity_type}
                  </div>
                )}
                {attribution.attribution_confidence && (
                  <div className="attribution-confidence">
                    <strong>Attribution Confidence:</strong> {attribution.attribution_confidence}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Crime History */}
          {crimeHistory && (
            <div className="crime-history">
              <h4>Criminal History:</h4>
              <div className="crime-content">
                {crimeHistory.criminal_activity_found && (
                  <div className="criminal-activity">
                    <strong>Criminal Activity:</strong> Yes
                  </div>
                )}
                {crimeHistory.breach_exposure_found && (
                  <div className="breach-exposure">
                    <strong>Data Breach Exposure:</strong> Yes
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Actions */}
      <div className="result-actions">
        <button 
          className="toggle-details"
          onClick={() => setShowDetails(!showDetails)}
        >
          {showDetails ? 'Hide Details' : 'Show Details'}
        </button>
        
        <button 
          className="toggle-raw-data"
          onClick={() => setShowRawData(!showRawData)}
        >
          {showRawData ? 'Hide Raw Data' : 'Show Raw Data'}
        </button>
        
        {onReanalyze && (
          <button 
            className="reanalyze-button"
            onClick={() => onReanalyze(analysisResult.address)}
          >
            Re-analyze
          </button>
        )}
      </div>

      {/* Raw Data (for debugging/transparency) */}
      {showRawData && (
        <div className="raw-data">
          <h4>Raw Analysis Data:</h4>
          <pre>{JSON.stringify(analysisResult, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};

export default AnalysisResultCard;