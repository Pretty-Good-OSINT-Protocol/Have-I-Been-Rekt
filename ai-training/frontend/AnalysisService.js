/**
 * Analysis Service - Frontend integration for Have I Been Rekt AI API
 * Provides methods to call the AI analysis API and handle responses
 */

class AnalysisService {
  constructor(apiBaseUrl = 'http://localhost:8000/api/v1') {
    this.apiBaseUrl = apiBaseUrl;
    this.defaultOptions = {
      include_recommendations: true,
      check_breach_data: true,
      deep_analysis: false,
      include_attribution: true,
      include_crime_history: true,
      explanation_level: 'standard'
    };
  }

  /**
   * Analyze a single cryptocurrency address or email
   * @param {string} address - Address to analyze
   * @param {Object} options - Analysis options
   * @returns {Promise<Object>} Analysis result
   */
  async analyzeAddress(address, options = {}) {
    const analysisOptions = { ...this.defaultOptions, ...options };
    
    try {
      const response = await fetch(`${this.apiBaseUrl}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          address: address.trim(),
          options: analysisOptions
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      return this.transformAnalysisResult(result);
      
    } catch (error) {
      console.error('Address analysis failed:', error);
      throw new AnalysisError(error.message, error.status);
    }
  }

  /**
   * Analyze multiple addresses in batch
   * @param {string[]} addresses - Addresses to analyze
   * @param {Object} options - Analysis options
   * @returns {Promise<Object>} Batch analysis result
   */
  async analyzeBatch(addresses, options = {}) {
    const analysisOptions = { ...this.defaultOptions, ...options };
    
    try {
      const response = await fetch(`${this.apiBaseUrl}/analyze/batch`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          addresses: addresses.map(addr => addr.trim()),
          options: analysisOptions
        })
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.detail || `HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      return this.transformBatchResult(result);
      
    } catch (error) {
      console.error('Batch analysis failed:', error);
      throw new AnalysisError(error.message, error.status);
    }
  }

  /**
   * Check API health status
   * @returns {Promise<Object>} Health status
   */
  async checkHealth() {
    try {
      const response = await fetch(`${this.apiBaseUrl.replace('/api/v1', '')}/health`);
      
      if (!response.ok) {
        throw new Error(`Health check failed: ${response.status}`);
      }

      return await response.json();
      
    } catch (error) {
      console.error('Health check failed:', error);
      throw error;
    }
  }

  /**
   * Transform API analysis result for frontend use
   * @private
   */
  transformAnalysisResult(apiResult) {
    return {
      requestId: apiResult.request_id,
      address: apiResult.address,
      
      // Risk Assessment
      risk: {
        score: apiResult.risk_assessment.risk_score,
        level: apiResult.risk_assessment.risk_level,
        category: apiResult.risk_assessment.risk_category,
        confidence: apiResult.risk_assessment.confidence,
        concerns: apiResult.risk_assessment.primary_concerns
      },

      // Analysis Metadata
      meta: {
        processingTime: apiResult.processing_time_ms,
        timestamp: new Date(apiResult.analysis_timestamp),
        cached: apiResult.cached,
        dataSources: apiResult.data_sources.map(ds => ({
          name: ds.source_name,
          found: ds.data_found,
          confidence: ds.confidence,
          lastUpdated: ds.last_updated ? new Date(ds.last_updated) : null
        }))
      },

      // Recommendations
      recommendations: apiResult.recommendations.map(rec => ({
        priority: rec.priority,
        action: rec.action,
        description: rec.description,
        reason: rec.reason
      })),

      // Additional Data
      explanation: apiResult.explanation,
      attribution: apiResult.attribution,
      crimeHistory: apiResult.crime_history,

      // UI Helper Methods
      getRiskColor: () => this.getRiskColor(apiResult.risk_assessment.risk_level),
      getRiskIcon: () => this.getRiskIcon(apiResult.risk_assessment.risk_level),
      getFormattedScore: () => `${Math.round(apiResult.risk_assessment.risk_score * 100)}%`
    };
  }

  /**
   * Transform batch analysis result
   * @private
   */
  transformBatchResult(apiResult) {
    return {
      requestId: apiResult.request_id,
      summary: {
        total: apiResult.total_addresses,
        successful: apiResult.successful_analyses,
        failed: apiResult.failed_analyses,
        processingTime: apiResult.processing_time_ms,
        timestamp: new Date(apiResult.analysis_timestamp)
      },
      results: apiResult.results.map(result => this.transformAnalysisResult(result))
    };
  }

  /**
   * Get color for risk level
   * @private
   */
  getRiskColor(riskLevel) {
    const colors = {
      'LOW': '#10B981',      // Green
      'MEDIUM': '#F59E0B',   // Yellow/Orange  
      'HIGH': '#EF4444',     // Red
      'CRITICAL': '#7C2D12', // Dark Red
      'CLEAN': '#10B981',    // Green
      'SUSPICIOUS': '#F59E0B', // Yellow
      'HIGH_RISK': '#EF4444',  // Red
      'CRIMINAL': '#7C2D12',   // Dark Red
      'SANCTIONED': '#1F2937' // Black
    };
    
    return colors[riskLevel?.toUpperCase()] || '#6B7280'; // Gray default
  }

  /**
   * Get icon for risk level
   * @private
   */
  getRiskIcon(riskLevel) {
    const icons = {
      'LOW': '✅',
      'MEDIUM': '⚠️', 
      'HIGH': '🚨',
      'CRITICAL': '🔴',
      'CLEAN': '✅',
      'SUSPICIOUS': '⚠️',
      'HIGH_RISK': '🚨', 
      'CRIMINAL': '🔴',
      'SANCTIONED': '⛔'
    };
    
    return icons[riskLevel?.toUpperCase()] || '❓';
  }
}

/**
 * Custom error class for analysis errors
 */
class AnalysisError extends Error {
  constructor(message, status = null) {
    super(message);
    this.name = 'AnalysisError';
    this.status = status;
  }
}

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { AnalysisService, AnalysisError };
}

// Export for ES6 modules
if (typeof window !== 'undefined') {
  window.AnalysisService = AnalysisService;
  window.AnalysisError = AnalysisError;
}

export { AnalysisService, AnalysisError };