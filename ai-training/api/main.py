"""
Have I Been Rekt AI Analysis API Server

FastAPI server providing real-time cryptocurrency risk assessment using trained ML models.
Integrates all data collectors and provides standardized API endpoints for frontend integration.
"""

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timezone
import asyncio
import logging
import os
import sys
import time
import uuid
from contextlib import asynccontextmanager

# Rate limiting
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# Caching
import redis
import json
import hashlib

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# Import our AI components
from ml.risk_scoring_engine import RiskScoringEngine, RiskScoreResult, RiskCategory
from collectors.address_attribution_aggregator import AddressAttributionAggregator
from collectors.historical_crime_aggregator import HistoricalCrimeAggregator
from data_collector import WalletAnalysis, RiskFactor, RiskLevel


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

# Global state for ML models and collectors
ml_components = {}
redis_client = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize and cleanup ML components"""
    global ml_components, redis_client
    
    logger.info("Initializing AI analysis components...")
    
    try:
        # Load configuration
        config = {
            'hibp_api_key': os.getenv('HIBP_API_KEY'),
            'virustotal_api_key': os.getenv('VIRUSTOTAL_API_KEY'),
            'chainalysis_api_key': os.getenv('CHAINALYSIS_API_KEY'),
            'cache_dir': './cache',
            'redis_url': os.getenv('REDIS_URL', 'redis://localhost:6379')
        }
        
        # Initialize Redis cache
        if config['redis_url']:
            try:
                redis_client = redis.from_url(config['redis_url'], decode_responses=True)
                redis_client.ping()  # Test connection
                logger.info("Redis cache initialized")
            except Exception as e:
                logger.warning(f"Redis connection failed, using in-memory cache: {e}")
                redis_client = None
        
        # Initialize ML components
        ml_components['risk_scoring_engine'] = RiskScoringEngine(config)
        ml_components['attribution_aggregator'] = AddressAttributionAggregator(config)
        ml_components['crime_aggregator'] = HistoricalCrimeAggregator(config)
        
        logger.info("AI components initialized successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to initialize AI components: {e}")
        raise
    finally:
        # Cleanup
        if redis_client:
            redis_client.close()
        logger.info("AI components cleaned up")


# Initialize FastAPI app
app = FastAPI(
    title="Have I Been Rekt AI Analysis API",
    description="Real-time cryptocurrency risk assessment using trained ML models",
    version="1.0.0",
    lifespan=lifespan
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001", "*"],  # Update for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Pydantic models for API
class AnalysisOptions(BaseModel):
    """Options for address analysis"""
    include_recommendations: bool = True
    check_breach_data: bool = True
    deep_analysis: bool = False
    include_attribution: bool = True
    include_crime_history: bool = True
    explanation_level: str = Field(default="standard", regex="^(minimal|standard|detailed)$")


class AddressAnalysisRequest(BaseModel):
    """Request model for single address analysis"""
    address: str = Field(..., min_length=1, max_length=200, description="Cryptocurrency address or email to analyze")
    options: Optional[AnalysisOptions] = AnalysisOptions()
    
    @validator('address')
    def validate_address(cls, v):
        v = v.strip()
        if not v:
            raise ValueError("Address cannot be empty")
        # Basic validation - could be expanded for specific address formats
        if len(v) < 10:
            raise ValueError("Address appears too short")
        return v


class BatchAnalysisRequest(BaseModel):
    """Request model for batch address analysis"""
    addresses: List[str] = Field(..., min_items=1, max_items=50, description="List of addresses to analyze")
    options: Optional[AnalysisOptions] = AnalysisOptions()
    
    @validator('addresses')
    def validate_addresses(cls, v):
        cleaned_addresses = []
        for addr in v:
            addr = addr.strip()
            if not addr:
                continue
            if len(addr) < 10:
                raise ValueError(f"Address '{addr}' appears too short")
            cleaned_addresses.append(addr)
        
        if not cleaned_addresses:
            raise ValueError("No valid addresses provided")
        
        return cleaned_addresses


class RiskAssessment(BaseModel):
    """Risk assessment result"""
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Risk score from 0.0 (clean) to 1.0 (critical)")
    risk_level: str = Field(..., description="Risk level: LOW, MEDIUM, HIGH, CRITICAL")
    risk_category: str = Field(..., description="Risk category: CLEAN, SUSPICIOUS, HIGH_RISK, CRIMINAL, SANCTIONED")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in assessment")
    primary_concerns: List[str] = Field(default=[], description="Primary risk concerns identified")


class DataSourceInfo(BaseModel):
    """Information about data sources used"""
    source_name: str
    data_found: bool
    confidence: Optional[float] = None
    last_updated: Optional[str] = None


class Recommendation(BaseModel):
    """Actionable recommendation"""
    priority: str = Field(..., regex="^(low|medium|high|critical)$")
    action: str
    description: str
    reason: str


class AnalysisResponse(BaseModel):
    """Response model for address analysis"""
    request_id: str = Field(..., description="Unique request identifier")
    address: str
    risk_assessment: RiskAssessment
    data_sources: List[DataSourceInfo]
    recommendations: List[Recommendation]
    explanation: Optional[str] = None
    attribution: Optional[Dict[str, Any]] = None
    crime_history: Optional[Dict[str, Any]] = None
    processing_time_ms: int
    analysis_timestamp: str
    cached: bool = False


class BatchAnalysisResponse(BaseModel):
    """Response model for batch analysis"""
    request_id: str
    total_addresses: int
    successful_analyses: int
    failed_analyses: int
    results: List[AnalysisResponse]
    processing_time_ms: int
    analysis_timestamp: str


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    timestamp: str
    version: str
    components: Dict[str, str]
    uptime_seconds: int


# Cache utilities
def get_cache_key(address: str, options: AnalysisOptions) -> str:
    """Generate cache key for analysis request"""
    options_str = json.dumps(options.dict(), sort_keys=True)
    cache_input = f"{address}:{options_str}"
    return f"analysis:{hashlib.md5(cache_input.encode()).hexdigest()}"


async def get_cached_result(cache_key: str) -> Optional[Dict[str, Any]]:
    """Get cached analysis result"""
    if not redis_client:
        return None
    
    try:
        cached_data = redis_client.get(cache_key)
        if cached_data:
            return json.loads(cached_data)
    except Exception as e:
        logger.warning(f"Cache retrieval failed: {e}")
    
    return None


async def cache_result(cache_key: str, result: Dict[str, Any], ttl_seconds: int = 3600):
    """Cache analysis result"""
    if not redis_client:
        return
    
    try:
        redis_client.setex(cache_key, ttl_seconds, json.dumps(result, default=str))
    except Exception as e:
        logger.warning(f"Cache storage failed: {e}")


# API Endpoints
@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Have I Been Rekt AI Analysis API",
        "version": "1.0.0",
        "status": "operational",
        "docs": "/docs"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    start_time = getattr(app.state, 'start_time', time.time())
    uptime = int(time.time() - start_time)
    
    # Check component status
    components = {}
    
    try:
        # Check risk scoring engine
        if 'risk_scoring_engine' in ml_components:
            components['risk_scoring_engine'] = "healthy"
        else:
            components['risk_scoring_engine'] = "unavailable"
        
        # Check data collectors
        for component in ['attribution_aggregator', 'crime_aggregator']:
            if component in ml_components:
                components[component] = "healthy"
            else:
                components[component] = "unavailable"
        
        # Check Redis cache
        if redis_client:
            redis_client.ping()
            components['redis_cache'] = "healthy"
        else:
            components['redis_cache'] = "disabled"
            
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        components['error'] = str(e)
    
    return HealthResponse(
        status="healthy" if all(status != "unavailable" for status in components.values()) else "degraded",
        timestamp=datetime.now(timezone.utc).isoformat(),
        version="1.0.0",
        components=components,
        uptime_seconds=uptime
    )


@app.post("/api/v1/analyze", response_model=AnalysisResponse)
@limiter.limit("10/minute")
async def analyze_address(
    request: AddressAnalysisRequest,
    background_tasks: BackgroundTasks,
    http_request: Request
):
    """Analyze a single cryptocurrency address or email"""
    
    request_id = str(uuid.uuid4())
    start_time = time.time()
    
    logger.info(f"Analysis request {request_id}: {request.address}")
    
    try:
        # Check cache first
        cache_key = get_cache_key(request.address, request.options)
        cached_result = await get_cached_result(cache_key)
        
        if cached_result:
            cached_result['request_id'] = request_id
            cached_result['cached'] = True
            cached_result['processing_time_ms'] = int((time.time() - start_time) * 1000)
            logger.info(f"Returning cached result for {request_id}")
            return AnalysisResponse(**cached_result)
        
        # Perform analysis
        analysis_result = await perform_address_analysis(request.address, request.options)
        
        if not analysis_result:
            raise HTTPException(status_code=422, detail="Analysis could not be completed")
        
        # Build response
        processing_time = int((time.time() - start_time) * 1000)
        
        response_data = {
            'request_id': request_id,
            'address': request.address,
            'risk_assessment': analysis_result['risk_assessment'],
            'data_sources': analysis_result['data_sources'],
            'recommendations': analysis_result['recommendations'],
            'explanation': analysis_result.get('explanation'),
            'attribution': analysis_result.get('attribution') if request.options.include_attribution else None,
            'crime_history': analysis_result.get('crime_history') if request.options.include_crime_history else None,
            'processing_time_ms': processing_time,
            'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
            'cached': False
        }
        
        # Cache result in background
        background_tasks.add_task(cache_result, cache_key, response_data)
        
        logger.info(f"Analysis completed for {request_id} in {processing_time}ms")
        
        return AnalysisResponse(**response_data)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Analysis failed for {request_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal analysis error")


@app.post("/api/v1/analyze/batch", response_model=BatchAnalysisResponse)
@limiter.limit("3/minute")
async def analyze_batch(
    request: BatchAnalysisRequest,
    background_tasks: BackgroundTasks,
    http_request: Request
):
    """Analyze multiple addresses in batch"""
    
    request_id = str(uuid.uuid4())
    start_time = time.time()
    
    logger.info(f"Batch analysis request {request_id}: {len(request.addresses)} addresses")
    
    try:
        results = []
        successful = 0
        failed = 0
        
        # Process addresses concurrently (with limit)
        semaphore = asyncio.Semaphore(5)  # Limit concurrent analyses
        
        async def analyze_single_address(address: str):
            async with semaphore:
                try:
                    single_request = AddressAnalysisRequest(address=address, options=request.options)
                    
                    # Use cache key for individual address
                    cache_key = get_cache_key(address, request.options)
                    cached_result = await get_cached_result(cache_key)
                    
                    if cached_result:
                        cached_result['request_id'] = f"{request_id}_{address[:8]}"
                        cached_result['cached'] = True
                        return AnalysisResponse(**cached_result)
                    
                    # Perform analysis
                    analysis_result = await perform_address_analysis(address, request.options)
                    
                    if analysis_result:
                        response_data = {
                            'request_id': f"{request_id}_{address[:8]}",
                            'address': address,
                            'risk_assessment': analysis_result['risk_assessment'],
                            'data_sources': analysis_result['data_sources'],
                            'recommendations': analysis_result['recommendations'],
                            'explanation': analysis_result.get('explanation'),
                            'attribution': analysis_result.get('attribution') if request.options.include_attribution else None,
                            'crime_history': analysis_result.get('crime_history') if request.options.include_crime_history else None,
                            'processing_time_ms': 0,  # Will be set by batch processing
                            'analysis_timestamp': datetime.now(timezone.utc).isoformat(),
                            'cached': False
                        }
                        
                        # Cache result
                        background_tasks.add_task(cache_result, cache_key, response_data)
                        
                        return AnalysisResponse(**response_data)
                    else:
                        return None
                        
                except Exception as e:
                    logger.error(f"Batch analysis failed for {address}: {e}")
                    return None
        
        # Execute batch analysis
        tasks = [analyze_single_address(addr) for addr in request.addresses]
        completed_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for result in completed_results:
            if isinstance(result, AnalysisResponse):
                results.append(result)
                successful += 1
            else:
                failed += 1
        
        processing_time = int((time.time() - start_time) * 1000)
        
        # Update processing times
        for result in results:
            result.processing_time_ms = processing_time // len(results) if results else processing_time
        
        logger.info(f"Batch analysis completed for {request_id}: {successful} successful, {failed} failed")
        
        return BatchAnalysisResponse(
            request_id=request_id,
            total_addresses=len(request.addresses),
            successful_analyses=successful,
            failed_analyses=failed,
            results=results,
            processing_time_ms=processing_time,
            analysis_timestamp=datetime.now(timezone.utc).isoformat()
        )
        
    except Exception as e:
        logger.error(f"Batch analysis failed for {request_id}: {e}")
        raise HTTPException(status_code=500, detail="Batch analysis error")


async def perform_address_analysis(address: str, options: AnalysisOptions) -> Optional[Dict[str, Any]]:
    """Perform comprehensive address analysis using ML components"""
    
    try:
        # Initialize results
        data_sources = []
        all_risk_factors = []
        
        # 1. Attribution Analysis
        attribution_result = None
        if options.include_attribution and 'attribution_aggregator' in ml_components:
            try:
                attribution_analysis = ml_components['attribution_aggregator'].analyze_address(address)
                if attribution_analysis:
                    attribution_result = attribution_analysis.raw_data
                    all_risk_factors.extend(attribution_analysis.risk_factors)
                    data_sources.append(DataSourceInfo(
                        source_name="address_attribution",
                        data_found=True,
                        confidence=attribution_analysis.confidence_score,
                        last_updated=datetime.now(timezone.utc).isoformat()
                    ))
            except Exception as e:
                logger.warning(f"Attribution analysis failed: {e}")
                data_sources.append(DataSourceInfo(
                    source_name="address_attribution",
                    data_found=False
                ))
        
        # 2. Crime History Analysis
        crime_result = None
        if options.include_crime_history and 'crime_aggregator' in ml_components:
            try:
                crime_analysis = ml_components['crime_aggregator'].analyze_address(address)
                if crime_analysis:
                    crime_result = crime_analysis.raw_data
                    all_risk_factors.extend(crime_analysis.risk_factors)
                    data_sources.append(DataSourceInfo(
                        source_name="historical_crime",
                        data_found=True,
                        confidence=crime_analysis.confidence_score,
                        last_updated=datetime.now(timezone.utc).isoformat()
                    ))
            except Exception as e:
                logger.warning(f"Crime analysis failed: {e}")
                data_sources.append(DataSourceInfo(
                    source_name="historical_crime",
                    data_found=False
                ))
        
        # 3. Create comprehensive wallet analysis
        overall_risk_score = 0.0
        confidence_score = 0.5
        risk_level = RiskLevel.LOW
        is_flagged = False
        
        if all_risk_factors:
            # Calculate risk metrics from factors
            risk_scores = [0.25 if rf.risk_level == RiskLevel.LOW else
                          0.5 if rf.risk_level == RiskLevel.MEDIUM else
                          0.75 if rf.risk_level == RiskLevel.HIGH else 1.0
                          for rf in all_risk_factors]
            
            confidences = [rf.confidence for rf in all_risk_factors]
            
            overall_risk_score = sum(r * c for r, c in zip(risk_scores, confidences)) / sum(confidences) if confidences else 0
            confidence_score = sum(confidences) / len(confidences) if confidences else 0.5
            
            # Determine risk level
            if overall_risk_score >= 0.8:
                risk_level = RiskLevel.CRITICAL
                is_flagged = True
            elif overall_risk_score >= 0.6:
                risk_level = RiskLevel.HIGH
                is_flagged = True
            elif overall_risk_score >= 0.3:
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.LOW
        
        # Create wallet analysis for risk scoring
        wallet_analysis = WalletAnalysis(
            address=address,
            analysis_timestamp=datetime.now(timezone.utc),
            data_sources=[ds.source_name for ds in data_sources],
            risk_factors=all_risk_factors,
            overall_risk_score=overall_risk_score,
            risk_level=risk_level,
            confidence_score=confidence_score,
            is_flagged=is_flagged,
            summary=f"Comprehensive analysis of {address}",
            raw_data={
                'attribution': attribution_result,
                'crime_history': crime_result
            }
        )
        
        # 4. Risk Scoring Engine
        risk_score_result = None
        if 'risk_scoring_engine' in ml_components:
            try:
                risk_score_result = ml_components['risk_scoring_engine'].calculate_risk_score(wallet_analysis)
            except Exception as e:
                logger.warning(f"Risk scoring failed: {e}")
        
        # 5. Build final result
        if risk_score_result:
            risk_assessment = RiskAssessment(
                risk_score=risk_score_result.overall_risk_score,
                risk_level=risk_score_result.risk_category.value.upper(),
                risk_category=risk_score_result.risk_category.value.upper(),
                confidence=risk_score_result.confidence_score,
                primary_concerns=[rf.type for rf in risk_score_result.primary_risk_factors[:3]]
            )
        else:
            risk_assessment = RiskAssessment(
                risk_score=overall_risk_score,
                risk_level=risk_level.name,
                risk_category="UNKNOWN",
                confidence=confidence_score,
                primary_concerns=[rf.type for rf in all_risk_factors[:3]]
            )
        
        # 6. Generate recommendations
        recommendations = generate_recommendations(risk_assessment, all_risk_factors)
        
        # 7. Generate explanation
        explanation = None
        if options.explanation_level != "minimal":
            explanation = generate_explanation(risk_assessment, all_risk_factors, options.explanation_level)
        
        return {
            'risk_assessment': risk_assessment.dict(),
            'data_sources': [ds.dict() for ds in data_sources],
            'recommendations': [rec.dict() for rec in recommendations],
            'explanation': explanation,
            'attribution': attribution_result,
            'crime_history': crime_result
        }
        
    except Exception as e:
        logger.error(f"Address analysis failed for {address}: {e}")
        return None


def generate_recommendations(risk_assessment: RiskAssessment, risk_factors: List[RiskFactor]) -> List[Recommendation]:
    """Generate actionable recommendations based on analysis"""
    
    recommendations = []
    
    # High-level recommendations based on risk score
    if risk_assessment.risk_score >= 0.8:
        recommendations.append(Recommendation(
            priority="critical",
            action="block_transaction",
            description="Block all transactions with this address immediately",
            reason=f"Critical risk score ({risk_assessment.risk_score:.2f}) indicates high probability of criminal activity"
        ))
        
        recommendations.append(Recommendation(
            priority="high",
            action="report_to_authorities",
            description="Report this address to relevant law enforcement authorities",
            reason="Address shows strong indicators of criminal activity"
        ))
        
    elif risk_assessment.risk_score >= 0.6:
        recommendations.append(Recommendation(
            priority="high",
            action="enhanced_monitoring",
            description="Implement enhanced monitoring and additional verification",
            reason=f"High risk score ({risk_assessment.risk_score:.2f}) requires careful oversight"
        ))
        
        recommendations.append(Recommendation(
            priority="medium",
            action="kyc_verification",
            description="Require additional KYC/AML verification before processing",
            reason="High-risk addresses require enhanced due diligence"
        ))
        
    elif risk_assessment.risk_score >= 0.3:
        recommendations.append(Recommendation(
            priority="medium",
            action="additional_verification",
            description="Perform additional verification checks before proceeding",
            reason=f"Moderate risk score ({risk_assessment.risk_score:.2f}) warrants caution"
        ))
        
    else:
        recommendations.append(Recommendation(
            priority="low",
            action="standard_processing",
            description="Address appears safe for standard processing",
            reason=f"Low risk score ({risk_assessment.risk_score:.2f}) indicates minimal threat"
        ))
    
    # Specific recommendations based on risk factors
    for risk_factor in risk_factors[:3]:  # Top 3 risk factors
        if 'sanction' in risk_factor.type.lower():
            recommendations.insert(0, Recommendation(
                priority="critical",
                action="compliance_review",
                description="Immediate compliance review required - potential sanctions violation",
                reason="Address may be subject to government sanctions"
            ))
        
        elif 'ransomware' in risk_factor.type.lower():
            recommendations.append(Recommendation(
                priority="high",
                action="ransomware_protocol",
                description="Follow ransomware incident response protocol",
                reason="Address linked to ransomware activity"
            ))
        
        elif 'mixer' in risk_factor.type.lower():
            recommendations.append(Recommendation(
                priority="medium",
                action="mixing_service_review",
                description="Review transaction for privacy service usage",
                reason="Address associated with cryptocurrency mixing services"
            ))
    
    return recommendations


def generate_explanation(risk_assessment: RiskAssessment, risk_factors: List[RiskFactor], level: str) -> str:
    """Generate human-readable explanation of analysis"""
    
    if level == "minimal":
        return f"Risk score: {risk_assessment.risk_score:.2f} ({risk_assessment.risk_level})"
    
    explanation_parts = []
    
    # Overall assessment
    explanation_parts.append(f"This address received a risk score of {risk_assessment.risk_score:.2f} "
                           f"({risk_assessment.risk_level} risk level) with {risk_assessment.confidence:.1%} confidence.")
    
    # Primary concerns
    if risk_assessment.primary_concerns:
        concerns_text = ', '.join(risk_assessment.primary_concerns[:3])
        explanation_parts.append(f"Primary concerns include: {concerns_text}.")
    
    if level == "detailed":
        # Detailed analysis
        if risk_factors:
            explanation_parts.append(f"Analysis identified {len(risk_factors)} risk factors:")
            
            for i, factor in enumerate(risk_factors[:5], 1):
                explanation_parts.append(f"{i}. {factor.description} "
                                       f"({factor.risk_level.name} risk, {factor.confidence:.1%} confidence)")
        
        # Data source information
        unique_sources = set(rf.source.name for rf in risk_factors)
        if unique_sources:
            sources_text = ', '.join(unique_sources)
            explanation_parts.append(f"Analysis based on data from: {sources_text}.")
    
    return ' '.join(explanation_parts)


# Store start time for uptime calculation
app.state.start_time = time.time()

if __name__ == "__main__":
    import uvicorn
    
    # Configuration from environment
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8000"))
    reload = os.getenv("RELOAD", "false").lower() == "true"
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )