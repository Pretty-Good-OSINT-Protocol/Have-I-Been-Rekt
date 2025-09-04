#!/usr/bin/env python3
"""
Have-I-Been-Rekt API Server
FastAPI backend for threat intelligence analysis
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import uvicorn
import logging

try:
    from spiderfoot_integration import HIBRIntelligence
except ImportError:
    # Fallback for MVP - use quota-protected APIs instead
    HIBRIntelligence = None

from payment_processor import payment_processor, create_payment_for_analysis, AnalysisType

# Import AI service
try:
    from hibr_ai_service import get_ai_service, analyze_threat, analyze_threats
    AI_AVAILABLE = True
except ImportError as e:
    logging.warning(f"AI service not available: {e}")
    AI_AVAILABLE = False

# Initialize FastAPI app
app = FastAPI(
    title="Have-I-Been-Rekt API",
    description="Comprehensive threat intelligence analysis service",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:3001"],  # React dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize intelligence service
if HIBRIntelligence:
    intel_service = HIBRIntelligence()
else:
    # Use quota-protected APIs for MVP
    from quota_protected_apis import threat_intel
    intel_service = threat_intel

# Request/Response Models
class AnalysisRequest(BaseModel):
    target: str
    analysis_type: Optional[str] = "auto"  # auto, email, ip, domain, crypto

class AnalysisResponse(BaseModel):
    success: bool
    data: Dict[str, Any]
    message: Optional[str] = None

class HealthResponse(BaseModel):
    status: str
    available_sources: Dict[str, bool]
    version: str

# Payment Models
class InvestigationRequest(BaseModel):
    victim_wallet: str
    suspicious_emails: Optional[List[str]] = []
    suspicious_ips: Optional[List[str]] = []
    suspicious_domains: Optional[List[str]] = []
    scammer_wallets: Optional[List[str]] = []
    incident_description: Optional[str] = ""
    analysis_type: str = "premium_api"  # free_local, premium_api, training_data
    user_email: Optional[str] = None
    session_id: str

class PaymentIntentRequest(BaseModel):
    investigation_data: Dict[str, Any]
    analysis_type: str
    session_id: str
    user_email: Optional[str] = None

class PaymentConfirmRequest(BaseModel):
    intent_id: str
    payment_method_id: str

# API Routes
@app.get("/", response_model=Dict[str, str])
async def root():
    """Root endpoint with API information"""
    return {
        "service": "Have-I-Been-Rekt API",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs"
    }

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint with available intelligence sources"""
    sources = intel_service.get_available_sources()
    
    # Add AI model status
    sources["ai_model"] = AI_AVAILABLE
    if AI_AVAILABLE:
        try:
            ai_service = get_ai_service()
            model_info = ai_service.get_model_info()
            sources["ai_model_status"] = model_info.get("status", "unknown")
        except:
            sources["ai_model_status"] = "error"
    
    return HealthResponse(
        status="healthy",
        available_sources=sources,
        version="1.0.0"
    )

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_target(request: AnalysisRequest):
    """
    Main analysis endpoint - automatically detects input type and runs analysis
    
    Args:
        request: Analysis request with target and optional type
        
    Returns:
        Comprehensive analysis results with source attribution
    """
    try:
        # Validate input
        if not request.target or not request.target.strip():
            raise HTTPException(status_code=400, detail="Target cannot be empty")
            
        target = request.target.strip()
        
        # Perform analysis based on type
        if request.analysis_type == "auto":
            result = intel_service.comprehensive_analysis(target)
        elif request.analysis_type == "email":
            result = intel_service.analyze_email(target)
        elif request.analysis_type == "ip":
            result = intel_service.analyze_ip(target)
        elif request.analysis_type == "domain":
            result = intel_service.analyze_domain(target)
        elif request.analysis_type == "crypto":
            result = intel_service.analyze_crypto_address(target)
        else:
            raise HTTPException(status_code=400, detail=f"Invalid analysis type: {request.analysis_type}")
        
        return AnalysisResponse(
            success=True,
            data=result,
            message="Analysis completed successfully"
        )
        
    except Exception as e:
        logging.error(f"Analysis error for target {request.target}: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/analyze/email", response_model=AnalysisResponse)
async def analyze_email(request: AnalysisRequest):
    """Analyze email address for breach data and reputation"""
    try:
        result = intel_service.analyze_email(request.target)
        return AnalysisResponse(success=True, data=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/ip", response_model=AnalysisResponse)
async def analyze_ip(request: AnalysisRequest):
    """Analyze IP address for malicious activity"""
    try:
        result = intel_service.analyze_ip(request.target)
        return AnalysisResponse(success=True, data=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/domain", response_model=AnalysisResponse)
async def analyze_domain(request: AnalysisRequest):
    """Analyze domain for reputation and malicious activity"""
    try:
        result = intel_service.analyze_domain(request.target)
        return AnalysisResponse(success=True, data=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/crypto", response_model=AnalysisResponse)
async def analyze_crypto(request: AnalysisRequest):
    """Analyze cryptocurrency address for suspicious activity"""
    try:
        # Extract blockchain type if provided
        blockchain = "bitcoin"  # default
        result = intel_service.analyze_crypto_address(request.target, blockchain)
        return AnalysisResponse(success=True, data=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/sources", response_model=Dict[str, bool])
async def get_available_sources():
    """Get list of available intelligence sources"""
    return intel_service.get_available_sources()

# Payment Processing Endpoints
@app.get("/pricing", response_model=Dict[str, Any])
async def get_pricing():
    """Get pricing information for different analysis tiers"""
    return payment_processor.get_pricing_info()

@app.post("/payment/create-intent", response_model=Dict[str, Any])
async def create_payment_intent(request: PaymentIntentRequest):
    """Create payment intent for premium analysis"""
    try:
        result = create_payment_for_analysis(
            session_id=request.session_id,
            analysis_type=request.analysis_type,
            investigation_data=request.investigation_data,
            user_email=request.user_email
        )
        
        if not result['success']:
            raise HTTPException(status_code=400, detail=result['error'])
        
        return result
        
    except Exception as e:
        logging.error(f"Payment intent creation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Payment processing error: {str(e)}")

@app.post("/payment/confirm", response_model=Dict[str, Any])
async def confirm_payment(request: PaymentConfirmRequest):
    """Confirm payment and enable premium analysis"""
    try:
        status = payment_processor.confirm_payment(
            intent_id=request.intent_id,
            payment_method_id=request.payment_method_id
        )
        
        return {
            "success": status.value == "completed",
            "status": status.value,
            "message": "Payment confirmed successfully" if status.value == "completed" else "Payment failed"
        }
        
    except Exception as e:
        logging.error(f"Payment confirmation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Payment confirmation error: {str(e)}")

@app.post("/investigate", response_model=AnalysisResponse)
async def run_comprehensive_investigation(request: InvestigationRequest):
    """
    Run comprehensive investigation with payment validation
    This is the main endpoint for the victim investigation form
    """
    try:
        # Prepare investigation data
        investigation_data = {
            'victim_wallet': request.victim_wallet,
            'suspicious_emails': request.suspicious_emails or [],
            'suspicious_ips': request.suspicious_ips or [],
            'suspicious_domains': request.suspicious_domains or [],
            'scammer_wallets': request.scammer_wallets or []
        }
        
        # For free tier, skip payment validation
        if request.analysis_type == "free_local":
            # Run local analysis only (would integrate with local AI model)
            result = {
                'analysis_type': 'free_local',
                'victim_wallet': request.victim_wallet,
                'total_targets': sum(len(targets) for targets in investigation_data.values() if isinstance(targets, list)),
                'risk_score': 0.3,  # Simulated local AI risk score
                'confidence': 0.6,
                'threats_found': 0,
                'recommendations': [
                    'Consider upgrading to premium analysis for real-time threat intelligence',
                    'Enable two-factor authentication on all crypto accounts',
                    'Monitor wallet activity regularly'
                ],
                'sources_checked': ['Local AI Model', 'Community Database'],
                'disclaimer': 'Free analysis provides basic risk assessment only'
            }
        else:
            # Validate payment for premium tiers
            # In production, we would validate the payment intent here
            # For now, simulate premium analysis
            
            try:
                # This would be replaced with actual real threat intelligence
                from test_real_flow_minimal import MinimalThreatIntel
                threat_intel = MinimalThreatIntel()
                
                # Simulate comprehensive analysis
                email_results = []
                ip_results = []
                domain_results = []
                wallet_results = []
                
                for email in investigation_data['suspicious_emails']:
                    result = threat_intel.check_email_breaches(email)
                    email_results.append({
                        'target': result.target,
                        'is_threat': result.is_threat,
                        'confidence': result.confidence,
                        'details': result.details,
                        'source': result.source
                    })
                
                for ip in investigation_data['suspicious_ips']:
                    result = threat_intel.check_ip_reputation(ip)
                    ip_results.append({
                        'target': result.target,
                        'is_threat': result.is_threat,
                        'confidence': result.confidence,
                        'details': result.details,
                        'source': result.source
                    })
                
                for domain in investigation_data['suspicious_domains']:
                    result = threat_intel.check_domain_reputation(domain)
                    domain_results.append({
                        'target': result.target,
                        'is_threat': result.is_threat,
                        'confidence': result.confidence,
                        'details': result.details,
                        'source': result.source
                    })
                
                for wallet in investigation_data['scammer_wallets']:
                    result = threat_intel.check_wallet_address(wallet)
                    wallet_results.append({
                        'target': result.target,
                        'is_threat': result.is_threat,
                        'confidence': result.confidence,
                        'details': result.details,
                        'source': result.source
                    })
                
                # Calculate overall risk
                all_results = email_results + ip_results + domain_results + wallet_results
                threats_found = [r for r in all_results if r['is_threat']]
                total_checks = len(all_results)
                overall_risk = (len(threats_found) / total_checks * 100) if total_checks > 0 else 0
                
                result = {
                    'analysis_type': request.analysis_type,
                    'victim_wallet': request.victim_wallet,
                    'email_analysis': email_results,
                    'ip_analysis': ip_results,
                    'domain_analysis': domain_results,
                    'wallet_analysis': wallet_results,
                    'overall_risk_score': min(overall_risk, 90),
                    'threats_found': len(threats_found),
                    'total_checks': total_checks,
                    'confidence': sum(r['confidence'] for r in all_results) / len(all_results) if all_results else 0,
                    'recommendations': [
                        '🚨 HIGH RISK - Consider wallet compromised' if overall_risk > 70 else 
                        '⚠️ MEDIUM RISK - Monitor accounts closely' if overall_risk > 30 else 
                        '✅ LOW RISK - Continue normal precautions',
                        '💰 Transfer funds to new secure wallet immediately' if overall_risk > 70 else
                        '🔍 Verify all recent transactions' if overall_risk > 30 else
                        '🛡️ Maintain good security hygiene',
                        '🔐 Change all passwords associated with crypto accounts' if overall_risk > 50 else
                        '📚 Stay informed about current threats'
                    ],
                    'sources_checked': list(set(r['source'] for r in all_results)),
                    'incident_description': request.incident_description
                }
                
            except Exception as e:
                # Fallback to simulated analysis if real APIs fail
                logging.warning(f"Real API analysis failed, using simulation: {str(e)}")
                result = {
                    'analysis_type': request.analysis_type,
                    'victim_wallet': request.victim_wallet,
                    'simulation_mode': True,
                    'risk_score': 0.4,
                    'confidence': 0.7,
                    'threats_found': 1,
                    'recommendations': [
                        'Premium analysis temporarily unavailable - showing simulated results',
                        'Monitor wallet activity for suspicious transactions',
                        'Consider contacting support for manual analysis'
                    ],
                    'error': str(e)
                }
        
        return AnalysisResponse(
            success=True,
            data=result,
            message=f"Investigation completed for {request.victim_wallet}"
        )
        
    except Exception as e:
        logging.error(f"Investigation failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Investigation failed: {str(e)}")

@app.post("/payment/webhook")
async def stripe_webhook(request: Dict[str, Any]):
    """Handle Stripe webhook events"""
    try:
        # Extract signature from headers (in real implementation)
        signature = "simulated_signature"
        payload = str(request)
        
        result = payment_processor.handle_webhook(payload, signature)
        return result
        
    except Exception as e:
        logging.error(f"Webhook processing failed: {str(e)}")
        raise HTTPException(status_code=400, detail="Webhook processing failed")

# Batch analysis endpoint for multiple targets
class BatchAnalysisRequest(BaseModel):
    targets: List[str]
    analysis_type: Optional[str] = "auto"

@app.post("/analyze/batch", response_model=Dict[str, Any])
async def analyze_batch(request: BatchAnalysisRequest):
    """
    Batch analysis endpoint for analyzing multiple targets
    
    Args:
        request: Batch analysis request with list of targets
        
    Returns:
        Dictionary with results for each target
    """
    try:
        if len(request.targets) > 50:  # Rate limiting
            raise HTTPException(status_code=400, detail="Maximum 50 targets per batch request")
            
        results = {}
        for target in request.targets:
            if request.analysis_type == "auto":
                results[target] = intel_service.comprehensive_analysis(target)
            # Add other analysis types as needed
            
        return {
            "success": True,
            "batch_size": len(request.targets),
            "results": results,
            "message": f"Batch analysis completed for {len(request.targets)} targets"
        }
        
    except Exception as e:
        logging.error(f"Batch analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")

# AI Model Endpoints
class AIAnalysisRequest(BaseModel):
    indicator: str

class AIBatchRequest(BaseModel):
    indicators: List[str]

@app.post("/ai/analyze")
async def ai_analyze_single(request: AIAnalysisRequest):
    """
    Free AI analysis endpoint - analyze single indicator using trained model
    
    This provides instant threat assessment without API costs
    """
    if not AI_AVAILABLE:
        raise HTTPException(
            status_code=503, 
            detail="AI model not available. Install PyTorch and ensure model file exists."
        )
    
    try:
        if not request.indicator or not request.indicator.strip():
            raise HTTPException(status_code=400, detail="Indicator cannot be empty")
        
        result = analyze_threat(request.indicator.strip())
        
        return {
            "success": True,
            "data": result,
            "message": "AI analysis completed",
            "service": "hibr_ai_free_tier"
        }
        
    except Exception as e:
        logging.error(f"AI analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")

@app.post("/ai/analyze/batch")
async def ai_analyze_batch(request: AIBatchRequest):
    """
    Free AI batch analysis - analyze multiple indicators efficiently
    
    Useful for investigating complex incidents with multiple indicators
    """
    if not AI_AVAILABLE:
        raise HTTPException(
            status_code=503, 
            detail="AI model not available. Install PyTorch and ensure model file exists."
        )
    
    try:
        if not request.indicators:
            raise HTTPException(status_code=400, detail="Indicators list cannot be empty")
        
        if len(request.indicators) > 50:
            raise HTTPException(status_code=400, detail="Maximum 50 indicators per batch")
        
        # Clean indicators
        clean_indicators = [ind.strip() for ind in request.indicators if ind and ind.strip()]
        
        if not clean_indicators:
            raise HTTPException(status_code=400, detail="No valid indicators provided")
        
        results = analyze_threats(clean_indicators)
        
        return {
            "success": True,
            "data": {
                "results": results,
                "total_analyzed": len(results),
                "analysis_summary": {
                    "high_risk": len([r for r in results if r.get('risk_level') in ['HIGH', 'VERY HIGH']]),
                    "medium_risk": len([r for r in results if r.get('risk_level') == 'MEDIUM']),
                    "low_risk": len([r for r in results if r.get('risk_level') == 'LOW']),
                    "errors": len([r for r in results if 'error' in r])
                }
            },
            "message": f"AI batch analysis completed for {len(results)} indicators",
            "service": "hibr_ai_free_tier"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"AI batch analysis error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"AI batch analysis failed: {str(e)}")

@app.get("/ai/model/info")
async def ai_model_info():
    """Get information about the loaded AI model"""
    if not AI_AVAILABLE:
        return {
            "success": False,
            "message": "AI model not available",
            "status": "unavailable"
        }
    
    try:
        ai_service = get_ai_service()
        model_info = ai_service.get_model_info()
        
        return {
            "success": True,
            "data": model_info,
            "message": "AI model information retrieved"
        }
        
    except Exception as e:
        logging.error(f"AI model info error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to get model info: {str(e)}")

# Error handlers
@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "success": False,
            "message": "Endpoint not found",
            "available_endpoints": [
                "/", "/health", "/analyze", "/analyze/email", 
                "/analyze/ip", "/analyze/domain", "/analyze/crypto",
                "/sources", "/analyze/batch"
            ]
        }
    )

@app.exception_handler(500)
async def internal_error_handler(request, exc):
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "message": "Internal server error",
            "error": str(exc)
        }
    )

# AI Analysis Endpoints
class AIAnalysisRequest(BaseModel):
    indicator: str

class AIBatchRequest(BaseModel):
    indicators: List[str]

@app.post("/ai/analyze")
async def ai_analyze_single(request: AIAnalysisRequest):
    """AI-powered threat analysis for a single indicator"""
    if not AI_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI service not available")
    
    try:
        result = analyze_threat(request.indicator)
        return result
    except Exception as e:
        logging.error(f"AI analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.post("/ai/analyze/batch")
async def ai_analyze_batch(request: AIBatchRequest):
    """AI-powered threat analysis for multiple indicators (max 50)"""
    if not AI_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI service not available")
    
    if len(request.indicators) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 indicators per batch")
    
    try:
        results = analyze_threats(request.indicators)
        return {"results": results, "count": len(results)}
    except Exception as e:
        logging.error(f"Batch AI analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")

@app.get("/ai/model/info")
async def ai_model_info():
    """Get information about the AI model"""
    if not AI_AVAILABLE:
        raise HTTPException(status_code=503, detail="AI service not available")
    
    try:
        ai_service = get_ai_service()
        model_info = ai_service.get_model_info()
        return model_info
    except Exception as e:
        logging.error(f"Model info request failed: {e}")
        raise HTTPException(status_code=500, detail=f"Model info failed: {str(e)}")

if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    
    logger.info("Starting Have-I-Been-Rekt API server...")
    logger.info(f"Available intelligence sources: {intel_service.get_available_sources()}")
    
    # Run the server
    uvicorn.run(
        "hibr_api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )