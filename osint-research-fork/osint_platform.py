#!/usr/bin/env python3
"""
PGOP OSINT Research Platform
Main application entry point
"""

import os
import logging
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from datetime import datetime
import json

# Import our modules
from spiderfoot_automation import SpiderFootAutomation, ResearchTarget, TargetType
from form_automation import FormAutomationEngine
from pivot_workflows import PivotWorkflowEngine

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Initialize components
spiderfoot = SpiderFootAutomation(os.getenv('SPIDERFOOT_URL', 'http://localhost:5001'))
form_engine = FormAutomationEngine()
workflow_engine = PivotWorkflowEngine()

# Simple HTML template for the web interface
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>PGOP OSINT Research Platform</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }
        .header { text-align: center; margin-bottom: 40px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: bold; }
        .form-group input, .form-group textarea, .form-group select { 
            width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; 
        }
        .form-group textarea { height: 100px; }
        .btn { background: #007bff; color: white; padding: 12px 24px; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .results { margin-top: 40px; padding: 20px; background: #f8f9fa; border-radius: 4px; }
        .target { margin: 10px 0; padding: 10px; background: white; border-left: 4px solid #007bff; }
        .log-entry { font-family: monospace; font-size: 12px; margin: 5px 0; }
        .stats { display: flex; gap: 20px; margin: 20px 0; }
        .stat { background: white; padding: 15px; border-radius: 4px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 PGOP OSINT Research Platform</h1>
            <p>Automated SpiderFoot research with intelligent pivot sequences</p>
        </div>
        
        <form id="researchForm">
            <div class="form-group">
                <label>Target Email Address:</label>
                <input type="email" name="target_email" placeholder="suspicious@example.com" required>
            </div>
            
            <div class="form-group">
                <label>Target Domain:</label>
                <input type="text" name="target_domain" placeholder="suspicious-site.com">
            </div>
            
            <div class="form-group">
                <label>Investigation Notes:</label>
                <textarea name="investigation_notes" placeholder="Background information and research objectives..."></textarea>
            </div>
            
            <div class="form-group">
                <label>Max Research Depth:</label>
                <select name="max_depth">
                    <option value="1">Light (1 level)</option>
                    <option value="2" selected>Standard (2 levels)</option>
                    <option value="3">Deep (3 levels)</option>
                </select>
            </div>
            
            <button type="submit" class="btn">🚀 Start OSINT Research</button>
        </form>
        
        <div id="results" class="results" style="display:none;">
            <h2>Research Results</h2>
            <div id="stats" class="stats"></div>
            <div id="targets"></div>
            <div id="workflow-log"></div>
        </div>
    </div>

    <script>
        document.getElementById('researchForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData.entries());
            
            const submitBtn = e.target.querySelector('button');
            submitBtn.disabled = true;
            submitBtn.textContent = '🔄 Processing...';
            
            try {
                const response = await fetch('/api/research', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(data)
                });
                
                const result = await response.json();
                displayResults(result);
                
            } catch (error) {
                alert('Research failed: ' + error.message);
            } finally {
                submitBtn.disabled = false;
                submitBtn.textContent = '🚀 Start OSINT Research';
            }
        });
        
        function displayResults(data) {
            const resultsDiv = document.getElementById('results');
            const statsDiv = document.getElementById('stats');
            const targetsDiv = document.getElementById('targets');
            const logDiv = document.getElementById('workflow-log');
            
            // Display stats
            statsDiv.innerHTML = `
                <div class="stat">
                    <h3>${data.total_findings || 0}</h3>
                    <p>Total Findings</p>
                </div>
                <div class="stat">
                    <h3>${data.targets_generated || 0}</h3>
                    <p>Targets Generated</p>
                </div>
                <div class="stat">
                    <h3>${data.rules_executed || 0}</h3>
                    <p>Rules Executed</p>
                </div>
            `;
            
            // Display generated targets
            if (data.targets && data.targets.length > 0) {
                targetsDiv.innerHTML = '<h3>Generated Research Targets:</h3>' +
                    data.targets.map(target => 
                        `<div class="target">
                            <strong>${target.value}</strong> (${target.type})
                            <br><small>Source: ${target.source}</small>
                        </div>`
                    ).join('');
            }
            
            // Display workflow log
            if (data.execution_log && data.execution_log.length > 0) {
                logDiv.innerHTML = '<h3>Execution Log:</h3>' +
                    data.execution_log.map(log => 
                        `<div class="log-entry">${log}</div>`
                    ).join('');
            }
            
            resultsDiv.style.display = 'block';
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Main research interface"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/research', methods=['POST'])
def start_research():
    """Start automated OSINT research workflow"""
    try:
        data = request.json
        
        logger.info(f"🔍 Starting research for: {data.get('target_email', 'N/A')}")
        
        # Process form submission (this triggers SpiderFoot automation)
        form_result = form_engine.process_form_submission('threat_actor_investigation', data)
        
        # Extract findings from research results
        research_results = form_result.research_results
        all_findings = research_results.get('final_findings', [])
        
        # Convert findings to dict format for workflow engine
        findings_data = []
        for finding in all_findings:
            findings_data.append({
                'data_type': finding.data_type,
                'data_value': finding.data_value,
                'confidence': finding.confidence * 100,  # Convert to percentage
                'source_module': finding.source_module
            })
        
        # Execute workflow automation
        workflow_context = workflow_engine.execute_workflow(findings_data)
        
        # Prepare response
        response = {
            'form_id': form_result.form_id,
            'total_findings': len(all_findings),
            'targets_generated': len(workflow_context.targets),
            'rules_executed': workflow_engine.execution_stats['rules_executed'],
            'actions_performed': workflow_engine.execution_stats['actions_performed'],
            'targets': workflow_context.targets,
            'execution_log': workflow_context.execution_log,
            'auto_filled_data': form_result.auto_filled_data,
            'workflow_id': research_results.get('workflow_id'),
            'processing_time': str(research_results.get('end_time', datetime.now()) - research_results.get('start_time', datetime.now()))
        }
        
        logger.info(f"✅ Research completed: {response['total_findings']} findings, {response['targets_generated']} targets")
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"❌ Research failed: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/templates', methods=['GET'])
def get_templates():
    """Get available form templates"""
    return jsonify({
        'templates': list(form_engine.templates.keys())
    })

@app.route('/api/workflows', methods=['GET'])
def get_workflows():
    """Get available workflow rules"""
    return jsonify({
        'rules': len(workflow_engine.rules),
        'rules_list': [{'name': rule.name, 'description': rule.description, 'enabled': rule.enabled} 
                      for rule in workflow_engine.rules]
    })

@app.route('/api/status', methods=['GET'])
def get_status():
    """Get platform status"""
    return jsonify({
        'platform': 'PGOP OSINT Research Platform',
        'status': 'operational',
        'spiderfoot_url': spiderfoot.spiderfoot_url,
        'templates_loaded': len(form_engine.templates),
        'workflow_rules': len(workflow_engine.rules),
        'execution_stats': workflow_engine.execution_stats
    })

if __name__ == '__main__':
    # Load form templates
    try:
        form_engine.load_template_from_json('templates/threat_actor_template.json')
        logger.info("✅ Loaded form templates")
    except Exception as e:
        logger.warning(f"⚠️ Could not load form templates: {e}")
    
    # Load workflow rules
    try:
        workflow_engine.load_rules_from_json('workflows/example_rules.json')
        logger.info("✅ Loaded workflow rules")
    except Exception as e:
        logger.warning(f"⚠️ Could not load workflow rules: {e}")
    
    # Start the application
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    logger.info(f"🚀 Starting PGOP OSINT Platform on port {port}")
    app.run(host='0.0.0.0', port=port, debug=debug)