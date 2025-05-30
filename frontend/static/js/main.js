document.addEventListener('DOMContentLoaded', () => {
    // DOM Elements
    const urlInput = document.getElementById('urlInput');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const resultsSection = document.getElementById('resultsSection');
    const errorMessage = document.getElementById('errorMessage');
    const tabButtons = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');

    // Event Listeners
    analyzeBtn.addEventListener('click', handleAnalysis);
    tabButtons.forEach(button => {
        button.addEventListener('click', () => switchTab(button.dataset.tab));
    });

    if (errorMessage.querySelector('.close-btn')) {
        errorMessage.querySelector('.close-btn').addEventListener('click', () => {
            errorMessage.classList.add('hidden');
        });
    }

    // Functions
    async function handleAnalysis() {
        const url = urlInput.value.trim();
        
        if (!isValidUrl(url)) {
            showError('Please enter a valid URL');
            return;
        }

        try {
            showLoading(true);
            const result = await analyzeUrl(url);
            displayResults(result);
        } catch (error) {
            showError(error.message || 'An error occurred during analysis');
        } finally {
            showLoading(false);
        }
    }

    function isValidUrl(string) {
        try {
            new URL(string);
            return true;
        } catch (_) {
            return false;
        }
    }

    async function analyzeUrl(url) {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url })
        });

        if (!response.ok) {
            throw new Error('Analysis failed. Please try again.');
        }

        return await response.json();
    }

    function displayResults(data) {
        resultsSection.classList.remove('hidden');
        
        // Display Summary
        displaySummary(data.summary);
        
        // Display Security Analysis
        displaySecurityAnalysis(data.detailed_analysis);
        
        // Display DNS Information
        displayDNSInfo(data.detailed_analysis.dns_analysis);
        
        // Display Server Information
        displayServerInfo(data.detailed_analysis.server_analysis);
        
        // Display Recommendations
        displayRecommendations(data.recommendations);

        // Show the first tab
        switchTab('security');
    }

    function displaySummary(summary) {
        const summaryContent = document.getElementById('summaryContent');
        const verdictBadge = document.getElementById('verdictBadge');
        
        // Set verdict badge
        verdictBadge.textContent = summary.verdict;
        verdictBadge.className = 'verdict-badge';
        verdictBadge.classList.add(`verdict-${summary.verdict.toLowerCase().replace(/\s+/g, '-')}`);

        // Display key findings and critical issues
        let summaryHTML = '<h3>Key Findings</h3><ul>';
        summary.key_findings.forEach(finding => {
            summaryHTML += `<li>${finding}</li>`;
        });
        summaryHTML += '</ul>';

        if (summary.critical_issues.length > 0) {
            summaryHTML += '<h3>Critical Issues</h3><ul class="critical-issues">';
            summary.critical_issues.forEach(issue => {
                summaryHTML += `<li>${issue}</li>`;
            });
            summaryHTML += '</ul>';
        }

        summaryContent.innerHTML = summaryHTML;
    }

    function displaySecurityAnalysis(analysis) {
        const securityFindings = document.getElementById('securityFindings');
        const riskScore = document.getElementById('riskScore');
        
        // Display risk score
        riskScore.textContent = `Risk Score: ${analysis.link_analysis.risk_score}`;
        
        // Display security findings
        let findingsHTML = '<ul>';
        if (analysis.link_analysis.warnings) {
            analysis.link_analysis.warnings.forEach(warning => {
                findingsHTML += `<li>${warning}</li>`;
            });
        }
        if (analysis.browser_analysis.warnings) {
            analysis.browser_analysis.warnings.forEach(warning => {
                findingsHTML += `<li>${warning}</li>`;
            });
        }
        findingsHTML += '</ul>';
        
        securityFindings.innerHTML = findingsHTML;
    }

    function displayDNSInfo(dnsAnalysis) {
        const dnsRecords = document.getElementById('dnsRecords');
        const domainInfo = document.getElementById('domainInfo');
        
        // Display DNS records
        let recordsHTML = '<div class="dns-grid">';
        for (const [recordType, records] of Object.entries(dnsAnalysis)) {
            if (recordType !== 'analysis' && recordType !== 'whois_info') {
                recordsHTML += `
                    <div class="dns-record-type">
                        <h4>${recordType.toUpperCase()} Records</h4>
                        <ul>
                            ${Array.isArray(records) ? records.map(record => `<li>${record}</li>`).join('') : `<li>${records}</li>`}
                        </ul>
                    </div>
                `;
            }
        }
        recordsHTML += '</div>';
        dnsRecords.innerHTML = recordsHTML;

        // Display WHOIS information
        if (dnsAnalysis.whois_info) {
            let whoisHTML = '<div class="whois-info">';
            for (const [key, value] of Object.entries(dnsAnalysis.whois_info)) {
                if (value && key !== 'error') {
                    whoisHTML += `
                        <div class="whois-item">
                            <strong>${key.replace('_', ' ').toUpperCase()}:</strong>
                            <span>${value}</span>
                        </div>
                    `;
                }
            }
            whoisHTML += '</div>';
            domainInfo.innerHTML = whoisHTML;
        }
    }

    function displayServerInfo(serverAnalysis) {
        const serverInfo = document.getElementById('serverInfo');
        const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
        
        // Display server information
        let serverHTML = '<div class="server-grid">';
        for (const [key, value] of Object.entries(serverAnalysis.server_info || {})) {
            if (value && typeof value !== 'object') {
                serverHTML += `
                    <div class="server-item">
                        <strong>${key.replace('_', ' ').toUpperCase()}:</strong>
                        <span>${value}</span>
                    </div>
                `;
            }
        }
        serverHTML += '</div>';
        serverInfo.innerHTML = serverHTML;

        // Display vulnerabilities
        if (serverAnalysis.vulnerabilities && serverAnalysis.vulnerabilities.length > 0) {
            let vulnHTML = '<div class="vulnerabilities-list">';
            serverAnalysis.vulnerabilities.forEach(vuln => {
                vulnHTML += `
                    <div class="vulnerability-item severity-${vuln.severity.toLowerCase()}">
                        <h4>${vuln.id}</h4>
                        <p>${vuln.description}</p>
                        <span class="severity">Severity: ${vuln.severity}</span>
                    </div>
                `;
            });
            vulnHTML += '</div>';
            vulnerabilitiesList.innerHTML = vulnHTML;
        } else {
            vulnerabilitiesList.innerHTML = '<p>No vulnerabilities detected</p>';
        }
    }

    function displayRecommendations(recommendations) {
        const recommendationsList = document.getElementById('recommendationsList');
        
        let recsHTML = '';
        recommendations.forEach(rec => {
            recsHTML += `
                <div class="recommendation-item priority-${rec.priority.toLowerCase()}">
                    <h4>${rec.category}</h4>
                    <p>${rec.suggestion}</p>
                    <span class="priority">Priority: ${rec.priority}</span>
                </div>
            `;
        });
        
        recommendationsList.innerHTML = recsHTML;
    }

    function switchTab(tabId) {
        // Update tab buttons
        tabButtons.forEach(button => {
            button.classList.toggle('active', button.dataset.tab === tabId);
        });

        // Update tab panes
        tabPanes.forEach(pane => {
            pane.classList.toggle('active', pane.id === `${tabId}Tab`);
        });
    }

    function showLoading(show) {
        loadingIndicator.classList.toggle('hidden', !show);
        analyzeBtn.disabled = show;
    }

    function showError(message) {
        errorMessage.querySelector('p').textContent = message;
        errorMessage.classList.remove('hidden');
        setTimeout(() => {
            errorMessage.classList.add('hidden');
        }, 5000);
    }
});
