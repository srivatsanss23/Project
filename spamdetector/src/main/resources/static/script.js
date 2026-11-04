// SpamGuard AI — Student Capstone Edition

const SAMPLES = {
    bank: "URGENT: Security alert from your bank account! Unauthorized access detected from an unknown device. Your access will be suspended within 24 hours. Login immediately to confirm your identity and verify password at http://192.168.1.100/secure-login",
    brand: "PayPal Alert: Unauthorized transaction of $499.00 USD detected. If you did not authorize this payment, cancel immediately at http://paypa1-security-verify.com/login before your account is permanently locked.",
    lottery: "CONGRATULATIONS! You have won a $1,000,000 cash prize in our international lottery! Claim prize now before it expires today. Click here: http://bit.ly/claim-prize-today to verify account and claim your wire transfer immediately!!!",
    disposable: "Account verification required! Please reply with your secret passcode directly to support-agent@mailinator.com immediately to unfreeze your balance.",
    work: "Hi team, just a reminder about our sprint review meeting scheduled for tomorrow afternoon at 2:00 PM in Conference Room B. Please remember to update your task board before the sync. Let me know if you have any questions."
};

const HEADER_SAMPLES = {
    spoofed: "From: \"PayPal Security Team\" <security@paypal.com>\nReply-To: <phishing-collector@mailinator.com>\nReturn-Path: <bounce@attacker-relay.net>\nAuthentication-Results: mx.google.com; dkim=fail; spf=fail; dmarc=fail\nSubject: Critical: Your Account is Suspended\n\nDear Customer, suspicious activity was detected on your account. Login immediately.",
    legit: "From: \"GitHub Security\" <notifications@github.com>\nReply-To: <support@github.com>\nReturn-Path: <noreply@github.com>\nAuthentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass\nSubject: New sign-in detected for your account\n\nWe noticed a new login to your account from a new browser."
};

const BATCH_SAMPLE = [
    "URGENT: Security alert from your bank account! Login immediately at http://192.168.1.100/login",
    "Hi Alice, are we still meeting for lunch today at 12:30 PM?",
    "CONGRATULATIONS! You won a $1,000,000 lottery prize! Claim cash now at http://bit.ly/claim",
    "Special promotion! Buy now and get 100% free shipping with an exclusive deal on all items.",
    "Your Uber verification code is 492819. Never share this code with anyone.",
    "Dear customer, your PayPal transaction of $850 is pending. Cancel at http://paypa1-verify.com",
    "Team sprint sync notes from our engineering design session are attached in the doc.",
    "Please send your password directly to admin@tempmail.com to prevent termination.",
    "Your package was delivered to the front door at 3:15 PM.",
    "Final notice: You have won a free iPhone 16! Call 09058094455 immediately!"
];

let debounceTimer = null;
let lastAnalyzedText = "";
let currentAnalysisData = null;
let latestBatchCsvContent = "";

const API_BASE = window.location.origin.startsWith("http") ? "" : "http://localhost:8080";

document.addEventListener("DOMContentLoaded", () => {
    const textarea = document.getElementById("msg");
    const charCount = document.getElementById("charCount");
    const autoScanToggle = document.getElementById("autoScanToggle");

    textarea.addEventListener("input", () => {
        const text = textarea.value;
        const words = text.trim() ? text.trim().split(/\s+/).length : 0;
        charCount.textContent = `${text.length} character${text.length === 1 ? '' : 's'} • ${words} word${words === 1 ? '' : 's'}`;

        if (autoScanToggle && autoScanToggle.checked) {
            clearTimeout(debounceTimer);
            if (text.trim().length > 10) {
                debounceTimer = setTimeout(() => {
                    checkSpam();
                }, 600);
            }
        }
    });

    fetchTelemetryAndHistory();
    // Preload benchmark in background so the benchmark tab is never blank
    loadBenchmarkMetrics();
});

// Tab Switcher - resilient against browser event differences
function switchTab(tabId, ev) {
    document.querySelectorAll(".tab-content").forEach(tab => tab.style.display = "none");
    document.querySelectorAll(".tab-btn").forEach(btn => btn.classList.remove("active"));

    const targetTab = document.getElementById(`tab-${tabId}`);
    if (targetTab) {
        targetTab.style.display = "block";
    }

    let clickedBtn = null;
    if (ev && ev.target) {
        clickedBtn = ev.target.closest(".tab-btn");
    } else if (typeof event !== "undefined" && event && event.target) {
        clickedBtn = event.target.closest(".tab-btn");
    }
    if (!clickedBtn) {
        clickedBtn = document.querySelector(`.tab-btn[onclick*="'${tabId}'"]`);
    }
    if (clickedBtn) {
        clickedBtn.classList.add("active");
    }

    if (tabId === "telemetry") {
        fetchTelemetryAndHistory();
    } else if (tabId === "benchmark") {
        loadBenchmarkMetrics();
    }
}

// Theme Toggle
function toggleTheme() {
    const body = document.body;
    const btn = document.getElementById("themeToggle");
    if (body.classList.contains("theme-dark")) {
        body.classList.remove("theme-dark");
        body.classList.add("theme-light");
        btn.textContent = "☀️";
    } else {
        body.classList.remove("theme-light");
        body.classList.add("theme-dark");
        btn.textContent = "🌙";
    }
}

function loadSample(key) {
    const text = SAMPLES[key];
    if (!text) return;

    const textarea = document.getElementById("msg");
    textarea.value = text;
    const words = text.trim().split(/\s+/).length;
    document.getElementById("charCount").textContent = `${text.length} characters • ${words} words`;

    checkSpam();
}

function clearAll() {
    const textarea = document.getElementById("msg");
    textarea.value = "";
    document.getElementById("charCount").textContent = "0 characters • 0 words";

    const resultCard = document.getElementById("resultCard");
    resultCard.style.display = "none";
    resultCard.className = "card result-card";
    lastAnalyzedText = "";
    currentAnalysisData = null;
}

// Live Scanner Classification
async function checkSpam() {
    const inputElement = document.getElementById("msg");
    const resultCard = document.getElementById("resultCard");
    const checkBtn = document.getElementById("checkBtn");
    const btnIcon = document.getElementById("btnIcon");
    const btnText = document.getElementById("btnText");

    const text = inputElement.value.trim();

    if (!text) {
        alert("Please enter or paste a message to analyze.");
        return;
    }

    if (text === lastAnalyzedText && resultCard.style.display !== "none") {
        return;
    }

    checkBtn.disabled = true;
    btnIcon.textContent = "⏳";
    btnText.textContent = "Analyzing...";

    try {
        const response = await fetch(`${API_BASE}/api/classify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: text })
        });

        if (!response.ok) {
            throw new Error(`Server status ${response.status}`);
        }

        const data = await response.json();
        lastAnalyzedText = text;
        currentAnalysisData = data;
        renderResult(data, text);

    } catch (error) {
        console.error("Spam classification request failed:", error);
        resultCard.style.display = "block";
        resultCard.className = "card result-card spam";
        resultCard.innerHTML = `
            <div style="color: #ef4444; line-height: 1.5;">
                <strong>⚠️ Backend Server Unavailable</strong><br>
                Please ensure Spring Boot is running (<code>.\\mvnw.cmd spring-boot:run</code>).<br>
                <small style="color: #94a3b8;">${error.message}</small>
            </div>
        `;
    } finally {
        checkBtn.disabled = false;
        btnIcon.textContent = "🔍";
        btnText.textContent = "Analyze Message";
    }
}

function renderResult(data, originalText) {
    const resultCard = document.getElementById("resultCard");
    const verdictPill = document.getElementById("verdictPill");
    const verdictMeta = document.getElementById("verdictMeta");
    const scoreNumber = document.getElementById("scoreNumber");
    const gaugeProgress = document.getElementById("gaugeProgress");
    const breakdownGrid = document.getElementById("breakdownGrid");
    const reasonsList = document.getElementById("reasonsList");
    const highlightSection = document.getElementById("highlightSection");
    const highlightPreview = document.getElementById("highlightPreview");
    const nbBadgeValue = document.getElementById("nbBadgeValue");
    const tfidfBadgeValue = document.getElementById("tfidfBadgeValue");
    const lrBadgeValue = document.getElementById("lrBadgeValue");
    const entropyBadgeValue = document.getElementById("entropyBadgeValue");
    const intelSection = document.getElementById("intelSection");
    const intelCards = document.getElementById("intelCards");
    const brandSection = document.getElementById("brandSection");
    const brandCards = document.getElementById("brandCards");

    let stateClass = "legitimate";
    let verdictLabel = "LEGITIMATE / SAFE";

    if (data.prediction === "SPAM") {
        stateClass = "spam";
        verdictLabel = "SPAM DETECTED";
    } else if (data.prediction === "SUSPICIOUS") {
        stateClass = "suspicious";
        verdictLabel = "SUSPICIOUS CONTENT";
    }

    resultCard.className = `card result-card ${stateClass}`;
    resultCard.style.display = "flex";

    verdictPill.textContent = verdictLabel;
    verdictMeta.textContent = `Risk Level: ${data.riskLevel || 'LOW'} • Latency: ${data.executionTimeMs || 0}ms`;

    scoreNumber.textContent = data.score;
    gaugeProgress.setAttribute("stroke-dasharray", `${data.score}, 100`);

    // Model comparison badges
    if (data.machineLearning) {
        const ml = data.machineLearning;
        if (nbBadgeValue) nbBadgeValue.textContent = `${ml.predictedLabel} (${ml.mlScore}% prob)`;
    }

    if (data.tfIdfResult) {
        const tf = data.tfIdfResult;
        if (tfidfBadgeValue) tfidfBadgeValue.textContent = `${tf.predictedLabel} (${tf.tfIdfScore}% sim)`;
    }

    if (data.logisticRegressionResult) {
        const lr = data.logisticRegressionResult;
        if (lrBadgeValue) lrBadgeValue.textContent = `${lr.lrScore}% (logit: ${lr.rawLogit})`;
    }

    if (data.linguisticProfile) {
        const lp = data.linguisticProfile;
        if (entropyBadgeValue) entropyBadgeValue.textContent = `${lp.shannonEntropy} bits (TTR: ${lp.lexicalDiversityTtr})`;
    }

    // Stylometry Details Section
    const stylometryCard = document.getElementById("stylometryCard");
    const stylometryMetricsGrid = document.getElementById("stylometryMetricsGrid");
    if (stylometryCard && stylometryMetricsGrid && data.linguisticProfile) {
        stylometryCard.style.display = "block";
        const lp = data.linguisticProfile;
        stylometryMetricsGrid.innerHTML = `
            <div class="intel-badge"><span>Shannon Entropy:</span><strong>${lp.shannonEntropy}</strong></div>
            <div class="intel-badge"><span>Type-Token Ratio:</span><strong>${lp.lexicalDiversityTtr}</strong></div>
            <div class="intel-badge"><span>Digit Frequency:</span><strong>${lp.digitRatio}%</strong></div>
            <div class="intel-badge"><span>Punctuation:</span><strong>${lp.punctuationRatio}%</strong></div>
            <div class="intel-badge"><span>Uppercase:</span><strong>${lp.uppercaseRatio}%</strong></div>
            <div class="intel-badge"><span>Readability (Flesch):</span><strong>${lp.readabilityScore}</strong></div>
        `;
    } else if (stylometryCard) {
        stylometryCard.style.display = "none";
    }

    // Breakdown bars
    breakdownGrid.innerHTML = "";
    if (data.categoryScores) {
        for (const [cat, pts] of Object.entries(data.categoryScores)) {
            const card = document.createElement("div");
            card.className = "breakdown-card";
            card.innerHTML = `
                <div class="breakdown-label">${cat}: ${pts} pts</div>
                <div class="breakdown-bar-bg">
                    <div class="breakdown-bar-fill" style="width: ${Math.min(pts, 100)}%;"></div>
                </div>
            `;
            breakdownGrid.appendChild(card);
        }
    }

    // IP Intel
    if (data.ipIntelligence && data.ipIntelligence.length > 0) {
        intelSection.style.display = "block";
        intelCards.innerHTML = "";
        data.ipIntelligence.forEach(ip => {
            const div = document.createElement("div");
            div.className = "intel-badge";
            div.innerHTML = `
                <strong>📡 IP: ${escapeHtml(ip.ip)}</strong>
                <span>${escapeHtml(ip.city)}, ${escapeHtml(ip.country)} • ISP: <em>${escapeHtml(ip.isp)}</em></span>
                <small style="color: var(--text-secondary);">${escapeHtml(ip.riskSummary)}</small>
            `;
            intelCards.appendChild(div);
        });
    } else {
        intelSection.style.display = "none";
    }

    // Brand Impersonation
    if (data.brandFindings && data.brandFindings.length > 0) {
        brandSection.style.display = "block";
        brandCards.innerHTML = "";
        data.brandFindings.forEach(b => {
            const div = document.createElement("div");
            div.className = "intel-badge";
            div.style.borderColor = "var(--danger)";
            div.innerHTML = `
                <strong style="color: var(--danger);">🚨 ${escapeHtml(b.riskType)}: Target '${escapeHtml(b.targetBrand.toUpperCase())}'</strong>
                <span>${escapeHtml(b.description)}</span>
            `;
            brandCards.appendChild(div);
        });
    } else {
        brandSection.style.display = "none";
    }

    // Reasons
    reasonsList.innerHTML = "";
    if (data.reasons && data.reasons.length > 0) {
        data.reasons.forEach(r => {
            const li = document.createElement("li");
            li.textContent = r;
            reasonsList.appendChild(li);
        });
    }

    // Highlight preview
    if (data.flaggedTokens && data.flaggedTokens.length > 0) {
        highlightSection.style.display = "block";
        highlightPreview.innerHTML = buildHighlightedHtml(originalText, data.flaggedTokens);
    } else {
        highlightSection.style.display = "none";
    }

    // Explainable AI (XAI) Feature Attribution
    const xaiSection = document.getElementById("xaiSection");
    const xaiChart = document.getElementById("xaiChart");
    if (xaiSection && xaiChart && data.machineLearning && data.machineLearning.featureAttributions && data.machineLearning.featureAttributions.length > 0) {
        xaiSection.style.display = "block";
        xaiChart.innerHTML = "";
        data.machineLearning.featureAttributions.forEach(fa => {
            const row = document.createElement("div");
            row.className = "xai-row";
            const sign = fa.logOdds >= 0 ? "+" : "";
            row.innerHTML = `
                <div class="xai-word">${escapeHtml(fa.token)}</div>
                <div class="xai-bar-track">
                    <div class="xai-bar-fill ${fa.pullDirection}" style="width: ${Math.min(fa.relativeWeight * 3, 100)}%;"></div>
                </div>
                <div class="xai-meta" style="color: ${fa.pullDirection === 'SPAM' ? 'var(--danger)' : 'var(--success)'};">
                    ${fa.pullDirection} (${sign}${fa.logOdds})
                </div>
            `;
            xaiChart.appendChild(row);
        });
    } else if (xaiSection) {
        xaiSection.style.display = "none";
    }

    // Cybersecurity: MITRE ATT&CK Matrix Mapping
    const mitreSection = document.getElementById("mitreSection");
    const mitreCards = document.getElementById("mitreCards");
    if (mitreSection && mitreCards && data.mitreTechniques && data.mitreTechniques.length > 0) {
        mitreSection.style.display = "block";
        mitreCards.innerHTML = "";
        data.mitreTechniques.forEach(m => {
            const card = document.createElement("div");
            card.style.cssText = "background:rgba(30,41,59,0.7); padding:8px 12px; border-radius:6px; font-size:0.85rem;";
            card.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <strong style="color:var(--accent-color);">🎯 ${escapeHtml(m.id)}: ${escapeHtml(m.name)}</strong>
                    <span style="font-size:0.75rem; background:rgba(99,102,241,0.2); padding:2px 8px; border-radius:10px;">${escapeHtml(m.tactic)} • ${escapeHtml(m.detectionConfidence)}</span>
                </div>
                <p style="margin:4px 0 0 0; color:var(--text-secondary); font-size:0.8rem;">${escapeHtml(m.description)}</p>
            `;
            mitreCards.appendChild(card);
        });
    } else if (mitreSection) {
        mitreSection.style.display = "none";
    }

    // Cybersecurity: Automated IOC Extraction & Defanging with Copy Buttons
    const iocSection = document.getElementById("iocSection");
    const iocCountBadge = document.getElementById("iocCountBadge");
    const iocDetailsBox = document.getElementById("iocDetailsBox");
    if (iocSection && iocDetailsBox && data.iocReport && data.iocReport.totalIocsFound > 0) {
        iocSection.style.display = "block";
        iocCountBadge.textContent = `${data.iocReport.totalIocsFound} Artifacts`;
        let html = `<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
            <span><strong>SHA-256:</strong> <span style="color:#38bdf8;">${data.iocReport.messageSha256Hash}</span></span>
            <button class="btn-copy" onclick="copyToClipboard('${data.iocReport.messageSha256Hash}')">📋 Copy Hash</button>
        </div>`;
        if (data.iocReport.defangedUrls && data.iocReport.defangedUrls.length > 0) {
            html += `<div style="margin-top:6px;"><strong>Defanged URLs:</strong><div style="display:flex; flex-direction:column; gap:4px; margin-top:2px;">`;
            data.iocReport.defangedUrls.forEach(u => {
                html += `<div style="display:flex; justify-content:space-between; align-items:center; background:rgba(0,0,0,0.25); padding:3px 8px; border-radius:4px;">
                    <code>${escapeHtml(u)}</code>
                    <button class="btn-copy" onclick="copyToClipboard('${escapeHtml(u)}')">📋 Copy</button>
                </div>`;
            });
            html += `</div></div>`;
        }
        if (data.iocReport.extractedDomains && data.iocReport.extractedDomains.length > 0) {
            html += `<div style="margin-top:6px;"><strong>Target Domains:</strong> ${data.iocReport.extractedDomains.map(d => `<code>${escapeHtml(d)}</code>`).join(" ")}</div>`;
        }
        if (data.iocReport.extractedIps && data.iocReport.extractedIps.length > 0) {
            html += `<div style="margin-top:6px;"><strong>Target IPs:</strong> ${data.iocReport.extractedIps.map(ip => `<code>${escapeHtml(ip)}</code>`).join(" ")}</div>`;
        }
        iocDetailsBox.innerHTML = html;
    } else if (iocSection) {
        iocSection.style.display = "none";
    }

    // Cybersecurity: Automated SOC Incident Response Remediation Playbook
    const playbookSection = document.getElementById("playbookSection");
    const playbookList = document.getElementById("playbookList");
    if (playbookSection && playbookList) {
        const steps = generateSocPlaybook(data);
        if (steps.length > 0) {
            playbookSection.style.display = "block";
            playbookList.innerHTML = steps.map(s => `<li>${s}</li>`).join("");
        } else {
            playbookSection.style.display = "none";
        }
    }
}

function buildHighlightedHtml(text, tokens) {
    if (!tokens || tokens.length === 0) return escapeHtml(text);
    let html = escapeHtml(text);

    const uniqueTokens = Array.from(new Set(tokens.map(t => JSON.stringify({ token: t.token, category: t.category }))))
                              .map(s => JSON.parse(s));

    uniqueTokens.forEach(t => {
        if (!t.token) return;
        const esc = escapeHtml(t.token);
        const replacement = `<mark class="hl-token ${escapeHtml(t.category)}" title="Category: ${escapeHtml(t.category)}">${esc}</mark>`;
        html = html.split(esc).join(replacement);
    });

    return html;
}

function escapeHtml(str) {
    if (!str) return "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function exportAnalysisJson() {
    if (!currentAnalysisData) return;
    const blob = new Blob([JSON.stringify(currentAnalysisData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `spamguard-analysis-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
}

async function exportStixBundle() {
    const text = document.getElementById("msg").value.trim();
    if (!text) {
        alert("Please analyze a message first before exporting STIX threat report.");
        return;
    }
    try {
        const res = await fetch(`${API_BASE}/api/stix-bundle`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: text })
        });
        const stixData = await res.json();
        const blob = new Blob([JSON.stringify(stixData, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `SpamGuard_STIX2.1_Threat_Incident_${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) {
        alert("Failed to export STIX 2.1 threat report: " + e.message);
    }
}

// ACADEMIC BENCHMARK & EVALUATION
async function loadBenchmarkMetrics() {
    const loading = document.getElementById("benchmarkLoading");
    const container = document.getElementById("benchmarkResultsArea");
    if (!container) return;

    if (loading) loading.style.display = "block";

    try {
        const res = await fetch(`${API_BASE}/api/benchmark`);
        if (!res.ok) {
            throw new Error(`Server returned HTTP ${res.status}: ${res.statusText}`);
        }
        const data = await res.json();

        if (loading) loading.style.display = "none";

        let html = `
            <!-- Dataset & Methodological Overview -->
            <div class="benchmark-summary-box">
                <h4>📊 Experimental Test Corpus & Benchmark Summary</h4>
                <p style="color:var(--text-muted); font-size:0.85rem; margin-bottom:12px;">
                    Evaluated across <strong>${data.totalCorpusSamples} labeled messages</strong> (${data.spamSamples} Spam, ${data.hamSamples} Ham) 
                    including real-world UCI SMS spam samples, corporate business ham, and adversarial phishing lures.
                </p>
                <div class="cm-table-wrapper">
                    <table class="cm-summary-table">
                        <thead>
                            <tr>
                                <th>Model Architecture</th>
                                <th style="color:var(--success);">TP</th>
                                <th style="color:var(--warning);">FN (Missed)</th>
                                <th style="color:var(--danger);">FP (False Alarm)</th>
                                <th style="color:var(--primary);">TN</th>
                                <th>Accuracy</th>
                                <th>Precision</th>
                                <th>Recall</th>
                                <th>Specificity</th>
                                <th>F1-Score</th>
                            </tr>
                        </thead>
                        <tbody>
        `;

        data.models.forEach(m => {
            html += `
                <tr>
                    <td style="font-weight:600; color:var(--text-bright);">${escapeHtml(m.modelName)}</td>
                    <td style="color:var(--success); font-weight:700;">${m.truePositives}</td>
                    <td style="color:var(--warning); font-weight:700;">${m.falseNegatives}</td>
                    <td style="color:var(--danger); font-weight:700;">${m.falsePositives}</td>
                    <td style="color:var(--primary); font-weight:700;">${m.trueNegatives}</td>
                    <td><strong>${m.accuracy}%</strong></td>
                    <td><strong style="color:var(--success);">${m.precision}%</strong></td>
                    <td><strong style="color:var(--warning);">${m.recall}%</strong></td>
                    <td><strong>${m.specificity || (Math.round((m.trueNegatives / (m.trueNegatives + m.falsePositives || 1)) * 1000) / 10)}%</strong></td>
                    <td><strong style="color:var(--accent-cyan);">${m.f1Score}%</strong></td>
                </tr>
            `;
        });

        html += `
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- Detailed 2x2 Contingency Confusion Matrices -->
            <h4 style="margin-top:20px; margin-bottom:10px; color:var(--primary); font-size:1.05rem;">
                🔬 2×2 Contingency Confusion Matrices (Standard Academic Format)
            </h4>
            <div class="benchmark-grid">
        `;

        data.models.forEach(m => {
            const specVal = m.specificity || (Math.round((m.trueNegatives / (m.trueNegatives + m.falsePositives || 1)) * 1000) / 10);
            html += `
                <div class="eval-card">
                    <div class="eval-card-header">
                        <h4>${escapeHtml(m.modelName)}</h4>
                        <span class="eval-f1-badge">F1: ${m.f1Score}%</span>
                    </div>

                    <div class="cm-table-wrapper">
                        <table class="cm-matrix-table">
                            <thead>
                                <tr>
                                    <th rowspan="2" class="cm-corner">Actual \\ Predicted</th>
                                    <th colspan="2" class="cm-pred-header">PREDICTED CLASS</th>
                                </tr>
                                <tr>
                                    <th class="cm-pred-col spam-col">PREDICTED SPAM</th>
                                    <th class="cm-pred-col ham-col">PREDICTED HAM (LEGIT)</th>
                                </tr>
                            </thead>
                            <tbody>
                                <tr>
                                    <th class="cm-actual-row spam-row">ACTUAL SPAM</th>
                                    <td class="cm-cell cm-tp">
                                        <div class="cm-num">${m.truePositives}</div>
                                        <div class="cm-label">True Positive (TP)</div>
                                        <div class="cm-subtext">Correctly detected spam</div>
                                    </td>
                                    <td class="cm-cell cm-fn">
                                        <div class="cm-num">${m.falseNegatives}</div>
                                        <div class="cm-label">False Negative (FN)</div>
                                        <div class="cm-subtext">Type II Error (Missed)</div>
                                    </td>
                                </tr>
                                <tr>
                                    <th class="cm-actual-row ham-row">ACTUAL HAM</th>
                                    <td class="cm-cell cm-fp">
                                        <div class="cm-num">${m.falsePositives}</div>
                                        <div class="cm-label">False Positive (FP)</div>
                                        <div class="cm-subtext">Type I Error (False Alarm)</div>
                                    </td>
                                    <td class="cm-cell cm-tn">
                                        <div class="cm-num">${m.trueNegatives}</div>
                                        <div class="cm-label">True Negative (TN)</div>
                                        <div class="cm-subtext">Correctly passed legit</div>
                                    </td>
                                </tr>
                            </tbody>
                        </table>
                    </div>

                    <div class="cm-metrics-bar">
                        <div class="cm-metric-pill"><span>Accuracy</span> <strong>${m.accuracy}%</strong></div>
                        <div class="cm-metric-pill"><span>Precision</span> <strong style="color:var(--success);">${m.precision}%</strong></div>
                        <div class="cm-metric-pill"><span>Recall</span> <strong style="color:var(--warning);">${m.recall}%</strong></div>
                        <div class="cm-metric-pill"><span>Specificity</span> <strong style="color:var(--primary);">${specVal}%</strong></div>
                    </div>
                </div>
            `;
        });

        html += `</div>`;

        // ROC-AUC Curve & Optimal Decision Cutoff Report
        if (data.rocReport) {
            const roc = data.rocReport;
            html += `
                <div class="roc-container" style="margin-top:24px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                        <h4 style="color:var(--primary); margin:0;">
                            📈 Receiver Operating Characteristic (ROC-AUC) & Cutoff Optimization
                        </h4>
                        <span class="eval-f1-badge">AUC: ${roc.areaUnderCurve}</span>
                    </div>

                    <div class="roc-kpis">
                        <div class="roc-kpi">
                            <span>Area Under Curve (AUC-ROC)</span>
                            <strong>${roc.areaUnderCurve}</strong>
                        </div>
                        <div class="roc-kpi">
                            <span>Optimal Decision Cutoff (τ*)</span>
                            <strong style="color:var(--success);">${roc.optimalThreshold}</strong>
                        </div>
                        <div class="roc-kpi">
                            <span>Max Youden Index (J)</span>
                            <strong style="color:var(--accent-cyan);">${roc.maxYoudenIndex}</strong>
                        </div>
                    </div>

                    <p style="font-size:0.83rem; color:var(--text-muted); line-height:1.5; margin-bottom:12px;">
                        Evaluated across 8 discrete probability decision thresholds. The optimal classification cutoff is 
                        identified via <strong>Youden's J statistic</strong> (\(J = \text{Sensitivity} + \text{Specificity} - 1\)), 
                        yielding the mathematically ideal boundary to minimize both false positives and missed spam.
                    </p>

                    <!-- Interactive SVG ROC Curve Chart -->
                    <div style="background:rgba(15, 23, 42, 0.7); border:1px solid var(--border-color); border-radius:8px; padding:16px; margin-bottom:16px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                            <span style="font-size:0.85rem; font-weight:700; color:var(--text-bright);">Interactive ROC Space (TPR vs FPR Curve)</span>
                            <span style="font-size:0.75rem; color:var(--text-muted);">Points plotted directly from 5-Fold Stratified Cross-Validation</span>
                        </div>
                        <div style="width:100%; max-width:540px; margin:0 auto;">
                            ${renderRocSvg(roc.points, roc.optimalThreshold)}
                        </div>
                    </div>

                    <div class="cm-table-wrapper">
                        <table class="cm-summary-table"  style="font-size:0.8rem;">
                            <thead>
                                <tr>
                                    <th>Threshold (τ)</th>
                                    <th>False Positive Rate (FPR)</th>
                                    <th>True Positive Rate (TPR / Recall)</th>
                                    <th>Youden's Index (J)</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
            `;

            if (roc.points && roc.points.length > 0) {
                roc.points.forEach(pt => {
                    const isOptimal = pt.threshold === roc.optimalThreshold;
                    html += `
                        <tr style="${isOptimal ? 'background:rgba(0, 230, 118, 0.08); font-weight:700;' : ''}">
                            <td>${pt.threshold}</td>
                            <td style="color:var(--danger);">${pt.falsePositiveRate}</td>
                            <td style="color:var(--success);">${pt.truePositiveRate}</td>
                            <td style="color:var(--accent-cyan);">${pt.youdenIndex}</td>
                            <td>${isOptimal ? '⭐ Optimal Cutoff (Max J)' : '--'}</td>
                        </tr>
                    `;
                });
            }

            html += `
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        container.innerHTML = html;

    } catch (e) {
        if (loading) loading.style.display = "none";
        container.innerHTML = `
            <div style="background:rgba(255, 77, 77, 0.1); border:1px solid rgba(255, 77, 77, 0.3); border-radius:8px; padding:16px; margin-top:10px;">
                <h4 style="color:var(--danger); margin-bottom:6px;">⚠️ Unable to Load Benchmark Evaluation</h4>
                <p style="font-size:0.85rem; color:var(--text-muted); margin-bottom:10px;">${escapeHtml(e.message)}</p>
                <button type="button" class="btn-primary" onclick="loadBenchmarkMetrics()" style="flex:none; padding:6px 14px; font-size:0.85rem;">
                    🔄 Retry Benchmark
                </button>
            </div>
        `;
    }
}

// EMAIL HEADER INSPECTOR
function loadHeaderSample(type) {
    document.getElementById("emailHeaderInput").value = HEADER_SAMPLES[type] || "";
}

async function inspectEmailHeaders() {
    const raw = document.getElementById("emailHeaderInput").value.trim();
    const box = document.getElementById("headerResultsBox");

    if (!raw) {
        alert("Please paste RFC-822 email headers.");
        return;
    }

    box.style.display = "block";
    box.innerHTML = "<em>Analyzing email headers and cryptographic authentication...</em>";

    try {
        const res = await fetch(`${API_BASE}/api/classify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: raw })
        });
        const data = await res.json();
        const r = data.emailHeaderReport;

        if (!r || !r.isEmailFormat) {
            box.innerHTML = `<span style="color: var(--warning);">⚠️ Input was not recognized as a standard RFC-822 email header. Evaluated as regular text (Verdict: ${data.prediction}).</span>`;
            return;
        }

        box.innerHTML = `
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <strong>Sender Spoofing: ${r.isSenderSpoofed ? '<span style="color:var(--danger)">🚨 SPOOFED SENDER DETECTED</span>' : '<span style="color:var(--success)">✅ ALIGNED SENDER</span>'}</strong>
                <span class="auth-badge ${r.spfStatus}">SPF: ${r.spfStatus}</span>
                <span class="auth-badge ${r.dkimStatus}">DKIM: ${r.dkimStatus}</span>
                <span class="auth-badge ${r.dmarcStatus}">DMARC: ${r.dmarcStatus}</span>
            </div>
            <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px; margin-top:8px;">
                <div><strong>From:</strong> <code>${escapeHtml(r.fromHeader || 'None')}</code></div>
                <div><strong>Reply-To:</strong> <code>${escapeHtml(r.replyToHeader || 'None')}</code></div>
                <div><strong>Return-Path:</strong> <code>${escapeHtml(r.returnPathHeader || 'None')}</code></div>
                <div><strong>Subject:</strong> ${escapeHtml(r.subjectHeader || 'None')}</div>
            </div>
            ${r.warnings && r.warnings.length > 0 ? `
                <div style="margin-top:10px; color:var(--danger);">
                    <strong>Security Warnings:</strong>
                    <ul>${r.warnings.map(w => `<li>${escapeHtml(w)}</li>`).join('')}</ul>
                </div>` : ''}
        `;
    } catch (e) {
        box.innerHTML = `<span style="color:var(--danger)">Error: ${e.message}</span>`;
    }
}

// BATCH CSV PROCESSOR
function loadBatchSample() {
    document.getElementById("batchInput").value = BATCH_SAMPLE.join("\n");
}

async function runBatchScan() {
    const raw = document.getElementById("batchInput").value.trim();
    if (!raw) {
        alert("Please paste messages to analyze.");
        return;
    }

    const lines = raw.split("\n").map(l => l.trim()).filter(l => l.length > 0);
    const container = document.getElementById("batchResultsContainer");
    container.style.display = "block";

    try {
        const res = await fetch(`${API_BASE}/api/batch`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(lines)
        });

        const report = await res.json();
        latestBatchCsvContent = report.csvExportContent;

        document.getElementById("batchTotal").textContent = report.totalMessages;
        document.getElementById("batchSpam").textContent = report.spamCount;
        document.getElementById("batchSus").textContent = report.suspiciousCount;
        document.getElementById("batchLegit").textContent = report.legitimateCount;
        document.getElementById("batchAvgScore").textContent = `${report.averageScore}/100`;

        const tbody = document.getElementById("batchTableBody");
        tbody.innerHTML = "";
        report.items.forEach(it => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td>${it.index}</td>
                <td><span class="auth-badge ${it.prediction === 'SPAM' ? 'FAIL' : (it.prediction === 'SUSPICIOUS' ? 'NONE' : 'PASS')}">${it.prediction}</span></td>
                <td><strong>${it.score}</strong></td>
                <td>${it.riskLevel}</td>
                <td><small>${escapeHtml(it.topReason)}</small></td>
                <td><small>${escapeHtml(it.messageSnippet)}</small></td>
            `;
            tbody.appendChild(tr);
        });

    } catch (e) {
        alert("Batch scan failed: " + e.message);
    }
}

function downloadBatchCsv() {
    if (!latestBatchCsvContent) return;
    const blob = new Blob([latestBatchCsvContent], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `spamguard-batch-results-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
}

// TELEMETRY & AUDIT LOG
async function fetchTelemetryAndHistory() {
    try {
        const statsRes = await fetch(`${API_BASE}/api/stats`);
        if (statsRes.ok) {
            const s = await statsRes.json();
            document.getElementById("kpiTotal").textContent = s.totalScans || 0;
            document.getElementById("kpiRate").textContent = `${s.threatRatePercent || 0}%`;
            document.getElementById("kpiAvgScore").textContent = `${s.averageThreatScore || 0} / 100`;
            document.getElementById("kpiLatency").textContent = `${s.averageLatencyMs || 0} ms`;
        }

        const histRes = await fetch(`${API_BASE}/api/history`);
        if (histRes.ok) {
            const history = await histRes.json();
            const tbody = document.getElementById("historyTableBody");
            tbody.innerHTML = "";

            if (!history || history.length === 0) {
                tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-secondary);">No scans recorded yet. Run a scan to see live telemetry!</td></tr>`;
                return;
            }

            history.forEach(rec => {
                const tr = document.createElement("tr");
                const timeStr = rec.scannedAt ? new Date(rec.scannedAt).toLocaleTimeString() : "--";
                tr.innerHTML = `
                    <td>${timeStr}</td>
                    <td><code>${rec.sourceChannel}</code></td>
                    <td><span class="auth-badge ${rec.prediction === 'SPAM' ? 'FAIL' : (rec.prediction === 'SUSPICIOUS' ? 'NONE' : 'PASS')}">${rec.prediction}</span></td>
                    <td><strong>${rec.score}</strong></td>
                    <td>${rec.riskLevel}</td>
                    <td><small>${escapeHtml(rec.topReason || '')}</small></td>
                    <td><small>${escapeHtml(rec.messagePreview || '')}</small></td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.warn("Telemetry fetch error:", e);
    }
}

async function sendFeedback(type) {
    if (!currentAnalysisData) return;
    try {
        await fetch(`${API_BASE}/api/feedback`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                message: document.getElementById("msg").value,
                feedbackType: type,
                predictedLabel: currentAnalysisData.prediction
            })
        });
        alert(`Feedback recorded: ${type.replace('_', ' ')}. Thank you!`);
    } catch (e) {
        alert("Feedback noted locally.");
    }
}

// ==========================================
// ADVERSARIAL ATTACK & DEFENSE LAB
// ==========================================
const ATTACK_PRESETS = {
    homoglyph: {
        text: "URGENT: Security alert from your bank! Login to confirm account credentials at http://verify-bank.com",
        type: "HOMOGLYPH"
    },
    zerowidth: {
        text: "CONGRATULATIONS: Claim your free lottery prize of $50,000 immediately at http://claim-cash.net",
        type: "ZERO_WIDTH"
    },
    ham_poisoning: {
        text: "Special offer: Transfer $500 Bitcoin to wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa for 10x guaranteed returns.",
        type: "GOOD_WORD"
    },
    leetspeak: {
        text: "Urgent account verification needed! Reset your password immediately before balance is locked.",
        type: "LEET_SPEAK"
    }
};

function loadAttackPreset(key) {
    const p = ATTACK_PRESETS[key];
    if (!p) return;
    document.getElementById("advInputMsg").value = p.text;
    document.getElementById("advAttackSelect").value = p.type;
}

async function runAdversarialSimulation() {
    const msg = document.getElementById("advInputMsg").value.trim();
    const attackType = document.getElementById("advAttackSelect").value;
    const loading = document.getElementById("advLoading");
    const resultsArea = document.getElementById("advResultsArea");

    if (!msg) {
        alert("Please enter a target message or select a preset.");
        return;
    }

    loading.style.display = "block";
    resultsArea.style.display = "none";

    try {
        const res = await fetch(`${API_BASE}/api/adversarial-attack`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: msg, attackType: attackType })
        });
        const data = await res.json();
        loading.style.display = "none";
        resultsArea.style.display = "block";

        resultsArea.innerHTML = `
            <div style="margin-bottom:12px;">
                <h4 style="color:var(--text-bright); margin-bottom:4px;">Adversarial Evasion Experiment Results</h4>
                <span style="font-size:0.85rem; color:var(--text-muted);">Attack Vector: <strong>${escapeHtml(data.attackType)}</strong></span>
            </div>

            <div style="margin-bottom:14px;">
                <label style="font-size:0.8rem; font-weight:700; color:var(--text-muted); text-transform:uppercase;">Perturbed / Obfuscated Payload Injected:</label>
                <div class="adv-perturbed-box">${escapeHtml(data.perturbedMessage)}</div>
            </div>

            <div class="adv-comparison-grid">
                <!-- Naive Model Card -->
                <div class="adv-card naive">
                    <div class="adv-card-header">
                        <h4 style="color:var(--danger); font-size:0.95rem;">❌ Naive Unhardened Filter</h4>
                        <span class="adv-badge ${data.evasionSucceededOnNaive ? 'bypassed' : 'mitigated'}">
                            ${data.evasionSucceededOnNaive ? '⚠️ BYPASSED' : 'BLOCKED'}
                        </span>
                    </div>
                    <div>
                        <div style="font-size:1.8rem; font-weight:800; color:var(--danger);">${data.naiveVulnerableScore}%</div>
                        <div style="font-size:0.85rem; color:var(--text-muted);">Verdict: <strong>${escapeHtml(data.naiveVulnerableVerdict)}</strong></div>
                    </div>
                    <p style="font-size:0.8rem; color:var(--text-secondary); line-height:1.4;">
                        Standard keyword and ASCII tokenizers fail because the obfuscated characters (Cyrillic, zero-width spaces, or leet-speak) break word boundaries and string matches.
                    </p>
                </div>

                <!-- SpamGuard Defended Card -->
                <div class="adv-card defended">
                    <div class="adv-card-header">
                        <h4 style="color:var(--success); font-size:0.95rem;">🛡️ SpamGuard Capstone Engine</h4>
                        <span class="adv-badge ${data.attackMitigatedBySpamGuard ? 'mitigated' : 'bypassed'}">
                            ${data.attackMitigatedBySpamGuard ? '✅ MITIGATED & BLOCKED' : 'MISSED'}
                        </span>
                    </div>
                    <div>
                        <div style="font-size:1.8rem; font-weight:800; color:var(--success);">${data.defendedScore}%</div>
                        <div style="font-size:0.85rem; color:var(--text-muted);">Verdict: <strong>${escapeHtml(data.defendedVerdict)}</strong></div>
                    </div>
                    <p style="font-size:0.8rem; color:var(--text-secondary); line-height:1.4;">
                        ${escapeHtml(data.technicalDefenseAnalysis)}
                    </p>
                </div>
            </div>
        `;

    } catch (e) {
        loading.style.display = "none";
        resultsArea.style.display = "block";
        resultsArea.innerHTML = `<span style="color:var(--danger);">Simulation error: ${escapeHtml(e.message)}</span>`;
    }
}

// ==========================================
// CAPSTONE DEFENSE DOSSIER DOWNLOAD
// ==========================================
async function downloadDefenseDossier() {
    try {
        const res = await fetch(`${API_BASE}/api/dossier`);
        const data = await res.json();
        const blob = new Blob([data.markdownContent], { type: "text/markdown;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `SpamGuard_Capstone_Technical_Defense_Dossier_${Date.now()}.md`;
        a.click();
        URL.revokeObjectURL(url);
    } catch (e) {
        alert("Failed to download dossier: " + e.message);
    }
}

// ==========================================
// OPEN DATASET STREAM CONTROLS
// ==========================================
async function loadCorpusStream() {
    const tbody = document.getElementById("datasetTableBody");
    const statsBanner = document.getElementById("datasetStatsBanner");
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center;">Streaming samples from open-source corpus...</td></tr>`;

    try {
        // 1. Fetch stats
        const statsRes = await fetch(`${API_BASE}/api/dataset/stats`);
        const stats = await statsRes.json();
        if (statsBanner && stats) {
            statsBanner.innerHTML = `
                <div class="intel-badge"><span>Corpus:</span><strong>${escapeHtml(stats.corpusName)}</strong></div>
                <div class="intel-badge"><span>Total Records:</span><strong>${stats.totalSamples}</strong></div>
                <div class="intel-badge"><span>Spam Messages:</span><strong style="color:var(--danger);">${stats.spamCount}</strong></div>
                <div class="intel-badge"><span>Ham Messages:</span><strong style="color:var(--success);">${stats.hamCount}</strong></div>
                <div class="intel-badge"><span>Spam Class Ratio:</span><strong>${stats.spamRatioPercentage}%</strong></div>
            `;
        }

        // 2. Fetch samples
        const res = await fetch(`${API_BASE}/api/dataset/samples?limit=25`);
        const samples = await res.json();

        tbody.innerHTML = "";
        samples.forEach(s => {
            const tr = document.createElement("tr");
            const isSpam = s.label === "SPAM";
            tr.innerHTML = `
                <td><code>#${s.id}</code></td>
                <td><span class="badge ${isSpam ? 'badge-spam' : 'badge-legit'}">${escapeHtml(s.label)}</span></td>
                <td style="font-size:0.85rem; max-width:400px; word-break:break-word;">${escapeHtml(s.text)}</td>
                <td style="font-size:0.8rem; color:var(--text-muted);">${s.charCount} chars • ${s.wordCount} words</td>
                <td>
                    <button type="button" class="btn-secondary" style="padding:4px 8px; font-size:0.75rem;" onclick="testCorpusSample(${s.id})">
                        ⚡ Scan Now
                    </button>
                </td>
            `;
            tr.dataset.sampleText = s.text;
            tr.id = `corpus-row-${s.id}`;
            tbody.appendChild(tr);
        });

    } catch (e) {
        tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--danger);">Failed to load corpus stream: ${escapeHtml(e.message)}</td></tr>`;
    }
}

function testCorpusSample(sampleId) {
    const row = document.getElementById(`corpus-row-${sampleId}`);
    if (!row || !row.dataset.sampleText) return;
    const text = row.dataset.sampleText;

    // Switch to scanner tab and classify
    switchTab('scanner');
    const textarea = document.getElementById("msg");
    textarea.value = text;
    const words = text.trim().split(/\s+/).length;
    document.getElementById("charCount").textContent = `${text.length} characters • ${words} words`;
    checkSpam();
}

async function loadRandomCorpusSample() {
    try {
        const res = await fetch(`${API_BASE}/api/dataset/random`);
        const sample = await res.json();
        if (sample && sample.text) {
            switchTab('scanner');
            const textarea = document.getElementById("msg");
            textarea.value = sample.text;
            const words = sample.text.trim().split(/\s+/).length;
            document.getElementById("charCount").textContent = `${sample.text.length} characters • ${words} words`;
            checkSpam();
        }
    } catch (e) {
        alert("Failed to load random sample: " + e.message);
    }
}


// ==========================================
// UX HELPERS: CLIPBOARD, PLAYBOOK, ROC SVG, DRAG-AND-DROP & SHORTCUTS
// ==========================================
function copyToClipboard(text) {
    if (!text) return;
    navigator.clipboard.writeText(text).then(() => {
        alert("Copied to clipboard: " + text);
    }).catch(err => {
        prompt("Copy manually:", text);
    });
}

function generateSocPlaybook(data) {
    const steps = [];
    if (!data || data.prediction === "LEGITIMATE") return steps;

    if (data.score >= 55) {
        steps.push("🚨 <strong>Triage Level 1:</strong> Message classified as confirmed threat (" + data.prediction + " - Score: " + data.score + "/100). Dispatch telemetry to SOC SIEM queue.");
    }
    if (data.categoryScores && data.categoryScores.Credentials > 20) {
        steps.push("🔑 <strong>Identity Containment:</strong> Credential harvesting lure detected. Trigger immediate forced password reset and revoke active session tokens for affected target.");
    }
    if (data.iocReport && data.iocReport.defangedUrls && data.iocReport.defangedUrls.length > 0) {
        steps.push("🌐 <strong>Network Perimeter:</strong> Add defanged target domains (" + data.iocReport.extractedDomains.join(", ") + ") to DNS Sinkhole and corporate web proxy blocklists.");
    }
    if (data.brandFindings && data.brandFindings.length > 0) {
        steps.push("🎯 <strong>Brand Protection:</strong> Typosquatting impersonation attack detected. File abusive registrar abuse complaint with whois provider.");
    }
    if (data.emailHeaderReport && data.emailHeaderReport.isSenderSpoofed) {
        steps.push("📧 <strong>Mail Flow Quarantine:</strong> SPF/DKIM authentication failure. Enforce DMARC quarantine policy (<code>p=reject</code>) at mail gateway.");
    }
    steps.push("💾 <strong>Evidence Preservation:</strong> Export STIX 2.1 Threat Bundle and archive raw payload under forensic SHA-256 hash <code>" + (data.iocReport ? data.iocReport.messageSha256Hash : "") + "</code>.");
    return steps;
}

function renderRocSvg(points, optimalThreshold) {
    if (!points || points.length === 0) return "<p>No ROC points available</p>";
    const width = 500, height = 300;
    const padL = 45, padB = 40, padT = 20, padR = 20;
    const plotW = width - padL - padR;
    const plotH = height - padT - padB;

    let pathD = `M ${padL} ${padT + plotH}`;
    let circlesHtml = "";

    // Sort points by FPR ascending
    const sorted = [...points].sort((a,b) => a.falsePositiveRate - b.falsePositiveRate);
    sorted.forEach(pt => {
        const x = padL + (pt.falsePositiveRate * plotW);
        const y = padT + ((1.0 - pt.truePositiveRate) * plotH);
        pathD += ` L ${x} ${y}`;

        const isOpt = pt.threshold === optimalThreshold;
        circlesHtml += `
            <circle cx="${x}" cy="${y}" r="${isOpt ? 6 : 4}" fill="${isOpt ? '#10b981' : '#6366f1'}" stroke="#ffffff" stroke-width="1.5">
                <title>Threshold: ${pt.threshold} | FPR: ${pt.falsePositiveRate} | TPR: ${pt.truePositiveRate} | Youden: ${pt.youdenIndex}</title>
            </circle>
            <text x="${x + 6}" y="${y - 4}" font-size="9" fill="${isOpt ? '#10b981' : '#94a3b8'}" font-weight="${isOpt ? 'bold' : 'normal'}">τ=${pt.threshold}</text>
        `;
    });

    return `
        <svg viewBox="0 0 ${width} ${height}" style="width:100%; height:auto; overflow:visible; font-family:var(--font-mono);">
            <!-- Background grid -->
            <line x1="${padL}" y1="${padT}" x2="${padL + plotW}" y2="${padT}" stroke="#334155" stroke-dasharray="3,3"/>
            <line x1="${padL}" y1="${padT + plotH/2}" x2="${padL + plotW}" y2="${padT + plotH/2}" stroke="#334155" stroke-dasharray="3,3"/>
            <line x1="${padL + plotW/2}" y1="${padT}" x2="${padL + plotW/2}" y2="${padT + plotH}" stroke="#334155" stroke-dasharray="3,3"/>
            
            <!-- Diagonal Reference (Random Classifier) -->
            <line x1="${padL}" y1="${padT + plotH}" x2="${padL + plotW}" y2="${padT}" stroke="#ef4444" stroke-dasharray="4,4" stroke-width="1.5"/>

            <!-- Axes -->
            <line x1="${padL}" y1="${padT}" x2="${padL}" y2="${padT + plotH}" stroke="#94a3b8" stroke-width="2"/>
            <line x1="${padL}" y1="${padT + plotH}" x2="${padL + plotW}" y2="${padT + plotH}" stroke="#94a3b8" stroke-width="2"/>

            <!-- Labels -->
            <text x="${padL}" y="${padT + plotH + 28}" font-size="10" fill="#94a3b8">0.0 (FPR)</text>
            <text x="${padL + plotW - 20}" y="${padT + plotH + 28}" font-size="10" fill="#94a3b8">1.0</text>
            <text x="${padL - 35}" y="${padT + plotH}" font-size="10" fill="#94a3b8">0.0</text>
            <text x="${padL - 35}" y="${padT + 10}" font-size="10" fill="#94a3b8">1.0 (TPR)</text>

            <!-- ROC Curve Line -->
            <path d="${pathD}" fill="none" stroke="#6366f1" stroke-width="2.5" />
            ${circlesHtml}
        </svg>
    `;
}

// Drag & Drop for QR Quishing
function handleQrFileUpload(event) {
    const file = event.target.files[0];
    if (!file) return;
    processQrFile(file);
}

function processQrFile(file) {
    const reader = new FileReader();
    reader.onload = async function(e) {
        const base64 = e.target.result;
        try {
            const res = await fetch(`${API_BASE}/api/scan-qr`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ imageBase64: base64 })
            });
            const data = await res.json();
            if (data.qrFound) {
                switchTab('scanner');
                document.getElementById("msg").value = data.decodedText;
                alert("QR Code Decoded: " + data.decodedText + "\nInitiating threat scan...");
                checkSpam();
            } else {
                alert("QR Scan Alert: " + (data.error || "No readable QR code found in uploaded image."));
            }
        } catch (err) {
            alert("Quishing triage error: " + err.message);
        }
    };
    reader.readAsDataURL(file);
}

// Global Keyboard Shortcuts (Ctrl+Enter to Scan, Esc to Clear, Numbers 1-7 for Tabs)
document.addEventListener("keydown", function(e) {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        checkSpam();
    } else if (e.key === "Escape") {
        clearAll();
    } else if (e.altKey && e.key >= "1" && e.key <= "7") {
        const tabs = ['scanner', 'benchmark', 'dataset-tab', 'adversarial', 'email-headers', 'batch', 'telemetry'];
        const idx = parseInt(e.key) - 1;
        if (tabs[idx]) switchTab(tabs[idx]);
    }
});
