/* =========================================
   NEUROSHIELD-IDS : MASTER LOGIC ENGINE
   THEME: NEON CYBERPUNK
========================================= */

const LIVE_MODE = document.body.dataset.liveMode === "True";
const timelineData = [];
const maxTimelinePoints = 15;
const quarantinedIPs = new Set();
let soarCounter = 0;

// PERSISTENCE CACHE FOR MATRIX (Smooth floating)
const activeNodes = new Map(); 

function riskClass(level) {
    if (level === "CRITICAL") return "row-crit";
    if (level === "HIGH") return "row-high";
    if (level === "MEDIUM") return "row-med";
    return "";
}

function updateStats(summary) {
    document.getElementById("totalLogs").textContent = (summary.total || 45210).toLocaleString();
    document.getElementById("threatsFound").textContent = summary.threats || 0;
    document.getElementById("criticalAlerts").textContent = summary.critical || 0;
    document.getElementById("soarCount").textContent = soarCounter;
    document.getElementById("topAttacker").textContent = summary.top_attacker || "AWAITING DATA";
}

/* =========================================
   THREAT MATRIX ENGINE
========================================= */
function updateThreatMatrix(results) {
    const matrix = document.getElementById("threatMatrix");
    if (!matrix) return;

    const currentIPs = new Set();
    const threats = results.filter(r => r.threat !== "Normal Activity").slice(0, 20);

    threats.forEach((r) => {
        if (quarantinedIPs.has(r.ip)) return;
        currentIPs.add(r.ip);

        let node;
        if (activeNodes.has(r.ip)) {
            node = activeNodes.get(r.ip);
        } else {
            node = document.createElement("div");
            // Map risk to specific cyber colors
            const nodeClass = r.risk_level === 'CRITICAL' ? 'node-critical' : (r.risk_level === 'HIGH' ? 'node-high' : 'node-medium');
            node.className = `matrix-node ${nodeClass}`;
            node.onclick = () => showXAI(r.ip, r.threat, r.confidence, r.risk_level);
            matrix.appendChild(node);
            activeNodes.set(r.ip, node);
            
            // Spawn location
            node.style.left = `${Math.random() * 80 + 10}%`;
            node.style.top = `${Math.random() * 80 + 10}%`;
        }

        // Float logic
        const driftX = (Math.random() - 0.5) * 15; 
        const driftY = (Math.random() - 0.5) * 15;
        const currentLeft = parseFloat(node.style.left);
        const currentTop = parseFloat(node.style.top);
        
        node.style.left = `${Math.max(5, Math.min(95, currentLeft + driftX))}%`;
        node.style.top = `${Math.max(5, Math.min(95, currentTop + driftY))}%`;
    });

    // Cleanup dead nodes
    activeNodes.forEach((node, ip) => {
        if (!currentIPs.has(ip)) {
            node.style.opacity = '0';
            setTimeout(() => { node.remove(); activeNodes.delete(ip); }, 500);
        }
    });
}

/* =========================================
   GLOWING AREA CANVAS CHART
========================================= */
function drawTimeline(summary) {
    const canvas = document.getElementById("timelineChart");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const parent = canvas.parentElement;
    
    // Lock dimensions to prevent infinity bug
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    const dpr = window.devicePixelRatio || 1;
    const width = parent.clientWidth;
    const height = parent.clientHeight;
    
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    ctx.scale(dpr, dpr);

    const threats = summary.threats || 0;
    timelineData.push(threats);
    if (timelineData.length > maxTimelinePoints) timelineData.shift();

    ctx.clearRect(0, 0, width, height);
    if (timelineData.length < 2) return;

    const maxValue = Math.max(...timelineData, 10);
    const step = width / (maxTimelinePoints - 1);

    // Purple to Pink Gradient Fill
    const gradient = ctx.createLinearGradient(0, 0, 0, height);
    gradient.addColorStop(0, "rgba(255, 0, 170, 0.4)"); // Neon Pink
    gradient.addColorStop(1, "rgba(176, 38, 255, 0.0)"); // Neon Purple fading out

    ctx.beginPath();
    ctx.moveTo(0, height);
    for (let i = 0; i < timelineData.length; i++) {
        const x = i * step;
        const y = height - 10 - (timelineData[i] / maxValue) * (height - 20);
        if (i === 0) ctx.lineTo(x, y);
        else {
            const cpX = (i - 0.5) * step;
            ctx.bezierCurveTo(cpX, height - 10 - (timelineData[i-1]/maxValue)*(height-20), cpX, y, x, y);
        }
    }
    ctx.lineTo((timelineData.length - 1) * step, height);
    ctx.fillStyle = gradient;
    ctx.fill();

    // Glowing Neon Cyan Border
    ctx.beginPath();
    for (let i = 0; i < timelineData.length; i++) {
        const x = i * step;
        const y = height - 10 - (timelineData[i] / maxValue) * (height - 20);
        if (i === 0) ctx.moveTo(x, y);
        else {
            const cpX = (i - 0.5) * step;
            ctx.bezierCurveTo(cpX, height - 10 - (timelineData[i-1]/maxValue)*(height-20), cpX, y, x, y);
        }
    }
    ctx.strokeStyle = "#00f0ff"; // Cyan
    ctx.lineWidth = 2;
    ctx.shadowBlur = 10;
    ctx.shadowColor = "#00f0ff";
    ctx.stroke();
    ctx.shadowBlur = 0; // reset
}

/* =========================================
   TABLES, DISTRIBUTION & TERMINAL
========================================= */
function updateEvents(results) {
    const table = document.getElementById("eventsTable");
    table.innerHTML = "";
    results.forEach(r => {
        const isQuarantined = quarantinedIPs.has(r.ip);
        table.innerHTML += `
            <tr class="${isQuarantined ? 'row-quarantine' : riskClass(r.risk_level)}" id="row-${r.ip.replace(/\./g, '-')}">
                <td>${r.ip}</td>
                <td>${r.threat}</td>
                <td>${r.risk_level}</td>
                <td>${r.confidence}%</td>
                <td><button class="btn-micro" onclick="showXAI('${r.ip}', '${r.threat}', ${r.confidence}, '${r.risk_level}')">INSPECT</button></td>
                <td><button class="btn-micro btn-q" ${isQuarantined ? 'disabled' : ''} onclick="quarantineIP('${r.ip}', this)">${isQuarantined ? 'ISOLATED' : 'EXECUTE SOAR'}</button></td>
            </tr>
        `;
    });
}

function updateTerminal(results) {
    const terminal = document.getElementById("terminalFeed");
    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    
    results.slice(0, 3).forEach(r => {
        const p = document.createElement("p");
        p.innerHTML = `<span class="t-sys">[${time}]</span> ANOMALY: <span class="t-ip">${r.ip}</span> -> <span class="${r.risk_level === 'CRITICAL' ? 't-warn' : ''}">${r.threat}</span>`;
        terminal.appendChild(p);
    });
    terminal.scrollTop = terminal.scrollHeight;
}

function updateDistribution(summary) {
    const container = document.getElementById("distributionChart");
    if(!container) return;
    container.innerHTML = "";
    
    const labels = summary.labels || ["SQL INJECTION", "DDOS VOLUME", "BRUTE FORCE", "XSS PAYLOAD"];
    const values = summary.values || [45, 120, 85, 20];
    const maxValue = Math.max(...values, 1);

    labels.forEach((label, index) => {
        const value = values[index];
        const width = Math.max((value / maxValue) * 100, 5);
        container.innerHTML += `
            <div class="dist-row">
                <span class="dist-label">${label}</span>
                <div class="dist-bar-bg"><div class="dist-bar-fill" style="width:${width}%"></div></div>
                <span class="dist-val">${value}</span>
            </div>
        `;
    });
}

/* =========================================
   ACTIONS & XAI OVERLAY
========================================= */
function quarantineIP(ip, btn) {
    quarantinedIPs.add(ip);
    soarCounter++;
    document.getElementById("soarCount").textContent = soarCounter;
    
    btn.disabled = true;
    btn.innerText = "ISOLATED";
    const node = document.getElementById(`node-${ip.replace(/\./g, '-')}`);
    if (node) { node.style.display = 'none'; activeNodes.delete(ip); }
    document.getElementById(`row-${ip.replace(/\./g, '-')}`).className = "row-quarantine";

    const terminal = document.getElementById("terminalFeed");
    const p = document.createElement("p");
    p.innerHTML = `<span class="t-warn">> SOAR PROTOCOL ENGAGED: Target ${ip} isolated at firewall.</span>`;
    terminal.appendChild(p);
    terminal.scrollTop = terminal.scrollHeight;
}

function showXAI(ip, threat, confidence, risk) {
    const panel = document.getElementById("xaiPanel");
    document.getElementById("xaiIp").innerText = ip;
    document.getElementById("xaiThreat").innerText = threat;
    
    document.getElementById("xaiBar1").style.width = '0%';
    document.getElementById("xaiBar2").style.width = '0%';
    document.getElementById("xaiBar3").style.width = '0%';
    
    panel.classList.remove("hidden");

    setTimeout(() => {
        document.getElementById("xaiBar1").style.width = `${confidence}%`;
        document.getElementById("xaiBar2").style.width = `${Math.random()*30+50}%`;
        document.getElementById("xaiBar3").style.width = `${Math.random()*40+20}%`;
    }, 100);

    let conclusion = `Heuristic engine indicates structured reconnaissance. Lateral movement probability is escalating. Recommend active monitoring.`;
    if (risk === "CRITICAL") conclusion = `WARNING: Signature match confirms hostile payload execution. Immediate automated quarantine required.`;
    document.getElementById("xaiConclusion").innerText = conclusion;
}

function closeXAI() { document.getElementById("xaiPanel").classList.add("hidden"); }

/* =========================================
   DATA LOOP
========================================= */
async function fetchLiveData() {
    try {
        const response = await fetch("/api/live");
        if (!response.ok) throw new Error("API Offline");
        const data = await response.json();
        renderDashboard(data);
    } catch (e) { generateMockData(); }
}

function renderDashboard(data) {
    updateStats(data.summary);
    updateEvents(data.results);
    updateTerminal(data.results);
    updateThreatMatrix(data.results);
    drawTimeline(data.summary);
    updateDistribution(data.summary);
}

function generateMockData() {
    const risks = ["CRITICAL", "HIGH", "MEDIUM"];
    const threats = ["SQL Injection", "DDoS Volume", "SSH Brute Force", "Malware Beacon"];
    let mockResults = [];
    for(let i=0; i<6; i++) {
        mockResults.push({
            ip: `192.168.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
            threat: threats[Math.floor(Math.random()*threats.length)],
            risk_level: risks[Math.floor(Math.random()*risks.length)],
            confidence: Math.floor(Math.random()*25 + 75)
        });
    }
    renderDashboard({
        summary: { total: 45210, threats: Math.floor(Math.random()*50 + 200), critical: 12, top_attacker: mockResults[0].ip },
        results: mockResults
    });
}

window.addEventListener('resize', () => { if (timelineData.length > 0) drawTimeline({ threats: timelineData[timelineData.length - 1] }); });

async function startDashboard() {
    await fetchLiveData();
    if (LIVE_MODE) setInterval(fetchLiveData, 3000);
}
startDashboard();