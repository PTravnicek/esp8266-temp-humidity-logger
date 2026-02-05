// Global variables
let tempChart, humChart;
let deviceConfig = {};
let autoRefreshInterval = null;
let statusRefreshInterval = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing FireBeetle 2 SHT85 Logger...');
    initializeCharts();
    loadConfig();
    loadStorageStatus();
    checkTimeStatus();
    
    // Set default time range and auto-load data
    setQuickRange(1, true); // Last 24 hours (silent)
    
    // Start live status updates (every 5 seconds)
    updateLiveStatus();
    statusRefreshInterval = setInterval(function() {
        updateLiveStatus();
    }, 5000);
    console.log('Live status updates started (5s interval)');
    
    // Start auto-refresh for charts (every 30 seconds)
    startAutoRefresh(30);
    console.log('Auto-refresh started (30s interval)');
});

// Live status update
async function updateLiveStatus() {
    try {
        const response = await fetch('/api/status');
        if (response.ok) {
            const data = await response.json();
            
            // Update live readings (handle no-sensor mode)
            const liveEl = document.getElementById('liveStatus');
            if (liveEl) {
                const sensorOk = data.sensor && data.sensor.connected !== false &&
                    data.sensor.temperature != null && data.sensor.humidity != null &&
                    typeof data.sensor.temperature === 'number' && typeof data.sensor.humidity === 'number';
                if (sensorOk) {
                    const temp = data.sensor.temperature.toFixed(1);
                    const hum = data.sensor.humidity.toFixed(1);
                    const heaterOn = data.heating && data.heating.on === true;
                    liveEl.innerHTML = `<strong>${temp}°C</strong> | <strong>${hum}%RH</strong>${heaterOn ? ' <span class="heater-indicator">Heater on</span>' : ''}`;
                    liveEl.className = 'status-badge status-ok';
                } else {
                    liveEl.textContent = 'Sensor not connected';
                    liveEl.className = 'status-badge status-warning';
                }
            }
            
            // Update sample info
            const sampleEl = document.getElementById('sampleStatus');
            if (sampleEl && data.config.sample_period_s) {
                const interval = data.config.sample_period_s;
                let intervalText;
                if (interval < 60) {
                    intervalText = `${interval}s`;
                } else if (interval < 3600) {
                    intervalText = `${Math.round(interval / 60)}m`;
                } else {
                    intervalText = `${Math.round(interval / 3600)}h`;
                }
                sampleEl.textContent = `Interval: ${intervalText}`;
            }
            
            // Update time display
            const timeEl = document.getElementById('timeStatus');
            if (timeEl && data.time.set) {
                // Convert UTC to local time
                const deviceTime = new Date(data.time.iso);
                const localTime = deviceTime.toLocaleTimeString('cs-CZ', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
                timeEl.textContent = localTime;
                timeEl.className = 'status-badge status-ok';
            }
        }
    } catch (error) {
        console.error('Failed to update live status:', error);
        const liveEl = document.getElementById('liveStatus');
        if (liveEl) {
            liveEl.textContent = 'Offline';
            liveEl.className = 'status-badge status-error';
        }
    }
}

// Auto-refresh control
function startAutoRefresh(seconds) {
    stopAutoRefresh();
    if (seconds > 0) {
        autoRefreshInterval = setInterval(function() {
            console.log('Auto-refreshing data...');
            // Update time range to include new data
            document.getElementById('toDate').value = formatDateTimeLocal(new Date());
            loadData(true); // silent refresh
        }, seconds * 1000);
        
        const btn = document.getElementById('autoRefreshBtn');
        if (btn) {
            btn.textContent = `Auto: ${seconds}s`;
            btn.classList.add('btn-active');
        }
        console.log('Auto-refresh enabled: ' + seconds + 's');
    }
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
        console.log('Auto-refresh disabled');
    }
    const btn = document.getElementById('autoRefreshBtn');
    if (btn) {
        btn.textContent = 'Auto: Off';
        btn.classList.remove('btn-active');
    }
}

function toggleAutoRefresh() {
    if (autoRefreshInterval) {
        stopAutoRefresh();
    } else {
        startAutoRefresh(30);
    }
}

// Initialize ApexCharts with 8-bit pixel art theme
function initializeCharts() {
    const tempOptions = {
        series: [{
            name: 'Temperature',
            data: []
        }],
        chart: {
            type: 'line',
            height: 280,
            background: '#fff',
            foreColor: '#000',
            fontFamily: 'ModernDOS, Courier New, monospace',
            zoom: {
                enabled: true,
                type: 'x'
            },
            toolbar: {
                show: true,
                tools: {
                    download: false
                }
            },
            animations: {
                enabled: false
            },
            events: {
                zoomed: function(chartContext, { xaxis }) {
                    syncCharts(xaxis);
                },
                scrolled: function(chartContext, { xaxis }) {
                    syncCharts(xaxis);
                }
            }
        },
        dataLabels: {
            enabled: false
        },
        stroke: {
            curve: 'stepline',
            width: 2
        },
        xaxis: {
            type: 'datetime',
            labels: {
                datetimeUTC: false,
                style: {
                    colors: '#000',
                    fontFamily: 'ModernDOS, monospace',
                    fontSize: '14px'
                }
            },
            axisBorder: {
                color: '#000',
                strokeWidth: 3
            },
            axisTicks: {
                color: '#000'
            }
        },
        yaxis: {
            labels: {
                formatter: function(val) {
                    return val.toFixed(1) + '°';
                },
                style: {
                    colors: '#000',
                    fontFamily: 'ModernDOS, monospace',
                    fontSize: '14px'
                }
            }
        },
        tooltip: {
            x: {
                format: 'dd MMM yyyy HH:mm:ss'
            },
            y: {
                formatter: function(val) {
                    return val.toFixed(2) + ' °C';
                }
            },
            theme: 'light',
            style: {
                fontFamily: 'ModernDOS, monospace',
                fontSize: '14px'
            }
        },
        colors: ['#000'],
        grid: {
            borderColor: '#ccc',
            strokeDashArray: 0
        },
        markers: {
            size: 5,
            colors: ['#000'],
            strokeWidth: 0,
            shape: 'square'
        }
    };

    const humOptions = {
        series: [{
            name: 'Humidity',
            data: []
        }],
        chart: {
            type: 'line',
            height: 280,
            background: '#fff',
            foreColor: '#000',
            fontFamily: 'ModernDOS, Courier New, monospace',
            zoom: {
                enabled: true,
                type: 'x'
            },
            toolbar: {
                show: true,
                tools: {
                    download: false
                }
            },
            animations: {
                enabled: false
            },
            events: {
                zoomed: function(chartContext, { xaxis }) {
                    syncCharts(xaxis);
                },
                scrolled: function(chartContext, { xaxis }) {
                    syncCharts(xaxis);
                }
            }
        },
        dataLabels: {
            enabled: false
        },
        stroke: {
            curve: 'stepline',
            width: 2
        },
        xaxis: {
            type: 'datetime',
            labels: {
                datetimeUTC: false,
                style: {
                    colors: '#000',
                    fontFamily: 'ModernDOS, monospace',
                    fontSize: '14px'
                }
            },
            axisBorder: {
                color: '#000',
                strokeWidth: 3
            },
            axisTicks: {
                color: '#000'
            }
        },
        yaxis: {
            min: 0,
            max: 100,
            labels: {
                formatter: function(val) {
                    return val.toFixed(0) + '%';
                },
                style: {
                    colors: '#000',
                    fontFamily: 'ModernDOS, monospace',
                    fontSize: '14px'
                }
            }
        },
        tooltip: {
            x: {
                format: 'dd MMM yyyy HH:mm:ss'
            },
            y: {
                formatter: function(val) {
                    return val.toFixed(2) + ' %RH';
                }
            },
            theme: 'light',
            style: {
                fontFamily: 'ModernDOS, monospace',
                fontSize: '14px'
            }
        },
        colors: ['#000'],
        grid: {
            borderColor: '#ccc',
            strokeDashArray: 0
        },
        markers: {
            size: 5,
            colors: ['#000'],
            strokeWidth: 0,
            shape: 'square'
        }
    };

    tempChart = new ApexCharts(document.querySelector('#tempChart'), tempOptions);
    humChart = new ApexCharts(document.querySelector('#humChart'), humOptions);
    
    tempChart.render();
    humChart.render();
}

// Sync charts when one is zoomed/panned
function syncCharts(xaxis) {
    if (xaxis && xaxis.min && xaxis.max) {
        if (tempChart && humChart) {
            const activeChart = document.activeElement.closest('.apexcharts-canvas') ? 
                (document.querySelector('#tempChart .apexcharts-canvas').contains(document.activeElement) ? tempChart : humChart) :
                tempChart;
            
            if (activeChart === tempChart) {
                humChart.zoomX(xaxis.min, xaxis.max);
            } else {
                tempChart.zoomX(xaxis.min, xaxis.max);
            }
        }
    }
}

// Load configuration
async function loadConfig() {
    try {
        const response = await fetch('/api/config');
        if (response.ok) {
            deviceConfig = await response.json();
            document.getElementById('deviceId').textContent = deviceConfig.device_id || 'ESP8266 Logger';
            updateSettingsForm();
        }
    } catch (error) {
        console.error('Failed to load config:', error);
    }
}

// Update settings form with current values
function updateSettingsForm() {
    if (!deviceConfig.sample_period_s) return;
    
    const period = deviceConfig.sample_period_s;
    let value, unit;
    
    if (period < 3600) {
        if (period >= 60 && period % 60 === 0) {
            value = period / 60;
            unit = 'minutes';
        } else {
        value = period;
        unit = 'seconds';
        }
    } else if (period < 86400) {
        value = period / 3600;
        unit = 'hours';
    } else {
        value = period / 86400;
        unit = 'days';
    }
    
    document.getElementById('intervalValue').value = value;
    document.getElementById('intervalUnit').value = unit;
    updateIntervalConstraints();
    const heatingEl = document.getElementById('heatingMode');
    if (heatingEl) heatingEl.value = deviceConfig.heating_mode || 'off';
}

function updateIntervalConstraints() {
    const valueInput = document.getElementById('intervalValue');
    const unitSelect = document.getElementById('intervalUnit');
    if (!valueInput || !unitSelect) return;

    const unit = unitSelect.value;
    valueInput.min = unit === 'seconds' ? 10 : 1;
}

// Load storage status
async function loadStorageStatus() {
    try {
        const response = await fetch('/api/storage');
        if (response.ok) {
            const data = await response.json();
            const lfs = data.lfs;
            const sd = data.sd;

            let statusText = `LFS: ${formatBytes(lfs.free)} free`;
            if (sd.present) {
                statusText += ` | SD: OK`;
            }
            
            document.getElementById('storageStatus').textContent = statusText;

            const capacityEl = document.getElementById('capacityStatus');
        if (capacityEl) {
            if (data.retention) {
                const estSamples = Number.isFinite(data.retention.est_samples) ? data.retention.est_samples : 0;
                const estDuration = Number.isFinite(data.retention.est_duration_s) ? data.retention.est_duration_s : 0;
                capacityEl.textContent = `Capacity: ${formatCount(estSamples)} samples / ${formatDuration(estDuration)}`;
            } else {
                capacityEl.textContent = 'Capacity: unavailable';
            }
        }
            
            if (data.write_errors > 0) {
                document.getElementById('storageStatus').classList.add('status-error');
                document.getElementById('storageStatus').textContent += ` (${data.write_errors} errors)`;
            }
        }
    } catch (error) {
        console.error('Failed to load storage status:', error);
    }
}

// Format bytes
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function formatCount(count) {
    if (count >= 1000000) return (count / 1000000).toFixed(1) + 'M';
    if (count >= 1000) return (count / 1000).toFixed(1) + 'k';
    return String(count);
}

function formatDuration(seconds) {
    if (!seconds || seconds <= 0) return '0';
    const days = seconds / 86400;
    if (days >= 1) return days.toFixed(1) + ' days';
    const hours = seconds / 3600;
    if (hours >= 1) return hours.toFixed(1) + ' hours';
    const minutes = Math.max(1, Math.round(seconds / 60));
    return minutes + ' min';
}

async function pruneLfs() {
    const input = document.getElementById('pruneDays');
    const btn = document.getElementById('pruneBtn');
    if (!input || !btn) return;

    const days = parseInt(input.value, 10);
    if (!Number.isFinite(days) || days <= 0) {
        alert('Please enter a valid number of days');
        return;
    }

    if (!confirm(`Delete LittleFS data older than ${days} days?`)) {
        return;
    }

    btn.disabled = true;
    const oldLabel = btn.textContent;
    btn.textContent = 'Pruning...';

    try {
        const response = await fetch(`/api/prune?days=${encodeURIComponent(days)}`);
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Prune failed');
        }

        alert(`Deleted ${data.deleted_samples} samples, freed ${formatBytes(data.freed_bytes)}`);
        loadStorageStatus();
        loadData(true);
    } catch (error) {
        console.error('Failed to prune LFS:', error);
        alert('Failed to prune: ' + error.message);
    } finally {
        btn.disabled = false;
        btn.textContent = oldLabel;
    }
}

// Check time status
async function checkTimeStatus() {
    try {
        const response = await fetch('/api/time');
        if (response.ok) {
            const data = await response.json();
            const timeStatus = document.getElementById('timeStatus');
            
            if (data.time_set) {
                // Time will be updated by updateLiveStatus
                timeStatus.className = 'status-badge status-ok';
                document.getElementById('timeModal').classList.remove('show');
            } else {
                timeStatus.textContent = 'Time: Not set!';
                timeStatus.className = 'status-badge status-warning';
                document.getElementById('timeModal').classList.add('show');
            }
        }
    } catch (error) {
        console.error('Failed to check time status:', error);
    }
}

// Set device time from browser
async function setDeviceTime() {
    const errorDiv = document.getElementById('timeError');
    errorDiv.classList.remove('show');
    
    try {
        const epoch = Math.floor(Date.now() / 1000);
        const response = await fetch('/api/time', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ epoch: epoch })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            document.getElementById('timeModal').classList.remove('show');
            checkTimeStatus();
        } else {
            errorDiv.textContent = data.error || 'Failed to set time';
            errorDiv.classList.add('show');
        }
    } catch (error) {
        errorDiv.textContent = 'Network error';
        errorDiv.classList.add('show');
    }
}

// Set quick time range
function setQuickRange(days, silent = false) {
    const to = new Date();
    const from = new Date();
    from.setDate(from.getDate() - days);

    document.getElementById('fromDate').value = formatDateTimeLocal(from);
    document.getElementById('toDate').value = formatDateTimeLocal(to);

    // Load immediately after changing the range for faster feedback
    loadData(silent);
}

// Format date for datetime-local input
function formatDateTimeLocal(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    return `${year}-${month}-${day}T${hours}:${minutes}`;
}

// Format date to ISO8601
function formatISO8601(date) {
    return date.toISOString().split('.')[0] + 'Z';
}

// Load data (silent = no alerts)
async function loadData(silent = false) {
    const fromInput = document.getElementById('fromDate').value;
    const toInput = document.getElementById('toDate').value;
    
    if (!fromInput || !toInput) {
        if (!silent) alert('Please select both from and to dates');
        return;
    }
    
    const from = new Date(fromInput);
    const to = new Date(toInput);
    
    if (from >= to) {
        if (!silent) alert('From date must be before to date');
        return;
    }
    
    try {
        const fromISO = formatISO8601(from);
        const toISO = formatISO8601(to);
        
        const response = await fetch(`/api/data?from=${encodeURIComponent(fromISO)}&to=${encodeURIComponent(toISO)}`);
        
        if (!response.ok) {
            throw new Error('Failed to load data');
        }
        
        const data = await response.json();
        
        if (data.warning && !silent) {
            alert(data.warning);
        }
        
        // Convert to ApexCharts format
        const tempData = [];
        const humData = [];
        
        if (data.points && Array.isArray(data.points)) {
            for (let i = 0; i < data.points.length; i++) {
                const point = data.points[i];
                if (!point || point.length < 3) continue;
                const timestamp = new Date(point[0]).getTime();
                tempData.push([timestamp, point[1]]);
                humData.push([timestamp, point[2]]);
            }
        } else if (data.ts && data.temp && data.hum) {
            for (let i = 0; i < data.ts.length; i++) {
                const timestamp = new Date(data.ts[i]).getTime();
                tempData.push([timestamp, data.temp[i]]);
                humData.push([timestamp, data.hum[i]]);
            }
        }
        let firstTs = null;
        let lastTs = null;
        if (tempData.length > 0) {
            firstTs = new Date(tempData[0][0]).toISOString();
            lastTs = new Date(tempData[tempData.length - 1][0]).toISOString();
        }
        
        // Update charts
        tempChart.updateSeries([{
            name: 'Temperature',
            data: tempData
        }]);
        
        humChart.updateSeries([{
            name: 'Humidity',
            data: humData
        }]);
        
        // Update data count
        const countEl = document.getElementById('dataCount');
        if (countEl) {
            const count = Number.isFinite(data.count) ? data.count : tempData.length;
            countEl.textContent = `${count} points`;
        }
        
    } catch (error) {
        console.error('Failed to load data:', error);
        if (!silent) alert('Failed to load data: ' + error.message);
    }
}

// Download CSV
async function downloadCSV() {
    const fromInput = document.getElementById('fromDate').value;
    const toInput = document.getElementById('toDate').value;
    
    if (!fromInput || !toInput) {
        alert('Please select both from and to dates');
        return;
    }
    
    const from = new Date(fromInput);
    const to = new Date(toInput);
    
    if (from >= to) {
        alert('From date must be before to date');
        return;
    }
    
    try {
        const fromISO = formatISO8601(from);
        const toISO = formatISO8601(to);
        
        const url = `/api/download?from=${encodeURIComponent(fromISO)}&to=${encodeURIComponent(toISO)}&format=csv&store=auto`;
        window.location.href = url;
    } catch (error) {
        console.error('Failed to download CSV:', error);
        alert('Failed to download CSV: ' + error.message);
    }
}

// Settings modal
function openSettings() {
    updateSettingsForm();
    document.getElementById('settingsModal').classList.add('show');
}

function closeSettings() {
    document.getElementById('settingsModal').classList.remove('show');
    document.getElementById('settingsError').classList.remove('show');
}

async function saveSettings(event) {
    event.preventDefault();
    const errorDiv = document.getElementById('settingsError');
    errorDiv.classList.remove('show');
    
    const value = parseFloat(document.getElementById('intervalValue').value);
    const unit = document.getElementById('intervalUnit').value;
    
    if (isNaN(value) || value <= 0) {
        errorDiv.textContent = 'Invalid interval value';
        errorDiv.classList.add('show');
        return;
    }

    if (unit === 'seconds' && value < 10) {
        errorDiv.textContent = 'Seconds must be at least 10';
        errorDiv.classList.add('show');
        return;
    }
    
    let periodSeconds;
    if (unit === 'seconds') {
        periodSeconds = Math.round(value);
    } else if (unit === 'minutes') {
        periodSeconds = Math.round(value * 60);
    } else if (unit === 'hours') {
        periodSeconds = Math.round(value * 3600);
    } else if (unit === 'days') {
        periodSeconds = Math.round(value * 86400);
    }
    
    if (periodSeconds < 10 || periodSeconds > 604800) {
        errorDiv.textContent = 'Interval must be between 10 seconds and 7 days';
        errorDiv.classList.add('show');
        return;
    }
    
    const heatingModeEl = document.getElementById('heatingMode');
    const heatingMode = heatingModeEl && ['off', '10s_5min', '1min_1hr', '1min_1day'].includes(heatingModeEl.value)
        ? heatingModeEl.value : 'off';
    
    try {
        const response = await fetch('/api/config', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ sample_period_s: periodSeconds, heating_mode: heatingMode })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            closeSettings();
            loadConfig();
            updateLiveStatus();
            loadStorageStatus();
        } else {
            errorDiv.textContent = data.error || 'Failed to save settings';
            errorDiv.classList.add('show');
        }
    } catch (error) {
        errorDiv.textContent = 'Network error';
        errorDiv.classList.add('show');
    }
}

// Test SD card
async function testSD() {
    try {
        const response = await fetch('/api/test-sd');
        const data = await response.json();
        
        if (data.success) {
            alert('✓ SD Card Test Passed!\n\n' + data.message);
        } else {
            alert('✗ SD Card Test Failed!\n\n' + data.error);
        }
    } catch (error) {
        alert('✗ SD Card Test Failed!\n\nNetwork error: ' + error.message);
    }
}
