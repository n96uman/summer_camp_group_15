from flask import Flask, render_template_string, request, redirect, url_for
import requests

app = Flask(__name__)
data={"key":"status","value":"stoped"}

temp1="""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="../static/css/style.css">
</head>
<body>
    
{% extends "base.html" %}

{% block title %}Security Alerts - IDS Dashboard{% endblock %}

{% block content %}
<!-- Navigation -->
<nav class="navigation">
    <div class="nav-container">
        <div class="nav-brand">IDS Dashboard</div>
        <ul class="nav-links">
            <li>
        <form method="GET" action="/">
            <button type="submit" class="nav-link">Home</button>
        </form>
    </li>
    <li>
        <form method="GET" action="/host_ids">
            <button type="submit" class="nav-link">HOST</button>
        </form>
    </li>
            <li><a href="export.html" class="nav-link">Export</a></li>
        </ul>
    </div>
</nav>

<main class="container mx-auto px-4 py-8 space-y-8">
    <div class="flex items-center justify-between">
        <div>
            <h1 class="text-3xl font-bold mb-2">Security Alerts</h1>
            <p class="text-muted-foreground">
                Host alerts and fail attempt logs
            </p>
        </div>
        <div class="flex items-center gap-2">
            <div id="status-indicator" class="h-3 w-3 rounded-full bg-muted"></div>
            <span id="status-text" class="text-sm font-medium">Monitoring Stopped</span>
        </div>
    </div>

        <div class="card p-4 border-destructive/20">
            <div class="flex items-center gap-3">
                <div class="p-2 bg-destructive/10 rounded">
                    <svg class="h-5 w-5 text-destructive" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"/>
                    </svg>
                </div>
                <div>
                    <p class="text-2xl font-bold" id="high-alerts-count">{{ high }}</p>
                    <p class="text-xs text-muted-foreground">High Severity</p>
                </div>
            </div>
        </div>

        <div class="card p-4 border-warning/20">
            <div class="flex items-center gap-3">
                <div class="p-2 bg-warning/10 rounded">
                    <svg class="h-5 w-5 text-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
                    </svg>
                </div>
                <div>
                    <p class="text-2xl font-bold" id="medium-alerts-count">{{ medium }}</p>
                    <p class="text-xs text-muted-foreground">Medium Severity</p>
                </div>
            </div>
        </div>

        <div class="card p-4 border-border">
            <div class="flex items-center gap-3">
                <div class="p-2 bg-primary/10 rounded">
                    <svg class="h-5 w-5 text-primary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                </div>
                <div>
                    <p class="text-2xl font-bold" id="low-alerts-count">{{ low }}</p>
                    <p class="text-xs text-muted-foreground">Low Severity</p>
                </div>
            </div>
        </div>
    </div>

    <!-- All Alerts -->
<div class="card" style="padding: 1.5rem; border: 1px solid #ccc; border-radius: 8px; background-color: #1f1f1f; color: #f0f0f0; font-family: Arial, sans-serif;">
    <h2 style="font-size: 1.25rem; font-weight: 600; margin-bottom: 1rem;">All IDS Alerts</h2>
    
    <div id="all-alerts">
        <!-- Header Row -->
        <div style="display: flex; font-weight: 600; border-bottom: 2px solid #555; padding-bottom: 0.5rem; text-transform: uppercase; font-size: 0.9rem;">
            <div style="flex: 1;">Time</div>
            <div style="flex: 1;">IP</div>
            <div style="flex: 1;">MAC</div>
            <div style="flex: 1;">Level</div>
            <div style="flex: 2;">Description</div>
        </div>

        <!-- Data Rows -->
        {% for alert in alerts %}
        <div style="display: flex; padding: 0.5rem 0; border-bottom: 1px solid #333; background-color: {% if loop.index % 2 == 0 %}#2a2a2a{% else %}#1f1f1f{% endif %}; transition: background-color 0.2s;">
            <div style="flex: 1;">{{ alert.timestamp }}</div>
            <div style="flex: 1;">{{ alert.ip }}</div>
            <div style="flex: 1;">{{ alert.mac }}</div>
            <div style="flex: 1; color: {% if alert.level == 'high' %}#ff4d4d{% elif alert.level == 'medium' %}#ffd633{% else %}#4dd0e1{% endif %}; font-weight: 600;">{{ alert.level }}</div>
            <div style="flex: 2;">{{ alert.description }}</div>
        </div>
        {% endfor %}

        {% if alerts|length == 0 %}
        <div style="text-align: center; padding: 1rem; color: #888;">
            No alerts detected.
        </div>
        {% endif %}
    </div>
</div>



    <div id="no-alerts" class="text-center py-12 hidden">
        <svg class="h-16 w-16 mx-auto mb-4 text-muted-foreground opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
        </svg>
        <p class="text-lg font-medium mb-2">No Alerts Detected</p>
        <p class="text-muted-foreground" id="no-alerts-message">
            Start the IDS to begin monitoring for security threats.
        </p>
    </div>
</main>

<script>
    // Load alerts when page loads
    document.addEventListener('DOMContentLoaded', function() {
        refreshAlerts();
    });
</script>
{% endblock %}
</body>
</html>"""

temp = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDSDocument</title>
    <link rel="stylesheet" href="static/css/style.css">
</head>
<body>
    
<!-- Navigation -->
<nav class="navigation">
    <div class="nav-container">
        <div class="nav-brand">IDS Dashboard</div>
        <ul class="nav-links">
            <li>
        <form method="GET" action="/">
            <button type="submit" class="nav-link">Home</button>
        </form>
    </li>
    <li>
        <form method="GET" action="/host_ids">
            <button type="submit" class="nav-link">HOST</button>
        </form>
    </li>
            <li><a href="" class="nav-link">Export</a></li>
        </ul>
    </div>
</nav>

<main class="container mx-auto px-4 py-8">
    <!-- Header -->
    <div class="flex items-center justify-between mb-8">
        <div>
            <h1 class="text-3xl font-bold mb-2">Security Dashboard</h1>
            <p class="text-muted-foreground">Real-time intrusion detection system monitoring</p>
        </div>
        <form method="post" action="/refresh">
            <button class="btn btn-outline" type="submit">Refresh</button>
        </form>
    </div>
    
    <div class="dashboard-grid">
        <!-- Left Column -->
        <div class="flex flex-col space-y-6">
            <!-- IDS Controls -->
            <div class="dashboard-card">
                <h3>IDS Controls</h3>
                <form method="post" action="/start_ids">
                    <button class="btn btn-primary" type="submit">Start IDS</button>
                </form>
                <form method="post" action="/stop_ids">
                    <button class="btn btn-danger" type="submit">Stop IDS</button>
                </form>
                <div class="status-indicator">
                    Status: <span id="ids-status" class="status-stopped">{{ status }}</span>
                </div>
            </div>
        </div>
    </div>
    <!-- IDS Statistics -->
            <div class="dashboard-card">
                <h3>IDS Statistics</h3>
                <div class="stats-grid">
                    <div class="stat-item">
                        <span class="stat-label">Status</span>
                        <span class="stat-value" id="stat-status">{{ status }}</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Total Alerts</span>
                        <span class="stat-value" id="stat-total">{{ total }} </span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-label">Alerts by Type</span>
                        <span class="stat-value">Traffic</span>
                    </div>
                    <div class="stat-item">
                        <a href=" " class="btn btn-outline btn-sm">Export Data</a>
                    </div>
                </div>
            </div>
            <!-- Security Overview -->
            <div class="dashboard-card">
                <h3>Security Overview</h3>
                <div id="security-status">
                    <div class="status-banner stopped mb-4 p-4 rounded-lg bg-destructive/10 border-destructive/20 text-center font-bold">
                        {{ status }}
                    </div>
                    <div class="grid grid-cols-2 gap-4">
                        <div class="stat-item">
                            <span class="stat-value" id="total-alerts"> {{ low }}</span>
                            <span class="stat-label">Total Alerts</span>
                            <span class="text-xs text-muted-foreground">From IDS monitoring</span>
                        </div>
                        <div class="stat-item border-l-4 border-destructive">
                            <span class="stat-value text-destructive" id="high-severity">{{ high }}</span>
                            <span class="stat-label">High Severity</span>
                            <span class="text-xs text-muted-foreground">Critical threats detected</span>
                        </div>
                        <div class="stat-item border-l-4 border-warning">
                            <span class="stat-value text-warning" id="medium-severity">{{ medium }}</span>
                            <span class="stat-label">Medium Severity</span>
                            <span class="text-xs text-muted-foreground">Potential threats</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">System Status</span>
                            <span class="stat-value" id="system-status">{{status}}</span>
                            <span class="text-xs text-muted-foreground">IDS monitoring</span>
                        </div>
                    </div>
                </div>
            </div>
            </dev>
            <!-- Right Column -->
        <div class="flex flex-col space-y-6">
            <!-- Alert Distribution -->
            <div class="dashboard-card">
                <h3>Alert Distribution</h3>
                <div class="chart-placeholder h-48 flex items-end justify-around p-4 bg-muted rounded-lg">
                    <div class="chart-bar bg-destructive w-8 rounded-t" style="height: 20%"></div>
                    <div class="chart-bar bg-warning w-8 rounded-t" style="height: 30%"></div>
                    <div class="chart-bar bg-primary w-8 rounded-t" style="height: 50%"></div>
                </div>
            </div>
            <!-- Recent Alerts -->
            <div class="dashboard-card">
                <h3>Recent Alerts</h3>
                <div id="all-alerts">
        <!-- Header Row -->
<div style="display: flex; font-weight: 600; border-bottom: 2px solid #555; padding: 0.5rem 0; text-transform: uppercase; font-size: 0.9rem;">
  <div style="flex: 1; text-align: left;">SRC IP</div>
  <div style="flex: 1; text-align: left;">ALERT</div>
  <div style="flex: 2; text-align: left;">DETAILS</div>
  <div style="flex: 1; text-align: center;">SEVERITY</div>
  <div style="flex: 1.5; text-align: center;">TIME</div>
</div>

<!-- Data Rows -->
{% for alert in alerts %}
<div style="display: flex; align-items: center; padding: 0.6rem 0; border-bottom: 1px solid #333; background-color: {% if loop.index is even %}#252525{% else %}#1f1f1f{% endif %}; transition: background-color 0.2s;">
  <div style="flex: 1; text-align: left;">{{ alert.src }}</div>
  <div style="flex: 1; text-align: left;">{{ alert.alart }}</div>
  <div style="flex: 2; text-align: left;">{{ alert.details }}</div>
  <div style="flex: 1; text-align: center; font-weight: 600; color:
      {% if alert.severity == 'High' %}#ff4d4d
      {% elif alert.severity == 'Medium' %}#ffd633
      {% else %}#4dd0e1{% endif %};">
    {{ alert.severity }}
  </div>
  <div style="flex: 1.5; text-align: center;">{{ alert.time }}</div>
</div>
{% endfor %}


        </div>
    </div>
</main>
</body>
</html>"""

# In-memory data storage
ids_status = "stopped"
alerts={}

@app.route("/")
def index():
    response=requests.get("http://10.46.25.40:5050/alerts")
    data=response.json()
    # Flatten nested lists if any
    flat_data = []
    for alert in data:
        if isinstance(alert, dict):
            flat_data.append(alert)
        elif isinstance(alert, list):
            flat_data.extend(alert)

    # Initialize counters
    counts = {"high": 0, "medium": 0, "low": 0}
    for alert in flat_data:
        level = alert.get("severity", "").lower()
        if level in counts:
            counts[level] += 1

    total = len(flat_data)
    return render_template_string(temp,
                                alerts=flat_data,
                                high=counts["high"],
                                medium=counts["medium"],
                                low=counts["low"],
                                total=total,
                                status=ids_status)
@app.route("/host_ids")
def host():
    global ids_status
    response = requests.get("http://10.46.25.40:5050/host_ids")
    data = response.json()

    # Flatten nested lists if any
    flat_data = []
    for alert in data:
        if isinstance(alert, dict):
            flat_data.append(alert)
        elif isinstance(alert, list):
            flat_data.extend(alert)

    # Initialize counters
    counts = {"high": 0, "medium": 0, "low": 0}
    for alert in flat_data:
        level = alert.get("level", "").lower()
        if level in counts:
            counts[level] += 1

    total = len(flat_data)
    return render_template_string(temp1,
                                alerts=flat_data,
                                high=counts["high"],
                                medium=counts["medium"],
                                low=counts["low"],
                                total=total,
                                status=ids_status)


@app.route("/start_ids", methods=["POST"])
def start_ids():
    global ids_status
    if ids_status == "stopped":
        ids_status = "running"
        data = {"key": "status", "value": ids_status}
        requests.post("http://10.46.25.40:5000/IDS_status", json=data)
        return redirect(url_for('index'))



@app.route("/stop_ids", methods=["POST"])
def stop_ids():
    global ids_status
    #if ids_status == "running":
    ids_status = "stopped"
    data = {"key": "status", "value": ids_status}
    requests.post("http://10.46.25.40:5000/IDS_status", json=data)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)