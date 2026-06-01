# =====================================================
# INCIDENT RESPONSE AI SYSTEM (FINAL ERROR-FREE VERSION)
# CO1 - CO6 FULL SYLLABUS COVERAGE
# =====================================================

import datetime
import heapq

# =====================================================
# CO1: PEAS MODEL
# =====================================================

PEAS = {
    "Performance": "Minimize downtime and impact",
    "Environment": "Enterprise IT Infrastructure",
    "Actuators": ["Restart Service", "Block IP", "Alert Admin", "Scale System"],
    "Sensors": ["Logs", "Network Alerts", "User Reports"]
}

# =====================================================
# KNOWLEDGE BASE
# =====================================================

INCIDENT_DB = {
    "database_failure": {
        "keywords": ["database down", "db not responding", "connection failed"],
        "component": "Database Server",
        "risk": 3,
        "recovery_time": "10-20 min",
        "actions": ["Restart DB service", "Check DB logs", "Verify connection pool"]
    },

    "server_overload": {
        "keywords": ["cpu high", "server slow", "system lag"],
        "component": "Application Server",
        "risk": 2,
        "recovery_time": "5-15 min",
        "actions": ["Check CPU usage", "Kill heavy process", "Scale system"]
    },

    "network_failure": {
        "keywords": ["network down", "timeout", "internet not working"],
        "component": "Network Layer",
        "risk": 2,
        "recovery_time": "5-10 min",
        "actions": ["Restart router", "Check firewall", "Run diagnostics"]
    },

    "security_breach": {
        "keywords": ["hack", "breach", "unauthorized", "attack"],
        "component": "Security System",
        "risk": 4,
        "recovery_time": "30-60 min",
        "actions": ["Block IP", "Isolate system", "Alert security team"]
    }
}

# =====================================================
# CO2: A* SEARCH (Incident Propagation Model)
# =====================================================

graph = {
    "User": [("Application", 2)],
    "Application": [("Database", 3), ("Network", 2)],
    "Database": [("Security", 2)],
    "Network": [("Security", 3)],
    "Security": []
}

heuristic = {
    "User": 4,
    "Application": 3,
    "Database": 2,
    "Network": 2,
    "Security": 0
}

def astar(start, goal):
    open_list = []
    heapq.heappush(open_list, (0, start, [start], 0))
    visited = set()

    while open_list:
        f, node, path, g = heapq.heappop(open_list)

        if node == goal:
            return path, g

        visited.add(node)

        for neighbor, cost in graph[node]:
            if neighbor not in visited:
                new_g = g + cost
                new_f = new_g + heuristic[neighbor]
                heapq.heappush(open_list, (new_f, neighbor, path + [neighbor], new_g))

    return [], 0

# =====================================================
# CO3: CSP (Analyst Assignment)
# =====================================================

domains = {
    "database_failure": ["Alice", "Bob"],
    "server_overload": ["Bob", "Charlie"],
    "network_failure": ["Alice", "Charlie"],
    "security_breach": ["Alice", "Bob", "Charlie"]
}

def assign_analysts(tasks, assignment=None):
    if assignment is None:
        assignment = {}

    if len(assignment) == len(tasks):
        return assignment

    task = next(t for t in tasks if t not in assignment)

    for analyst in domains[task]:
        if analyst not in assignment.values():
            assignment[task] = analyst
            result = assign_analysts(tasks, assignment)
            if result:
                return result
            del assignment[task]

    return None

# =====================================================
# CO5: BAYESIAN PROBABILITY
# =====================================================

def bayes_probability():
    p_attack = 0.3
    p_alert_attack = 0.9
    p_alert_no_attack = 0.1

    return round(
        (p_attack * p_alert_attack) /
        ((p_attack * p_alert_attack) +
         ((1 - p_attack) * p_alert_no_attack)),
        2
    )

# =====================================================
# CO4: UTILITY FUNCTION
# =====================================================

utility = {
    "Block IP": 100,
    "Restart DB service": 90,
    "Isolate system": 95,
    "Scale system": 85,
    "Kill heavy process": 80,
    "Check CPU usage": 70,
    "Restart router": 75,
    "Alert security team": 100
}

def best_action(actions):
    return max(actions, key=lambda x: utility.get(x, 50))

# =====================================================
# INPUT SYSTEM (IMPROVED FORM STYLE)
# =====================================================

def get_input():
    print("\n===================================")
    print(" INCIDENT INPUT FORM ")
    print("===================================\n")

    desc = input("1. Describe Incident : ")
    system = input("2. Affected System   : ")
    impact = input("3. User Impact (Low/Medium/High): ")

    return desc.lower(), system.lower(), impact.lower()

# =====================================================
# DETECTION ENGINE
# =====================================================

def detect(text):
    detected = []

    for incident, data in INCIDENT_DB.items():
        for kw in data["keywords"]:
            if kw in text:
                detected.append(incident)
                break

    return detected

# =====================================================
# RISK ENGINE
# =====================================================

def risk_score(detected):
    if not detected:
        return 1
    return max(INCIDENT_DB[d]["risk"] for d in detected)

def risk_level(score):
    return {
        1: "LOW",
        2: "MEDIUM",
        3: "HIGH",
        4: "CRITICAL"
    }[score]

# =====================================================
# ACTION ENGINE
# =====================================================

def generate_actions(detected):
    actions = []
    for d in detected:
        actions.extend(INCIDENT_DB[d]["actions"])

    return list(set(actions)) if actions else ["Monitor system and collect logs"]

# =====================================================
# EXPLANATION ENGINE (CLEAR & VIVA READY)
# =====================================================

def explain(detected, score, best, bayes, path, analysts):
    return [
        f"Step 1: Incident patterns detected → {detected if detected else 'No exact match'}",
        f"Step 2: Risk score calculated using severity rules → {score}",
        f"Step 3: Bayesian inference gives confidence → {bayes}",
        f"Step 4: A* search models system impact path → {path}",
        f"Step 5: CSP assigns analysts for response → {analysts}",
        f"Step 6: Utility function selects best action → {best}"
    ]

# =====================================================
# MAIN AGENT
# =====================================================

def incident_agent(desc, system, impact):

    detected = detect(desc)
    score = risk_score(detected)
    level = risk_level(score)

    actions = generate_actions(detected)
    best = best_action(actions)

    path, cost = astar("User", "Security")

    analysts = assign_analysts(list(domains.keys()))
    if analysts is None:
        analysts = {"system": "No valid CSP assignment found"}

    bayes = bayes_probability()

    return {
        "time": str(datetime.datetime.now()),
        "system": system,
        "risk_level": level,
        "risk_score": score,
        "detected": detected,
        "actions": actions,
        "best_action": best,
        "bayes": bayes,
        "attack_path": path,
        "path_cost": cost,
        "analysts": analysts,
        "explanation": explain(detected, score, best, bayes, path, analysts)
    }

# =====================================================
# OUTPUT DISPLAY (CLEAN + PROFESSIONAL)
# =====================================================

def display(result):

    print("\n===================================")
    print(" INCIDENT RESPONSE REPORT ")
    print("===================================\n")

    print("Time            :", result["time"])
    print("System          :", result["system"])
    print("Risk Level      :", result["risk_level"])
    print("Risk Score      :", result["risk_score"])

    print("\nDetected Issues :", result["detected"])

    print("\nSuggested Actions:")
    for a in result["actions"]:
        print(" -", a)

    print("\n Recommended Action:", result["best_action"])

    print("\nBayesian Confidence:", result["bayes"])

    print("\nA* System Path:", result["attack_path"])
    print("Path Cost:", result["path_cost"])

    print("\nCSP Analyst Assignment:")

    if isinstance(result["analysts"], dict):
        for k, v in result["analysts"].items():
            print(" -", k, "→", v)
    else:
        print(result["analysts"])

    print("\nEXPLANATION TRACE:")
    for step in result["explanation"]:
        print(" -", step)

# =====================================================
# MAIN PROGRAM
# =====================================================

if __name__ == "__main__":

    desc, system, impact = get_input()
    result = incident_agent(desc, system, impact)
    display(result)