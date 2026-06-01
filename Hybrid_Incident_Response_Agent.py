from dataclasses import dataclass
from typing import Dict, List
import heapq

# =====================================================
# CO1 : PEAS MODEL
# =====================================================

PEAS = {
    "Performance": "Minimize attack impact",
    "Environment": "Enterprise Network",
    "Actuators": ["Block IP", "Isolate Host", "Alert Admin"],
    "Sensors": ["Firewall Logs", "IDS Alerts", "System Logs"]
}

# =====================================================
# CO1 : STATE REPRESENTATION
# =====================================================

@dataclass
class IncidentState:
    node: str
    cost: int

# =====================================================
# CO1 : RULE-BASED KNOWLEDGE
# =====================================================

rules = {
    "failed_logins": "Brute Force Attack",
    "malware_alert": "Malware Infection",
    "phishing_mail": "Phishing Attack"
}

# =====================================================
# CO1 : ATTACK GRAPH
# =====================================================

network = {
    "Firewall": [("WebServer", 2)],
    "WebServer": [("Database", 3), ("MailServer", 4)],
    "Database": [("AdminPC", 1)],
    "MailServer": [("AdminPC", 2)],
    "AdminPC": []
}

heuristic = {
    "Firewall": 5,
    "WebServer": 4,
    "Database": 1,
    "MailServer": 2,
    "AdminPC": 0
}

# =====================================================
# CO2 : A* SEARCH
# =====================================================

def astar(start, goal):

    open_list = []

    heapq.heappush(
        open_list,
        (0, start, [start], 0)
    )

    visited = set()

    while open_list:

        f, current, path, g = heapq.heappop(open_list)

        if current == goal:
            return path, g

        visited.add(current)

        for neighbor, cost in network[current]:

            if neighbor not in visited:

                new_g = g + cost

                new_f = (
                    new_g +
                    heuristic[neighbor]
                )

                heapq.heappush(
                    open_list,
                    (
                        new_f,
                        neighbor,
                        path + [neighbor],
                        new_g
                    )
                )

    return None, 0

# =====================================================
# CO3 : CSP ANALYST ASSIGNMENT
# =====================================================

domains = {
    "Brute Force Attack":
        ["Alice", "Bob"],

    "Malware Infection":
        ["Bob", "Charlie"],

    "Phishing Attack":
        ["Alice", "Charlie"]
}

def assign_analysts(
    tasks,
    assignment={}
):

    if len(assignment) == len(tasks):
        return assignment

    task = None

    for t in tasks:
        if t not in assignment:
            task = t
            break

    for analyst in domains[task]:

        if analyst not in assignment.values():

            assignment[task] = analyst

            result = assign_analysts(
                tasks,
                assignment
            )

            if result:
                return result

            del assignment[task]

    return None

# =====================================================
# CO5 : BAYESIAN REASONING
# =====================================================

def bayes_attack_probability():

    prior_attack = 0.30

    p_alert_attack = 0.90

    p_alert_noattack = 0.10

    numerator = (
        p_alert_attack *
        prior_attack
    )

    denominator = (
        numerator +
        p_alert_noattack *
        (1 - prior_attack)
    )

    return numerator / denominator

# =====================================================
# CO4 : UTILITY FUNCTION
# =====================================================

utilities = {
    "Block IP": 70,
    "Isolate Host": 95,
    "Alert Admin": 50
}

def choose_best_action():

    best = max(
        utilities,
        key=utilities.get
    )

    return best

# =====================================================
# CO6 : HYBRID INCIDENT RESPONSE AGENT
# =====================================================

class HybridIncidentResponseAgent:

    def detect(self, event):

        print("\n[DETECTION]")

        threat = rules.get(
            event,
            "Unknown Incident"
        )

        print(
            "Detected Threat:",
            threat
        )

        return threat

    def reason(self):

        print("\n[REASONING]")

        probability = (
            bayes_attack_probability()
        )

        print(
            "Attack Probability:",
            round(probability, 2)
        )

        return probability

    def plan(self):

        print("\n[PLANNING]")

        path, cost = astar(
            "Firewall",
            "AdminPC"
        )

        print(
            "Attack Path:",
            path
        )

        print(
            "Path Cost:",
            cost
        )

        return path

    def allocate_resources(self):

        print("\n[RESOURCE ASSIGNMENT]")

        tasks = list(domains.keys())

        assignment = assign_analysts(tasks)

        print(
            "Assigned Analysts:"
        )

        for task, analyst in assignment.items():

            print(
                task,
                "->",
                analyst
            )

        return assignment

    def decide(self):

        print("\n[DECISION]")

        action = choose_best_action()

        print(
            "Recommended Action:",
            action
        )

        return action

    def run(self, event):

        print(
            "\n===== INCIDENT RESPONSE ====="
        )

        self.detect(event)

        self.reason()

        self.plan()

        self.allocate_resources()

        self.decide()

        print(
            "\n===== REASONING TRACE ====="
        )

        print(
            "Rule Base -> Threat Detection"
        )

        print(
            "Bayes Rule -> Threat Probability"
        )

        print(
            "A* Search -> Attack Path"
        )

        print(
            "CSP -> Analyst Allocation"
        )

        print(
            "Utility Function -> Best Action"
        )

# =====================================================
# TESTING
# =====================================================

def test_astar():

    path, cost = astar(
        "Firewall",
        "AdminPC"
    )

    assert path[-1] == "AdminPC"

def test_bayes():

    probability = (
        bayes_attack_probability()
    )

    assert probability > 0

def test_csp():

    result = assign_analysts(
        list(domains.keys())
    )

    assert result is not None

# =====================================================
# MAIN
# =====================================================

if __name__ == "__main__":

    test_astar()
    test_bayes()
    test_csp()

    agent = HybridIncidentResponseAgent()

    agent.run("failed_logins")