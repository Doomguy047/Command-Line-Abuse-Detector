import csv
import json

def load_rules(path):
    with open(path) as f:
        return json.load(f)

def analyze_logs(log_file, rules):
    findings = []

    with open(log_file, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            process = row["process_name"].lower()
            cmd = row["command_line"].lower()

            for rule in rules:
                if rule["process"] == process and rule["indicator"] in cmd:
                    findings.append({
                        "timestamp": row["timestamp"],
                        "process": row["process_name"],
                        "finding": rule["finding"],
                        "risk": rule["risk"],
                        "reason": rule["reason"]
                    })

    return findings

if __name__ == "__main__":
    rules = load_rules("detection_rules.json")
    results = analyze_logs("process_logs.csv", rules)
    print(json.dumps(results, indent=2))
