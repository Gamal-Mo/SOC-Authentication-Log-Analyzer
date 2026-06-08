import re
from datetime import datetime

# =========================
# STATE
# =========================

failed_counts_by_ip = {}
failed_counts_by_user = {}
failed_times_by_ip = {}
users_per_ip = {}

alerts = []

rules = {
    "WARNING": 2,
    "BRUTE_FORCE": 3,
    "PASSWORD_SPRAY_USERS": 3
}


# =========================
# PARSER
# =========================

def parse_log(log):
    user = re.search(r"user=(\w+)", log)
    ip = re.search(r"ip=(\d+\.\d+\.\d+\.\d+)", log)
    action = re.search(r"action=(\w+)", log)

    timestamp = re.search(
        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})",
        log
    )

    return {
        "user": user.group(1) if user else None,
        "ip": ip.group(1) if ip else None,
        "action": action.group(1) if action else None,
        "timestamp": timestamp.group(1) if timestamp else None
    }


# =========================
# TRACKING
# =========================

def update_failed_count_by_ip(ip):
    failed_counts_by_ip[ip] = failed_counts_by_ip.get(ip, 0) + 1


def update_failed_count_by_user(user):
    failed_counts_by_user[user] = (
        failed_counts_by_user.get(user, 0) + 1
    )


def update_failed_time(ip, timestamp):
    dt = datetime.strptime(
        timestamp,
        "%Y-%m-%d %H:%M:%S"
    )

    failed_times_by_ip.setdefault(ip, []).append(dt)


def update_users_per_ip(ip, user):
    users_per_ip.setdefault(ip, set()).add(user)


# =========================
# DETECTIONS
# =========================

def detect_rules(ip):
    count_by_ip = failed_counts_by_ip[ip]

    if count_by_ip == rules["BRUTE_FORCE"]:
        alert = (
            f"[BRUTE_FORCE] "
            f"{ip} -> {count_by_ip} failed logins"
        )

        alerts.append(alert)
        print(alert)

    elif count_by_ip == rules["WARNING"]:
        alert = (
            f"[WARNING] "
            f"{ip} -> {count_by_ip} failed logins "
        )

        alerts.append(alert)
        print(alert)


def detect_time_window(ip):
    times = failed_times_by_ip[ip]

    current_time = times[-1]

    recent_attempts = 0

    for t in times:
        diff = (
            current_time - t
        ).total_seconds()

        if diff <= 300:
            recent_attempts += 1

    if recent_attempts >= 3:
        alert = (
            f"[TIME_WINDOW_BRUTE_FORCE] "
            f"{ip} -> {recent_attempts} attempts "
            f"in 5 minutes"
        )

        alerts.append(alert)
        print(alert)


def detect_password_spraying(ip):
    if len(users_per_ip[ip]) >= rules["PASSWORD_SPRAY_USERS"]:
        alert = (
            f"[PASSWORD_SPRAY] "
            f"{ip} targeted "
            f"{len(users_per_ip[ip])} users"
        )

        alerts.append(alert)
        print(alert)


# =========================
# MAIN ENGINE
# =========================

with open("auth.log") as file:
    for log in file:
        event = parse_log(log)

        if (
            event["action"] == "failed_login"
            and event["ip"]
            and event["user"]
            and event["timestamp"]
        ):
            update_failed_count_by_ip(
                event["ip"]
            )

            update_failed_count_by_user(
                event["user"]
            )

            update_failed_time(
                event["ip"],
                event["timestamp"]
            )

            update_users_per_ip(
                event["ip"],
                event["user"]
            )

            detect_rules(
                event["ip"]
               
            )

            detect_time_window(
                event["ip"]
            )

for ip in users_per_ip:
    detect_password_spraying(ip)            

            


# =========================
# EXPORT ALERTS
# =========================

with open("alerts.txt", "w") as file:
    for alert in alerts:
        file.write(alert + "\n")


# =========================
# SUMMARY
# =========================

print("\n=== SUMMARY ===")

print("\nFailed Logins By IP:")
print(failed_counts_by_ip)

print("\nFailed Logins By User:")
print(failed_counts_by_user)

print("\nUsers Per IP:")
print(users_per_ip)

print("\nAlerts Generated:")
print(len(alerts))