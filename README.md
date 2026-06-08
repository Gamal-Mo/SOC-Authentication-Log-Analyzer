# SOC-Authentication-Log-Analyzer

A Python-based SOC automation project that parses authentication logs and detects suspicious login activity.

## Features

* Parse authentication logs using Regex
* Extract usernames, IP addresses, actions, and timestamps
* Track failed login attempts per IP
* Track failed login attempts per user
* Detect brute-force attacks
* Detect time-window brute-force attacks
* Detect password spraying attacks
* Generate and export alerts

## Detection Rules

### Warning Detection

Triggers when an IP reaches 2 failed login attempts.

### Brute Force Detection

Triggers when an IP reaches 3 or more failed login attempts.

### Time Window Brute Force

Triggers when 3 or more failed login attempts occur within 5 minutes.

### Password Spraying Detection

Triggers when a single IP targets 3 or more different usernames.

## Technologies Used

* Python
* Regular Expressions (Regex)
* Dictionaries
* File Handling
* Datetime Module

## Project Structure

detector.py → Main detection engine

auth.log → Sample authentication logs

alerts.txt → Generated alerts

## Sample Log Format

2026-06-02 15:30:22 user=admin ip=192.168.3.4 action=failed_login

## Future Improvements

* Sigma rule support
* VirusTotal integration
* AbuseIPDB integration
* JSON alert export
* Real-time log monitoring
