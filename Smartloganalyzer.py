# SmartlogAnalyzer
# Created by Samuel Dhamodharan
# Licensed under CC BY-NC 4.0
# https://creativecommons.org/licenses/by-nc/4.0/

# Description: Advanced log security scanner with AI-powered keyword generation

import os
import requests
from datetime import datetime
from colorama import Fore, Style, init
init(autoreset=True)

# Configuration file path
CONFIG_FILE = os.path.expanduser("~/.elsa_config.txt")

# AI model to summarize the log file
def generate_ai_summary(matches, report_path, api_key, model="mistralai/mistral-7b-instruct:free"):
    """Generate AI summary using OpenRouter API"""
    try:
        with open(report_path, 'r', encoding='utf-8') as f:
            report_content = f.read()
        
        prompt = (
            "Analyze these security scan results and provide a concise summary highlighting:\n"
            "1. The most critical findings\n"
            "2. Any patterns or repeated issues\n"
            "3. Recommended next steps\n\n"
            f"Scan Results:\n{report_content}"
        )
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        data = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7,
            "max_tokens": 500
        }

        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=30
        )
        response.raise_for_status()
        
        # Extract content from response
        response_data = response.json()
        return response_data["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"{Fore.RED}❌ AI Summary Error: {str(e)}")
        return None

def generate_ai_keywords(api_key, count=50, model="mistralai/mistral-7b-instruct:free"):
    """Generate security keywords using AI - returns simple text format"""
    try:
        prompt = (
            f"Generate {count} security-related keywords and phrases that might appear in system logs. "
            "For each keyword, provide its severity level. Format your response as simple lines like this:\n"
            "keyword1 - Critical\n"
            "keyword2 - High\n"
            "keyword3 - Medium\n"
            "keyword4 - Low\n\n"
            "Include various types of security events like attacks, vulnerabilities, and suspicious activities. "
            "Use only these severity levels: Critical, High, Medium, Low"
        )
        
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        data = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.5,
            "max_tokens": 2000
        }

        response = requests.post(
            "https://openrouter.ai/api/v1/chat/completions",
            headers=headers,
            json=data,
            timeout=45
        )
        response.raise_for_status()
        
        # Parse the text response
        content = response.json()["choices"][0]["message"]["content"]
        keywords = {}
        
        # Parse the AI response line by line
        for line in content.split('\n'):
            line = line.strip()
            if ' - ' in line:
                parts = line.split(' - ', 1)
                if len(parts) == 2:
                    keyword = parts[0].strip()
                    severity = parts[1].strip()
                    if keyword and severity in ['Critical', 'High', 'Medium', 'Low']:
                        keywords[keyword] = severity
        
        return keywords
    except Exception as e:
        print(f"{Fore.RED}❌ AI Keyword Generation Error: {str(e)}")
        return None

# Default keywords with expanded set
DEFAULT_KEYWORDS = {
    # Authentication/Authorization
    "authentication failure": "High",
    "invalid credentials": "Medium",
    "brute force attempt": "Critical",
    "account lockout": "Medium",
    "privilege escalation": "Critical",
    
    # Network Attacks
    "DDoS attack": "Critical",
    "port scan": "High",
    "SQL injection": "Critical",
    "XSS attempt": "Critical",
    "CSRF token mismatch": "High",
    
    # System Events
    "root login": "High",
    "sudo access": "Medium",
    "firewall rule changed": "High",
    "VPN tunnel down": "Medium",
    
    # Malware/Exploits
    "malware detected": "Critical",
    "ransomware activity": "Critical",
    "zero-day exploit": "Critical",
    "backdoor installed": "Critical",
    
    # Data Protection
    "PII access": "High",
    "data exfiltration": "Critical",
    "unencrypted data": "Medium",
    
    # System Health
    "failed backup": "Medium",
    "certificate expired": "Medium",
    "high CPU usage": "Low",
    
    # Additional security events
    "unauthorized access": "High",
    "session hijacking": "High",
    "IDS alert": "High",
    "WAF triggered": "High"
}

def load_config():
    """Load configuration from simple text file"""
    config = {"api_key": None, "keywords": DEFAULT_KEYWORDS.copy()}
    
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            for line in lines:
                line = line.strip()
                if line.startswith("API_KEY="):
                    config["api_key"] = line.split("=", 1)[1].strip()
                elif line.startswith("KEYWORD="):
                    # Format: KEYWORD=keyword_name,severity_level
                    keyword_data = line.split("=", 1)[1].strip()
                    if "," in keyword_data:
                        keyword, severity = keyword_data.split(",", 1)
                        config["keywords"][keyword.strip()] = severity.strip()
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️ Config load error: {e}")
    
    return config

def save_config(config):
    """Save configuration to simple text file"""
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            # Save API key
            if config.get('api_key'):
                f.write(f"API_KEY={config['api_key']}\n")
            
            # Save keywords (only save non-default ones to keep file small)
            for keyword, severity in config.get('keywords', {}).items():
                if keyword not in DEFAULT_KEYWORDS:
                    f.write(f"KEYWORD={keyword},{severity}\n")
    except Exception as e:
        print(f"{Fore.RED}⚠️ Failed to save config: {e}")



def scan_log_file(log_path, keywords):
    """Scan the log file for keywords with line context."""
    matches = []
    try:
        with open(log_path, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, start=1):
                line_lower = line.lower()
                for keyword, risk in keywords.items():
                    if keyword.lower() in line_lower:
                        matches.append({
                            "line": line_num,
                            "keyword": keyword,
                            "risk": risk,
                            "context": line.strip()[:100]
                        })
        return matches
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: {log_path}")
    except Exception as e:
        raise Exception(f"Error scanning file: {str(e)}")

def save_results(matches, output_path):
    """Save scan results to a markdown file with timestamp."""
    try:
        output_dir = os.path.dirname(output_path) or '.'
        os.makedirs(output_dir, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as md_file:
            md_file.write(f"# Keyword Scan Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            if not matches:
                md_file.write("## No security keywords found in the log file.\n")
            else:
                risk_levels = {}
                for match in matches:
                    if match['risk'] not in risk_levels:
                        risk_levels[match['risk']] = []
                    risk_levels[match['risk']].append(match)
                
                severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
                for risk_level in sorted(risk_levels.keys(), key=lambda x: severity_order.get(x, 4)):
                    md_file.write(f"## {risk_level} Risk Findings\n")
                    for match in risk_levels[risk_level]:
                        md_file.write(f"### Keyword: `{match['keyword']}`\n")
                        md_file.write(f"- **Line:** {match['line']}\n")
                        md_file.write(f"- **Context:** `{match['context']}`\n\n")
        
        return output_path
    except PermissionError:
        raise PermissionError(f"Permission denied. Cannot write to: {output_path}")
    except IOError as e:
        raise IOError(f"Could not write to output file: {str(e)}")
    except Exception as e:
        raise Exception(f"Error saving results: {str(e)}")

def validate_output_path(path):
    """Validate the output path is writable."""
    if os.path.isdir(path):
        raise ValueError("Output path must be a file path, not a directory")
    
    output_dir = os.path.dirname(path) or '.'
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
        except:
            raise PermissionError(f"Cannot create directory: {output_dir}")
    
    if os.path.exists(path):
        try:
            with open(path, 'a'):
                pass
        except:
            raise PermissionError(f"Cannot write to existing file: {path}")
    else:
        try:
            with open(path, 'w'):
                pass
            os.remove(path)
        except:
            raise PermissionError(f"Cannot create file at: {path}")
    return True

def analyze_threat_patterns(matches):
    """Analyze matches to identify threat patterns and generate severity scores"""
    if not matches:
        return []
    
    # Group matches by keyword to count occurrences
    keyword_counts = {}
    for match in matches:
        keyword = match['keyword']
        if keyword not in keyword_counts:
            keyword_counts[keyword] = {
                'count': 0,
                'risk': match['risk'],
                'lines': []
            }
        keyword_counts[keyword]['count'] += 1
        keyword_counts[keyword]['lines'].append(match['line'])
    
    # Generate threat descriptions based on patterns
    threats = []
    
    for keyword, data in keyword_counts.items():
        count = data['count']
        risk = data['risk']
        lines = data['lines']
        
        # Create contextual threat messages
        if keyword == "authentication failure" or "failed login" in keyword:
            if count >= 5:
                threat_msg = f"Critical Risk: {count} failed authentication attempts detected"
            elif count >= 3:
                threat_msg = f"High Risk: {count} failed login attempts"
            else:
                threat_msg = f"Medium Risk: {count} authentication failure(s)"
        
        elif keyword == "brute force attempt" or "brute force" in keyword:
            threat_msg = f"Critical Risk: Brute force attack detected ({count} occurrence(s))"
        
        elif keyword == "root login" or "sudo access" in keyword:
            if count >= 5:
                threat_msg = f"High Risk: {count} elevated privilege access attempts"
            else:
                threat_msg = f"Medium Risk: {count} root/admin access event(s)"
        
        elif keyword == "port scan" or "port scanning" in keyword:
            threat_msg = f"High Risk: Network scanning behavior detected ({count} event(s))"
        
        elif "ddos" in keyword.lower() or "dos attack" in keyword.lower():
            threat_msg = f"Critical Risk: Denial of Service attack in progress"
        
        elif "malware" in keyword or "ransomware" in keyword or "virus" in keyword:
            threat_msg = f"Critical Risk: Malicious software detected ({keyword})"
        
        elif "sql injection" in keyword or "xss" in keyword:
            threat_msg = f"Critical Risk: Web application attack attempt ({keyword})"
        
        elif "data exfiltration" in keyword or "data breach" in keyword:
            threat_msg = f"Critical Risk: Potential data compromise detected"
        
        elif "certificate expired" in keyword:
            threat_msg = f"Medium Risk: Security certificate issues ({count} certificate(s))"
        
        elif "failed backup" in keyword:
            threat_msg = f"Medium Risk: {count} backup failure(s) - data protection at risk"
        
        elif "high cpu usage" in keyword:
            threat_msg = f"Low Risk: System performance issues detected"
        
        elif "unauthorized access" in keyword:
            threat_msg = f"High Risk: {count} unauthorized access attempt(s)"
        
        elif "privilege escalation" in keyword:
            threat_msg = f"Critical Risk: Privilege escalation attempt detected"
        
        elif "session hijacking" in keyword:
            threat_msg = f"High Risk: Session hijacking attempt detected"
        
        elif "firewall" in keyword:
            threat_msg = f"High Risk: {count} firewall security event(s)"
        
        elif "vpn tunnel down" in keyword:
            threat_msg = f"Medium Risk: VPN connectivity issues ({count} event(s))"
        
        elif "ids alert" in keyword or "waf triggered" in keyword:
            threat_msg = f"High Risk: {count} security system alert(s) triggered"
        
        else:
            # Generic threat message for any other keywords
            if risk == "Critical":
                threat_msg = f"Critical Risk: {keyword} detected ({count} occurrence(s))"
            elif risk == "High":
                threat_msg = f"High Risk: {keyword} detected ({count} occurrence(s))"
            elif risk == "Medium":
                threat_msg = f"Medium Risk: {keyword} detected ({count} occurrence(s))"
            else:
                threat_msg = f"Low Risk: {keyword} detected ({count} occurrence(s))"
        
        threats.append({
            'message': threat_msg,
            'risk': risk,
            'count': count,
            'keyword': keyword,
            'lines': lines
        })
    
    # Sort threats by severity and count
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    threats.sort(key=lambda x: (severity_order.get(x['risk'], 4), -x['count']))
    
    return threats

def generate_local_summary(matches):
    """Generate a threat-focused summary with severity scoring."""
    if not matches:
        return "✅ No security threats detected in the log file."
    
    threats = analyze_threat_patterns(matches)
    
    summary_lines = ["🔍 THREAT ANALYSIS SUMMARY:"]
    summary_lines.append("=" * 40)
    
    # Show threat messages
    for threat in threats:
        risk_emoji = {
            'Critical': '🔴',
            'High': '🟠', 
            'Medium': '🟡',
            'Low': '🟢'
        }.get(threat['risk'], '⚪')
        
        summary_lines.append(f"{risk_emoji} {threat['message']}")
        if len(threat['lines']) <= 3:
            summary_lines.append(f"   └─ Found on line(s): {', '.join(map(str, threat['lines']))}")
        else:
            summary_lines.append(f"   └─ Found on {len(threat['lines'])} lines (first occurrence: line {threat['lines'][0]})")
        summary_lines.append("")
    
    # Overall risk assessment
    critical_count = len([t for t in threats if t['risk'] == 'Critical'])
    high_count = len([t for t in threats if t['risk'] == 'High'])
    
    summary_lines.append("📊 OVERALL RISK ASSESSMENT:")
    if critical_count > 0:
        summary_lines.append(f"⚠️  IMMEDIATE ACTION REQUIRED - {critical_count} critical threat(s) detected")
    elif high_count > 0:
        summary_lines.append(f"🔶 HIGH PRIORITY - {high_count} high-risk threat(s) require attention")
    else:
        summary_lines.append("🔹 MONITOR - Medium/Low risk events detected")
    
    return "\n".join(summary_lines)

def main():
    """Main function to execute the scanner with user interaction."""
    print(f"{Fore.CYAN}=== Advanced Keyword Security Scanner (Simplified) ===")
    print(f"{Fore.YELLOW}Licensed under CC BY-NC 4.0")
    
    # Load configuration
    config = load_config()
    api_key = config.get('api_key')
    keywords = config.get('keywords', DEFAULT_KEYWORDS.copy())
    
    # AI keyword generation option
    if input("Do you want to generate additional keywords with AI? (y/n): ").strip().lower() == 'y':
        if not api_key:
            api_key = input("Enter your OpenRouter API key: ").strip()
            if api_key:
                config['api_key'] = api_key
                save_config(config)
        
        if api_key:
            print(f"{Fore.BLUE}Generating additional keywords with AI...")
            ai_keywords = generate_ai_keywords(api_key)
            if ai_keywords:
                keywords.update(ai_keywords)
                print(f"{Fore.GREEN}Added {len(ai_keywords)} AI-generated keywords.")
                # Save the updated keywords to config
                config['keywords'] = keywords
                save_config(config)
            else:
                print(f"{Fore.YELLOW}Using existing keywords only.")
    
    # Log file input
    while True:
        log_path = input("Enter path to log file: ").strip()
        if os.path.isfile(log_path):
            break
        print(f"{Fore.RED}Error: File not found at {log_path}")
    
    # Output path handling
    while True:
        default_dir = input("Enter output directory (leave empty for current dir): ").strip() or "."
        default_filename = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        default_output = os.path.join(default_dir, default_filename)
        
        output_path = input(f"Enter output path [default: {default_output}]: ").strip()
        if not output_path:
            output_path = default_output
        
        try:
            validate_output_path(output_path)
            break
        except Exception as e:
            print(f"{Fore.RED}Error: {str(e)}")
            if input("Try again? (y/n): ").lower() != 'y':
                print(f"{Fore.YELLOW}Operation cancelled by user.")
                return
    
    try:
        print(f"\n{Fore.BLUE}Scanning log file with {len(keywords)} keywords...")
        matches = scan_log_file(log_path, keywords)
        result_path = save_results(matches, output_path)
        
        # Ask for Summary Assistance
        use_summary = input("\nDo you want summary assistance for this log? (y/n): ").strip().lower()
        if use_summary == 'y':
            print(f"\n{Fore.MAGENTA}⚡ Generating Summary...\n")
            
            # Let user choose summary type
            summary_type = input("Choose summary type (ai/local): ").strip().lower()
            
            if summary_type == 'ai':
                if not api_key:
                    api_key = input("Enter your OpenRouter API key: ").strip()
                    if api_key:
                        config['api_key'] = api_key
                        save_config(config)
                
                if api_key:
                    summary = generate_ai_summary(matches, result_path, api_key)
                else:
                    print(f"{Fore.YELLOW}No API key available, using local summary")
                    summary = generate_local_summary(matches)
            else:
                summary = generate_local_summary(matches)
            
            if summary:
                print(f"\n{Fore.CYAN}🔎 Summary of the Scan:\n")
                print(f"{Fore.WHITE}{summary}")

                save_summary = input("\nSave this summary to your report? (y/n): ").strip().lower()
                if save_summary == 'y':
                    with open(result_path, 'a', encoding='utf-8') as f:
                        f.write("\n---\n\n## 📝 Summary\n")
                        f.write(summary + "\n")
                    print(f"{Fore.GREEN}✅ Summary added to your report!")
        
        print(f"\n{Fore.GREEN}Scan completed successfully!")
        print(f"{Fore.WHITE}Found {len(matches)} security-related keywords.")
        print(f"{Fore.WHITE}Report saved to: {os.path.abspath(result_path)}")

        # Summary stats
        if matches:
            print(f"\n{Fore.CYAN}🔍 THREAT SEVERITY BREAKDOWN:")

            # Get threat analysis
            threats = analyze_threat_patterns(matches)
            
            risk_colors = {
                "Critical": Fore.RED + Style.BRIGHT,
                "High": Fore.MAGENTA,
                "Medium": Fore.YELLOW,
                "Low": Fore.GREEN
            }

            for threat in threats[:5]:  # Show top 5 threats
                color = risk_colors.get(threat['risk'], Fore.WHITE)
                print(f"{color}• {threat['message']}")
            
            if len(threats) > 5:
                print(f"{Fore.CYAN}... and {len(threats) - 5} more threat(s)")
            
            # Overall counts
            risk_counts = {}
            for threat in threats:
                risk_counts[threat['risk']] = risk_counts.get(threat['risk'], 0) + 1
            
            print(f"\n{Fore.CYAN}📊 Summary by Risk Level:")
            for risk, count in sorted(risk_counts.items(), key=lambda x: ({'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}.get(x[0], 4), -x[1])):
                color = risk_colors.get(risk, Fore.WHITE)
                print(f"{color}├─ {risk}: {count} threat type(s)")
    
    except PermissionError as e:
        print(f"\n{Fore.RED}Permission Error: {str(e)}")
        print(f"{Fore.YELLOW}Please try running as administrator or choose a different location.")
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}")
    finally:
        print(f"\n{Fore.CYAN}Thank you for using the Keyword Security Scanner!")

if __name__ == "__main__":
    main()