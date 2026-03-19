import streamlit as st
import pandas as pd
import os
from openai import OpenAI
from netmiko import ConnectHandler # Library for Network Automation (SSH connections to routers/firewalls)

# ==========================================
# 1. PAGE CONFIGURATION & API SETUP
# ==========================================
# Set up the main layout, title, and favicon (using the local logo.png) of the web application
st.set_page_config(page_title="Automaton", page_icon="logo.png", layout="wide")

# Places the sleek logo on the top-left corner of the app (Sidebar area)
st.logo("logo.png")

# PUT YOUR API ΚΕΥ HERE!
OPENAI_API_KEY = "API_KEY_HERE"

try:
    # Initialize the OpenAI client for the AI SOC Assistant
    client = OpenAI(api_key=OPENAI_API_KEY)
except Exception as e:
    client = None

# ==========================================
# 2. AUTOMATION ACTION (SOAR)
# ==========================================
def execute_soar_action(action_type):
    """
    Connects to the Cisco Edge Gateway via SSH and deploys containment measures.
    Demonstrates real-world SOAR (Security Orchestration, Automation, and Response).
    
    Args:
        action_type (int): 1 for Interface Shutdown, 2 for targeted ACL.
    Returns:
        tuple: (Boolean success status, String output/error log)
    """
    # Dictionary defining the target network device credentials and platform
    cisco_device = {
        'device_type': 'cisco_ios',
        'host': '192.168.56.50',
        'username': 'admin',
        'password': 'Hackathon2026!',
        'conn_timeout': 30,
        'auth_timeout': 30,
        'global_delay_factor': 2,
    }
    
    try:
        # Establish SSH connection to the router
        net_connect = ConnectHandler(**cisco_device)
        
        if action_type == 1:
            # OPTION 1: The Nuclear Option (Full Interface Shutdown)
            config_commands = [
                'interface FastEthernet0/1',
                'shutdown'
            ]
        elif action_type == 2:
            # OPTION 2: The Surgical Strike (Dynamic Micro-segmentation via ACL)
            config_commands = [
                'access-list 100 deny ip host 10.0.0.2 any',  
                'access-list 100 permit ip any any',          
                'interface FastEthernet0/1',
                'ip access-group 100 in'                      
            ]
            
        # Send the configuration commands and disconnect safely
        output = net_connect.send_config_set(config_commands)
        net_connect.disconnect()
        return True, output
    except Exception as e:
        return False, str(e)

# ==========================================
# 3. DATA INGESTION (TELEMETRY PARSING)
# ==========================================
# Using @st.cache_data to prevent reloading log files on every UI interaction

@st.cache_data
def load_waf_logs():
    try:
        return pd.read_csv('data/waf_alerts.csv')
    except Exception:
        return pd.DataFrame() 

@st.cache_data
def load_crypto_logs():
    try:
        df = pd.read_csv('data/x509.log', sep='\t', comment='#', names=['ts', 'id', 'version', 'serial', 'subject', 'issuer', 'not_valid_before', 'not_valid_after', 'key_alg', 'sig_alg', 'key_type', 'key_length', 'exponent', 'curve', 'san.dns', 'san.uri', 'san.email', 'san.ip', 'ca', 'path_len'])
        df['ts'] = pd.to_datetime(df['ts'], unit='s')
        df['not_valid_after'] = pd.to_datetime(df['not_valid_after'], unit='s')
        return df
    except Exception:
        return pd.DataFrame()

@st.cache_data
def load_ssl_logs():
    try:
        df = pd.read_csv('data/ssl.log', sep='\t', comment='#', header=None, low_memory=False)
        if len(df.columns) >= 8:
            df.rename(columns={0: 'ts', 2: 'src_ip', 4: 'dst_ip', 6: 'version', 7: 'cipher'}, inplace=True)
            df['ts'] = pd.to_datetime(pd.to_numeric(df['ts'], errors='coerce'), unit='s', errors='coerce')
        return df
    except Exception:
        return pd.DataFrame()

@st.cache_data
def load_raw_text_log(filename):
    filepath = os.path.join('data', filename)
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()[:3000]
    except Exception:
        return "Log file not found."

# Execute data loading functions
waf_df = load_waf_logs()
crypto_df = load_crypto_logs()
ssl_df = load_ssl_logs()
fortigate_raw = load_raw_text_log('FortiGate Sample logs.txt')
paloalto_raw = load_raw_text_log('PaloAlto sample traffic logs.txt')

# ==========================================
# 3.5 SIDEBAR (VISUAL ENHANCEMENT & STATUS)
# ==========================================
with st.sidebar:
    st.header("⚙️ System Status")
    
    # Dynamic AI Engine Check
    if client:
        st.success("🟢 **AI Engine:** Online & Correlating")
    else:
        st.error("🔴 **AI Engine:** Offline (API Error)")

    # Static SOAR Check
    st.success("🟢 **SOAR Module:** Armed (SSH Ready)")

    # Dynamic Telemetry Check
    if not waf_df.empty or not ssl_df.empty:
        st.success("🟢 **Telemetry:** Active")
    else:
        st.error("🔴 **Telemetry:** Disconnected (No Logs)")
        
    st.divider()
    st.markdown("**Gateway Target:** `192.168.56.50`")
    st.markdown("**Platform:** `Cisco IOS`")
    st.divider()
    
    st.caption("Automaton v1.1.0 - Zero Trust Architecture")
    st.caption("© 2026 | Developed by Alexandros Kitsios")

# ==========================================
# 4. DASHBOARD HEADER & BRANDING
# ==========================================
st.image("logo.png", width=280)
st.caption("Advanced Enterprise AI SOC & Cryptographic Analyzer")
st.divider()

# ==========================================
# 5. THREAT MONITORING TABS
# ==========================================
st.subheader("🔎 Multi-Vendor Log Analysis")
tab1, tab2, tab3, tab4 = st.tabs(["🔒 WAF/IDS Alerts", "🔐 PKI Health (x509)", "🌐 SSL Traffic (Network)", "🔥 Raw Vendor Logs (AI Parsed)"])

with tab1:
    if not waf_df.empty:
        st.dataframe(waf_df.rename(columns={'Source_IP': 'Source IP', 'Destination_IP': 'Destination IP', 'Threat_Type': 'Threat Type'}), use_container_width=True)
    else:
        st.warning("No WAF logs found.")

with tab2:
    if not crypto_df.empty:
        display_columns = ['ts', 'subject', 'issuer', 'not_valid_after', 'sig_alg', 'key_length']
        st.dataframe(crypto_df[display_columns].rename(columns={'ts': 'Timestamp', 'subject': 'Certificate Subject', 'issuer': 'Issuer (CA)', 'not_valid_after': 'Expiration Date', 'sig_alg': 'Signature Algorithm', 'key_length': 'RSA Key Size'}), use_container_width=True)
    else:
        st.warning("Crypto logs not found.")

with tab3:
    if not ssl_df.empty and 'src_ip' in ssl_df.columns:
        st.dataframe(ssl_df[['ts', 'src_ip', 'dst_ip', 'version', 'cipher']].head(100).rename(columns={'ts': 'Timestamp', 'src_ip': 'Source IP', 'dst_ip': 'Destination IP', 'version': 'TLS Version', 'cipher': 'Cipher Suite'}), use_container_width=True)
    else:
        st.warning("SSL logs not found.")

with tab4:
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**FortiGate Raw Traffic**")
        st.text_area("FortiGate Logs", fortigate_raw, height=250)
    with col_b:
        st.markdown("**Palo Alto Raw Traffic**")
        st.text_area("Palo Alto Logs", paloalto_raw, height=250)

st.divider()

# ==========================================
# 6. AUTOMATON AI INTERFACE & SOAR TRIGGER
# ==========================================
st.subheader("💬 Ask Automaton")

if "messages" not in st.session_state:
    st.session_state.messages = []

for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

if user_input := st.chat_input("E.g., 'Analyze the logs. Are there any threats or cryptographic risks?'"):
    
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)

    # --------------------------------------------------------------------------------
    # LLM PROMPT INJECTION & SOAR INTERCEPTION
    # --------------------------------------------------------------------------------
    trigger_action = 0
    user_text = user_input.lower()
    
    action_keywords = ["execute", "option", "do", "now", "authorize", "playbook"]
    
    if any(key in user_text for key in action_keywords):
        if "1" in user_text:
            trigger_action = 1
        elif "2" in user_text:
            trigger_action = 2
    elif len(st.session_state.messages) >= 2:
        last_ai_msg = st.session_state.messages[-2]["content"].lower()
        if "authorize" in last_ai_msg:
            if user_text.strip() == "1": trigger_action = 1
            if user_text.strip() == "2": trigger_action = 2

    context_waf = waf_df.to_string() if not waf_df.empty else "No WAF alerts."
    context_crypto = crypto_df[['ts', 'subject', 'issuer', 'not_valid_after']].to_string() if not crypto_df.empty else "No Crypto alerts."
    context_ssl = ssl_df[['ts', 'src_ip', 'dst_ip', 'version', 'cipher']].head(20).to_string() if 'src_ip' in ssl_df.columns else "No SSL alerts."
    
    system_prompt = f"""
    You are Automaton, an elite Enterprise AI SOC Analyst and Tier 3 Incident Responder.
    Your communication style is strictly that of a top-tier Security Orchestration, Automation, and Response (SOAR) platform.
    You MUST output extremely concise, highly structured incident reports. NO conversational filler. NO long paragraphs.

    DATA CONTEXT:
    [WAF LOGS]: {context_waf}
    [SSL LOGS]: {context_ssl}
    [X509 PKI LOGS]: {context_crypto}
    [FORTIGATE RAW]: {fortigate_raw}
    [PALO ALTO RAW]: {paloalto_raw}

    CRITICAL INSTRUCTIONS:
    1. Parse the logs and correlate attacker IPs with PKI/SSL threats (HNDL, weak ciphers, expired certs).
    2. Output distinct threat blocks for each vulnerability found.
    3. You MUST use the EXACT markdown template below. Do not deviate. Do not add introductory text.

    ### 🚨 **INCIDENT SUMMARY**
    Automated telemetry indicates multiple cryptographic and network-level anomalies requiring immediate containment.

    ---
    ### 🔴 **ALERT 1: [Short Threat Name - e.g., Cryptographic Downgrade Attack (HNDL)]**
    * **Target/Source:** [Extracted IP or Hostname]
    * **Vulnerability:** [e.g., Weak RC4 Cipher / Expired x509]
    * **MITRE ATT&CK:** [e.g., T1040 - Network Sniffing]
    * **CVE:** [Relevant CVE ID if applicable, else N/A]
    * **Severity:** [CRITICAL / HIGH]

    ### 🔴 **ALERT 2: [Short Threat Name]**
    * **Target/Source:** [Extracted IP]
    * **Vulnerability:** [Details]
    * **MITRE ATT&CK:** [T-Code and Name]
    * **CVE:** [Relevant CVE ID if applicable, else N/A]
    * **Severity:** [CRITICAL / HIGH]
    ---

    ### ⚡ **RECOMMENDED REMEDIATION PLAYBOOKS**
    Please authorize one of the following automated containment protocols:

    **[ 1 ] Gateway Interface Shutdown (Last Resort)**
    * **Action:** Administratively disable the physical edge interface via SSH.
    * **Impact:** High (Drastic containment; disrupts business continuity for all downstream hosts).

    **[ 2 ] Surgical Threat Isolation (Recommended)**
    * **Action:** Deploy dynamic ACL to the Core Router to isolate the specific attacker IP.
    * **Impact:** Low (Surgical containment; maintains business continuity for uncompromised users).

    **Awaiting Authorization:** Reply with "1" or "2" to execute the corresponding playbook.
    """

    with st.chat_message("assistant"):
        message_placeholder = st.empty()
        ai_prompt_to_send = user_input
        
        if trigger_action in [1, 2]:
            action_name = "Interface Shutdown" if trigger_action == 1 else "Dynamic ACL (Micro-segmentation)"
            
            with st.spinner(f"⚙️ Executing Zero-Trust Playbook: {action_name} via SSH (192.168.56.50)..."):
                success, log_output = execute_soar_action(trigger_action)
                
                if success:
                    st.success(f"✅ **ACTION SUCCESSFUL:** {action_name} deployed on Cisco Router. Threat isolated.")
                    ai_prompt_to_send = f"""The system successfully executed Option {trigger_action} ({action_name}). 
                    1. Confirm the execution to the user.
                    2. Generate a very short Post-Incident SOC Playbook (Containment, Eradication, Recovery) based on the threats found."""
                else:
                    st.error(f"❌ **ACTION FAILED:** SSH Error: {log_output}")
                    ai_prompt_to_send = "The SSH script failed. Inform the user."

        if not client:
            message_placeholder.markdown("⚠️ **Error:** OpenAI API client failed to initialize. Check your API Key.")
        else:
            try:
                api_messages = [{"role": "system", "content": system_prompt}]
                
                for m in st.session_state.messages[:-1]:
                    api_messages.append({"role": m["role"], "content": m["content"]})
                api_messages.append({"role": "user", "content": ai_prompt_to_send})
                
                response = client.chat.completions.create(
                    model="gpt-4.1", 
                    messages=api_messages,
                    temperature=0.3 
                )
                
                full_response = response.choices[0].message.content
                message_placeholder.markdown(full_response)
                
                st.session_state.messages.append({"role": "assistant", "content": full_response})
                
            except Exception as e:
                error_msg = f"⚠️ **API Connection Error:** {e}"
                message_placeholder.markdown(error_msg)
                st.session_state.messages.append({"role": "assistant", "content": error_msg})
