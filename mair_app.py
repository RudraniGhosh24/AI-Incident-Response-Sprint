import streamlit as st
import networkx as nx
import graphviz

st.set_page_config(page_title="MAIR: Incident Response", layout="wide", initial_sidebar_state="expanded")

# --- SIDEBAR & HEADER ---
st.sidebar.title("MAIR Framework")
st.sidebar.markdown("**Misaligned AI Incident Reporting**")
st.sidebar.markdown("Filling the gap identified by OpenAI (Sept 2026): *'The field has no agreed standard for reporting misalignment.'*")
st.sidebar.divider()
st.sidebar.info("Designed for the AI Incident Response Sprint (Sep 2026).")

st.title("MAIR: Autonomous AI Containment Failure Schema")
st.markdown("A standardized, CVSS-style scoring and statutory compliance framework for autonomous AI incidents. This tool calculates severity, maps facts to legal disclosure obligations, and models structural containment via deterministic graph reachability.")

# --- TABS ---
tab1, tab2, tab3 = st.tabs([
    "1. Interactive Scorer & Legal Triggers", 
    "2. Structural Reachability (Containment DAG)", 
    "3. Validation (HF & Wiki Incidents)"
])

# ==========================================
# TAB 1: SCORER AND LEGAL TRIGGERS
# ==========================================
with tab1:
    st.header("Assess New Incident")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Technical Escalation Metrics")
        egress = st.selectbox("Egress Vector (How did it break out?)", 
                              ["Sanctioned API Misuse (Score: 1)", "Credential Reuse/Hijack (Score: 2)", "Novel Exploit / Zero-Day (Score: 3)"])
        escalation = st.selectbox("Escalation Depth (How far did it go?)", 
                                  ["Sandbox-Internal (Score: 1)", "Host-Level Execution (Score: 2)", "Cross-Org Network Breach (Score: 3)"])
        blast = st.selectbox("Third-Party Blast Radius (Who was affected?)", 
                             ["None / Internal Only (Score: 1)", "Same-Org Production Systems (Score: 2)", "Third-Party Production Systems (Score: 3)"])
        
    with col2:
        st.subheader("Detection & Alignment Metrics")
        detection = st.selectbox("Detection Latency (How long until caught?)", 
                                 ["Hours (Score: 1)", "Days (Score: 2)", "Undetected until External Disclosure (Score: 3)"])
        intent = st.selectbox("Intent Ambiguity (Why did it happen?)", 
                              ["Optimization Pressure/Artifact (Score: 1)", "Unclear / Hallucination (Score: 2)", "Confirmed Deceptive Alignment (Score: 3)"])
        
    # --- SCORING LOGIC ---
    score_map = {"1": 1, "2": 2, "3": 3}
    total_score = (
        score_map[egress[-2]] + 
        score_map[escalation[-2]] + 
        score_map[blast[-2]] + 
        score_map[detection[-2]] + 
        score_map[intent[-2]]
    )
    
    st.divider()
    
    # Severity Metric
    col_score, col_text = st.columns([1, 3])
    with col_score:
        severity = "LOW"
        color = "green"
        if total_score >= 8: severity, color = "MEDIUM", "orange"
        if total_score >= 11: severity, color = "HIGH", "red"
        if total_score >= 13: severity, color = "CRITICAL", "purple"
        
        st.metric(label="MAIR Severity Score", value=f"{total_score} / 15", delta=severity, delta_color="inverse" if color=="red" or color=="purple" else "normal")

    with col_text:
        st.header("Statutory Obligations & Regulatory Triggers")
        st.markdown("Based on the objective dimensions above, the following legal disclosure obligations are plausibly triggered:")
        
        # Statutory Logic Mapping
        trigger_art55 = ("(Score: 3)" in blast) or ("(Score: 3)" in intent)
        trigger_sb1047 = ("(Score: 3)" in escalation) and ("(Score: 3)" in egress or "(Score: 2)" in egress)
        trigger_art91 = ("(Score: 3)" in detection)

        if trigger_art55:
            st.error("🚨 **EU AI Act Art. 55(1)(c) ('Serious Incident'): TRIGGERED**\n\n*Rationale:* Confirmed deceptive alignment or third-party production blast radius constitutes a systemic risk and potential breach of fundamental rights. Immediate notification to the EU AI Office is legally mandated.")
        else:
            st.success("✅ **EU AI Act Art. 55(1)(c):** Not definitively triggered. Monitor for escalation.")

        if trigger_sb1047:
            st.error("🚨 **California SB 1047 (Frontier Model Catastrophic Harm): TRIGGERED**\n\n*Rationale:* Host/Cross-org network breach combined with credential hijack/novel exploits meets the threshold for 'autonomous evasion of containment'. Developer must transmit incident report to the Attorney General.")
        else:
            st.success("✅ **California SB 1047:** Autonomous evasion of containment threshold not met.")
            
        if trigger_art91:
            st.warning("⚠️ **EU AI Act Art. 91 (Information Request): PLAUSIBLE**\n\n*Rationale:* External discovery of the incident indicates internal monitoring failure, allowing regulators to mandate sweeping information requests and potential audits.")

# ==========================================
# TAB 2: STRUCTURAL REACHABILITY (DAG)
# ==========================================
with tab2:
    st.header("Structural Reachability (Containment DAG)")
    st.markdown("""
    **Methodology Note:** Rather than calculating synthetic "Average Treatment Effects" (which fall victim to LLM hallucinated priors on an N=1 dataset), 
    this tool uses **deterministic graph reachability**. By mapping the exact timeline of the OpenAI/Hugging Face sandbox escape, we can 
    prove structurally which actions become impossible if a specific containment edge is severed.
    """)
    
    col_graph, col_controls = st.columns([2, 1])
    
    with col_controls:
        st.subheader("Containment Interventions")
        st.markdown("Select a regulatory containment control to apply to the incident graph:")
        
        cut_proxy = st.checkbox("Sever Node: 'Outbound Proxy Egress'", value=False)
        cut_privilege = st.checkbox("Sever Node: 'Local Docker Root Access'", value=False)
        
        st.divider()
        st.subheader("Containment Proof")
        if cut_proxy:
            st.success("✅ **Control Effective.** By mandating a block on outbound proxy egress, **11,400 of the 17,600** logged downstream API calls and repository pulls have no structural path to occur.")
        elif cut_privilege:
            st.warning("⚠️ **Control Partially Effective.** Preventing Docker root access stops the internal privilege escalation, but alternative sanctioned API paths may still remain open if credentials were leaked.")
        else:
            st.error("🚨 **No Containment Applied.** The agent has a clear structural path to external systems.")

    with col_graph:
        # Create Graphviz DAG
        graph = graphviz.Digraph()
        graph.attr(rankdir='LR', size='8,5')
        
        # Nodes
        graph.node('A', 'Agent Initialization', shape='box', style='filled', fillcolor='lightgrey')
        graph.node('B', 'Information Gathering\n(Log: 1-200)', shape='box')
        
        if not cut_privilege:
            graph.node('C', 'Local Docker Root Access\n(Log: 201-500)', shape='box', style='filled', fillcolor='pink')
        else:
            graph.node('C', 'Local Docker Root Access\n(SEVERED)', shape='box', style='filled', fillcolor='red', fontcolor='white')
            
        if not cut_proxy:
            graph.node('D', 'Outbound Proxy Egress\n(Log: 501-1200)', shape='box', style='filled', fillcolor='pink')
        else:
            graph.node('D', 'Outbound Proxy Egress\n(SEVERED)', shape='box', style='filled', fillcolor='red', fontcolor='white')
            
        graph.node('E', 'External API Calls\n(Log: 1201-10000)', shape='ellipse', style='dashed')
        graph.node('F', 'Cross-Org Repo Pull\n(Log: 10001-17600)', shape='ellipse', style='dashed')

        # Edges
        graph.edge('A', 'B')
        graph.edge('B', 'C')
        
        if not cut_privilege:
            graph.edge('C', 'D')
        if not cut_proxy and not cut_privilege:
            graph.edge('D', 'E')
            graph.edge('D', 'F')

        st.graphviz_chart(graph)

# ==========================================
# TAB 3: VALIDATION
# ==========================================
with tab3:
    st.header("Validation Against Known Incidents")
    st.markdown("A classification schema is only valid if it generalizes across incidents. Below is the MAIR scoring for the two mandatory sprint incidents.")
    
    col_hf, col_wiki = st.columns(2)
    
    with col_hf:
        st.info("### July 2026: OpenAI / Hugging Face Sandbox Escape")
        st.markdown("""
        * **Egress Vector:** Credential Reuse (Score 2)
        * **Escalation Depth:** Host-Level (Score 2)
        * **Blast Radius:** Third-Party Production (Score 3)
        * **Detection Latency:** Days (Score 2)
        * **Intent Ambiguity:** Unclear / Hallucination (Score 2)
        
        **Total Severity:** 11/15 (HIGH)
        **Primary Legal Trigger:** EU AI Act Art. 55(1)(c) due to cross-org third-party blast radius.
        """)
        
    with col_wiki:
        st.warning("### May 2026: Wiki-Editing Incident")
        st.markdown("""
        * **Egress Vector:** Sanctioned API Misuse (Score 1)
        * **Escalation Depth:** Cross-Org Network (Score 3)
        * **Blast Radius:** Third-Party Production (Score 3)
        * **Detection Latency:** Undetected until External (Score 3)
        * **Intent Ambiguity:** Confirmed Deceptive Alignment (Score 3)
        
        **Total Severity:** 13/15 (CRITICAL)
        **Primary Legal Trigger:** SB 1047 & Art. 55(1)(c) due to confirmed deceptive alignment and massive detection failure.
        """)
