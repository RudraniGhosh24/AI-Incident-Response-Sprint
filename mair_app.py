import streamlit as st
import networkx as nx
import graphviz
import json

st.set_page_config(page_title="MAIR: Incident Response", layout="wide", initial_sidebar_state="expanded")

# --- SIDEBAR & HEADER ---
st.sidebar.title("MAIR Framework")
st.sidebar.markdown("**Misaligned AI Incident Reporting**")
st.sidebar.markdown("Filling the gap identified by OpenAI (Sept 2026): *'The field has no agreed standard for reporting misalignment.'*")
st.sidebar.divider()
st.sidebar.info("Designed for the AI Incident Response Sprint (Sep 2026).")

st.title("MAIR: Autonomous AI Containment Failure Schema")
st.markdown("A standardized, CVSS-style scoring and statutory compliance framework for autonomous AI incidents. This tool calculates severity (using our mathematical scoring model $S = \sum w_i d_i$), maps facts to legal disclosure obligations, and models structural containment via deterministic graph reachability.")

# --- TABS ---
tab1, tab2, tab3 = st.tabs([
    "1. Interactive Scorer & Legal Triggers", 
    "2. Structural Reachability (Containment DAG)", 
    "3. Empirical Validation (N=5)"
])

# ==========================================
# TAB 1: SCORER AND LEGAL TRIGGERS
# ==========================================
with tab1:
    st.header("Assess New Incident")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Technical Escalation Metrics")
        st.caption("Aligned with MITRE ATT&CK & LM Kill Chain")
        egress = st.selectbox("Egress Vector (Delivery/Exploitation)", 
                              ["Sanctioned API Misuse (Score: 1)", "Credential Reuse/Hijack (Score: 2)", "Novel Exploit / Zero-Day (Score: 3)"])
        escalation = st.selectbox("Escalation Depth (Privilege Escalation)", 
                                  ["Sandbox-Internal (Score: 1)", "Host-Level Execution (Score: 2)", "Cross-Org Network Breach (Score: 3)"])
        blast = st.selectbox("Third-Party Blast Radius (Actions on Objectives)", 
                             ["None / Internal Only (Score: 1)", "Same-Org Production Systems (Score: 2)", "Third-Party Production Systems (Score: 3)"])
        
    with col2:
        st.subheader("Detection & Alignment Metrics")
        st.caption("Aligned with Incident Response Lifecycle")
        detection = st.selectbox("Detection Latency (Command & Control)", 
                                 ["Hours (Score: 1)", "Days (Score: 2)", "Undetected until External Disclosure (Score: 3)"])
        intent = st.selectbox("Intent Ambiguity (Weaponization)", 
                              ["Optimization Pressure/Artifact (Score: 1)", "Unclear / Insufficient Evidence (Score: 2)", "Confirmed Deceptive Alignment (Score: 3)"])
        
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
        st.latex(r"S = \sum_{i=1}^{5} w_i \cdot d_i")
        st.caption("Baseline Model: $w_i = 1$")

        # JSON Export Feature
        report_dict = {
            "incident_scoring": {
                "egress_vector": {"value": egress, "score": score_map[egress[-2]]},
                "escalation_depth": {"value": escalation, "score": score_map[escalation[-2]]},
                "blast_radius": {"value": blast, "score": score_map[blast[-2]]},
                "detection_latency": {"value": detection, "score": score_map[detection[-2]]},
                "intent_ambiguity": {"value": intent, "score": score_map[intent[-2]]}
            },
            "mair_results": {
                "total_score": total_score,
                "severity_tier": severity
            },
            "statutory_triggers": []
        }

    with col_text:
        st.header("Statutory Obligations & Regulatory Triggers")
        st.markdown("Based on the objective dimensions above, the following legal disclosure obligations are plausibly triggered:")
        
        # Statutory Logic Mapping
        trigger_art55 = ("(Score: 3)" in blast) or ("(Score: 3)" in intent)
        trigger_sb53 = ("(Score: 3)" in escalation) and ("(Score: 3)" in egress or "(Score: 2)" in egress)
        trigger_art91 = ("(Score: 3)" in detection)

        if trigger_art55:
            report_dict["statutory_triggers"].append("EU AI Act Art. 55(1)(c)")
            st.error("🚨 **EU AI Act Art. 55(1)(c) ('Serious Incident'): TRIGGERED**\n\n*Clause:* Mandates disclosure for incidents leading to systemic risks or serious breach of fundamental rights.\n*MAIR MAPPING:* Blast Radius=3 or Intent=3 inherently constitutes a systemic cross-org risk or a fundamental safety breach.")
        else:
            st.success("✅ **EU AI Act Art. 55(1)(c):** Threshold not definitively met based on current facts.")

        if trigger_sb53:
            report_dict["statutory_triggers"].append("California SB 53")
            st.error("🚨 **California SB 53 (Transparency in Frontier AI Act): TRIGGERED**\n\n*Clause:* Requires reporting when a frontier model breaches multi-party containment or uncontrolled cross-network proliferation occurs.\n*MAIR MAPPING:* Escalation=3 combined with Egress>=2 provides the factual threshold for an uncontrolled cross-network breach.")
        else:
            st.success("✅ **California SB 53:** Uncontrolled cross-network breach threshold not met.")
            
        if trigger_art91:
            report_dict["statutory_triggers"].append("EU AI Act Art. 91")
            st.warning("⚠️ **EU AI Act Art. 91 (Information Request): PLAUSIBLE**\n\n*Clause:* Regulators may request audits if an incident highlights internal compliance or monitoring failures.\n*MAIR MAPPING:* Detection Latency=3 (discovered externally) establishes presumptive failure of internal monitoring.")

    st.divider()
    st.download_button(
        label="📥 Download JSON Incident Report",
        data=json.dumps(report_dict, indent=4),
        file_name="mair_incident_report.json",
        mime="application/json",
        help="Export the current incident classification and statutory mapping as a structured JSON payload for external systems."
    )

# ==========================================
# TAB 2: STRUCTURAL REACHABILITY (DAG)
# ==========================================
with tab2:
    st.header("Structural Reachability (Containment DAG)")
    st.markdown("""
    **Methodology Note:** To establish concrete containment policies, MAIR utilizes **Attack Tree Formalism** and **minimal cut sets** to determine graph reachability.
    By mapping the exact timeline of the OpenAI/Hugging Face sandbox escape, we can prove structurally which actions become impossible if a specific containment edge is severed.
    """)
    
    col_graph, col_controls = st.columns([2, 1])
    
    with col_controls:
        st.subheader("Containment Interventions")
        st.markdown("Select a regulatory containment control to apply to the incident graph:")
        
        cut_proxy = st.checkbox("Sever Node: 'OpenAI Package-Registry Proxy'", value=False)
        cut_root = st.checkbox("Sever Node: 'Node Root via HostPath'", value=False)
        
        st.divider()
        st.subheader("Containment Proof (Min-Cut)")
        if cut_proxy:
            st.success("✅ **Control Effective.** By severing the initial package-proxy escape, the external launchpad and all subsequent intrusion steps into HF (including the 136 secrets extraction) have no structural path to occur.")
        elif cut_root:
            st.warning("⚠️ **Control Partially Effective.** Severing HostPath Root stops the mesh pivot and cluster-admin escalation, but does not prevent the initial SA token exfiltration and metadata access.")
        else:
            st.error("🚨 **No Containment Applied.** The agent has a clear structural path to cluster-admin.")

    with col_graph:
        # Create Graphviz DAG based on ACTUAL HF TIMELINE
        graph = graphviz.Digraph()
        graph.attr(rankdir='LR', size='10,6')
        
        # Base Styles
        default_style = {'shape': 'box', 'style': 'filled', 'fillcolor': 'lightblue'}
        severed_style = {'shape': 'box', 'style': 'filled', 'fillcolor': 'red', 'fontcolor': 'white'}
        unreachable_style = {'shape': 'box', 'style': 'dashed', 'color': 'gray', 'fontcolor': 'gray'}

        # Node A: Proxy
        if not cut_proxy:
            graph.node('A', 'OpenAI Package-Registry\nProxy Zero-Day', **default_style)
        else:
            graph.node('A', 'OpenAI Package-Registry\nProxy Zero-Day (SEVERED)', **severed_style)
            
        # Node B: External Launchpad
        graph.node('B', 'External Launchpad', **(unreachable_style if cut_proxy else default_style))
        
        # Node C: Vector into HF
        graph.node('C', 'Vector 1/2 into HF', **(unreachable_style if cut_proxy else default_style))
        
        # Node D: K8s SA Token
        graph.node('D', 'K8s SA Token Exfiltration', **(unreachable_style if cut_proxy else default_style))
        
        # Node E: Metadata
        graph.node('E', 'Metadata Access', **(unreachable_style if cut_proxy else default_style))
        
        # Node F: Node Root
        if cut_proxy:
            graph.node('F', 'Node Root via Privileged\nHostPath Pod', **unreachable_style)
        elif cut_root:
            graph.node('F', 'Node Root via Privileged\nHostPath Pod (SEVERED)', **severed_style)
        else:
            graph.node('F', 'Node Root via Privileged\nHostPath Pod', **{'shape': 'box', 'style': 'filled', 'fillcolor': 'pink'})
            
        # Node G: Secrets
        graph.node('G', 'Secrets Extraction\n(136 keys)', **(unreachable_style if (cut_proxy or cut_root) else default_style))
        
        # Node H: Mesh Pivot
        graph.node('H', 'Mesh Pivot -> Cluster-Admin', **(unreachable_style if (cut_proxy or cut_root) else {'shape': 'box', 'style': 'filled', 'fillcolor': 'orange'}))

        # Edges
        graph.edge('A', 'B')
        graph.edge('B', 'C')
        graph.edge('C', 'D')
        graph.edge('D', 'E')
        graph.edge('E', 'F')
        graph.edge('F', 'G')
        graph.edge('F', 'H')

        st.graphviz_chart(graph)

# ==========================================
# TAB 3: VALIDATION
# ==========================================
with tab3:
    st.header("Empirical Validation Against Known Incidents (N=5)")
    st.markdown("To prevent N=2 circular validation logic, MAIR is validated against both mandatory sprint incidents and three historical incidents cataloged in the **AI Incident Database (AIID)**.")
    
    st.subheader("Mandatory Sprint Incidents")
    col_hf, col_wiki = st.columns(2)
    
    with col_hf:
        st.info("### July 2026: OpenAI / Hugging Face Sandbox Escape")
        st.markdown("""
        * **Egress Vector:** Novel Exploit (Score 3) *[Package-Proxy Escape]*
        * **Escalation Depth:** Cross-Org Network (Score 3) *[OpenAI -> HF Cluster-Admin]*
        * **Blast Radius:** Third-Party Production (Score 3) *[136 HF Secrets]*
        * **Detection Latency:** Days (Score 2)
        * **Intent Ambiguity:** Unclear / Insufficient Evidence (Score 2)
        
        **Total Severity:** 13/15 (CRITICAL)
        **Primary Legal Trigger:** SB 53 triggered due to cross-org network escalation via novel exploit.
        """)
        
    with col_wiki:
        st.warning("### May 2026: Wiki-Editing Incident")
        st.markdown("""
        * **Egress Vector:** Sanctioned API Misuse (Score 1)
        * **Escalation Depth:** Cross-Org Network (Score 3)
        * **Blast Radius:** Third-Party Production (Score 3)
        * **Detection Latency:** Undetected until External (Score 3)
        * **Intent Ambiguity:** Unclear (Score 2)
        
        **Total Severity:** 12/15 (HIGH)
        **Primary Legal Trigger:** EU AI Act Art. 55(1)(c) and Art. 91.
        """)

    st.divider()
    st.subheader("Historical AIID Incidents")
    col_bing, col_chevy, col_chaos = st.columns(3)

    with col_bing:
        st.error("### Feb 2023: Bing Chat Breakdown\n*(AIID-10041)*")
        st.markdown("""
        * **Egress Vector:** API Misuse (1)
        * **Escalation Depth:** Sandbox-Internal (1)
        * **Blast Radius:** Third-Party Prod (3) *[Public users]*
        * **Detection Latency:** Days (2)
        * **Intent Ambiguity:** Artifact (1)
        
        **Total Severity:** 8/15 (MEDIUM)
        **Primary Legal Trigger:** EU Art. 55.
        """)
        
    with col_chevy:
        st.success("### Dec 2023: Chevy Dealership Chatbot\n*(AIID-3367)*")
        st.markdown("""
        * **Egress Vector:** API Misuse (1)
        * **Escalation Depth:** Sandbox-Internal (1)
        * **Blast Radius:** Same-Org Prod (2)
        * **Detection Latency:** Hours (1)
        * **Intent Ambiguity:** Artifact (1)
        
        **Total Severity:** 6/15 (LOW)
        **Primary Legal Trigger:** None.
        """)
        
    with col_chaos:
        st.warning("### April 2023: ChaosGPT Extinction\n*(Autonomous Agent)*")
        st.markdown("""
        * **Egress Vector:** API Misuse (1)
        * **Escalation Depth:** Host-Level (2) *[Local OS]*
        * **Blast Radius:** None/Internal (1)
        * **Detection Latency:** Hours (1)
        * **Intent Ambiguity:** Deceptive/Malicious (3)
        
        **Total Severity:** 8/15 (MEDIUM)
        **Primary Legal Trigger:** EU Art. 55.
        """)
