import streamlit as st
import networkx as nx
import graphviz
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

st.set_page_config(page_title="MAIR: Incident Response", layout="wide", initial_sidebar_state="expanded")

# --- SIDEBAR & HEADER ---
st.sidebar.image("https://upload.wikimedia.org/wikipedia/commons/thumb/c/c2/Shield-security-icon.svg/512px-Shield-security-icon.svg.png", width=50)
st.sidebar.title("MAIR Framework")
st.sidebar.markdown("**Misaligned AI Incident Reporting**")
st.sidebar.divider()
st.sidebar.markdown("### Data Sources")
st.sidebar.markdown("[AI Incident Database (AIID)](https://incidentdatabase.ai/)\n\n[AIAAIC Repository](https://www.aiaaic.org/)")
st.sidebar.divider()
st.sidebar.info("AI Incident Response Sprint (Sep 2026).")

st.title("MAIR: Autonomous AI Containment Schema")
st.markdown("A standardized compliance framework for autonomous AI incidents. Calculates severity ($S = \sum w_i d_i$), maps facts to legal obligations, and models active containment via graph reachability.")

# --- TABS ---
tab1, tab2, tab3, tab4 = st.tabs([
    "1. Interactive Scorer & Radar", 
    "2. NetworkX Containment DAG", 
    "3. Incident Heatmap (N=5)",
    "4. Preventive Engine (Track 1)"
])

# ==========================================
# TAB 1: SCORER AND RADAR
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
    v_egress = score_map[egress[-2]]
    v_escalation = score_map[escalation[-2]]
    v_blast = score_map[blast[-2]]
    v_detection = score_map[detection[-2]]
    v_intent = score_map[intent[-2]]
    total_score = v_egress + v_escalation + v_blast + v_detection + v_intent
    
    st.divider()
    
    # Severity Metric & Radar
    col_score, col_radar, col_text = st.columns([1, 1.5, 2])
    with col_score:
        severity = "LOW"
        color = "green"
        if total_score >= 8: severity, color = "MEDIUM", "orange"
        if total_score >= 11: severity, color = "HIGH", "red"
        if total_score >= 13: severity, color = "CRITICAL", "purple"
        
        st.metric(label="MAIR Severity Score", value=f"{total_score} / 15", delta=severity, delta_color="inverse" if color in ["red", "purple"] else "normal")
        st.latex(r"S = \sum_{i=1}^{5} w_i \cdot d_i")
        st.caption("Baseline Model: $w_i = 1$")
        
        report_dict = {
            "incident_scoring": {
                "egress": v_egress, "escalation": v_escalation, "blast": v_blast, 
                "detection": v_detection, "intent": v_intent, "total": total_score, "tier": severity
            },
            "statutory_triggers": []
        }
        
        st.download_button("📥 Export JSON Report", data=json.dumps(report_dict, indent=4), file_name="mair_report.json", mime="application/json")

    with col_radar:
        categories = ['Egress', 'Escalation', 'Blast Radius', 'Detection', 'Intent']
        fig = go.Figure()
        fig.add_trace(go.Scatterpolar(
            r=[v_egress, v_escalation, v_blast, v_detection, v_intent, v_egress],
            theta=categories + [categories[0]],
            fill='toself',
            name='Current Incident',
            line_color='red' if severity in ['HIGH', 'CRITICAL'] else 'orange' if severity == 'MEDIUM' else 'green'
        ))
        fig.update_layout(
            polar=dict(radialaxis=dict(visible=True, range=[0, 3])),
            showlegend=False,
            margin=dict(l=20, r=20, t=20, b=20),
            height=250
        )
        st.plotly_chart(fig, use_container_width=True)

    with col_text:
        st.subheader("Regulatory Triggers")
        trigger_art55 = (v_blast == 3) or (v_intent == 3)
        trigger_sb53 = (v_escalation == 3) and (v_egress >= 2)
        trigger_art91 = (v_detection == 3)

        if trigger_art55:
            st.error("🚨 **EU AI Act Art. 55(1)(c): TRIGGERED**\nBlast Radius=3 or Intent=3 inherently constitutes a systemic risk.")
        else:
            st.success("✅ **EU AI Act Art. 55(1)(c):** Not triggered.")

        if trigger_sb53:
            st.error("🚨 **California SB 53: TRIGGERED**\nEscalation=3 with Egress>=2 triggers cross-network breach reporting.")
        else:
            st.success("✅ **California SB 53:** Not triggered.")
            
        if trigger_art91:
            st.warning("⚠️ **EU AI Act Art. 91: PLAUSIBLE**\nDetection=3 establishes presumptive failure of internal monitoring.")
        else:
            st.success("✅ **EU AI Act Art. 91:** Not triggered.")

# ==========================================
# TAB 2: STRUCTURAL REACHABILITY (DAG)
# ==========================================
with tab2:
    st.header("Algorithmic Containment (NetworkX)")
    st.markdown("Unlike static flowcharts, MAIR uses `networkx` to calculate **structural reachability** and **minimum cut sets** dynamically. By severing nodes, you recalculate the agent's attack paths in real-time.")
    
    col_graph, col_controls = st.columns([2, 1])
    
    # Initialize NetworkX Graph
    G = nx.DiGraph()
    edges = [
        ('A: Proxy Zero-Day', 'B: Ext. Launchpad'),
        ('B: Ext. Launchpad', 'C: Vector into HF'),
        ('C: Vector into HF', 'D: SA Token Exfil'),
        ('D: SA Token Exfil', 'E: Metadata Access'),
        ('E: Metadata Access', 'F: Node Root (HostPath)'),
        ('F: Node Root (HostPath)', 'G: Secrets Extraction'),
        ('F: Node Root (HostPath)', 'H: Cluster-Admin Pivot')
    ]
    G.add_edges_from(edges)
    
    with col_controls:
        st.subheader("Containment Simulator")
        nodes_to_sever = st.multiselect(
            "Select infrastructure nodes to sever (Quarantine):", 
            options=list(G.nodes()), 
            default=[]
        )
        
        # Algorithmic Analysis
        st.divider()
        st.subheader("NetworkX Analysis")
        
        # Min cut calculation
        try:
            min_cut = nx.minimum_node_cut(G, 'A: Proxy Zero-Day', 'H: Cluster-Admin Pivot')
            st.info(f"**Vulnerability Analysis:** The mathematical minimum node cut set to prevent Cluster-Admin Pivot from the Proxy is size **{len(min_cut)}**: `{min_cut}`")
        except nx.NetworkXError:
            st.info("No path exists to calculate min-cut.")
            
        # Reachability simulation
        G_sim = G.copy()
        for node in nodes_to_sever:
            G_sim.remove_node(node)
            
        reachable = set()
        if 'A: Proxy Zero-Day' in G_sim.nodes():
            try:
                reachable = nx.descendants(G_sim, 'A: Proxy Zero-Day')
            except nx.NetworkXError:
                pass
            reachable.add('A: Proxy Zero-Day')
            
        if 'H: Cluster-Admin Pivot' in reachable:
            st.error("🚨 **Containment Failed.** Agent still has a structural path to Cluster-Admin.")
        else:
            st.success("✅ **Containment Effective.** Cluster-Admin is no longer reachable from the entrypoint.")

    with col_graph:
        dot = graphviz.Digraph()
        dot.attr(rankdir='LR', size='10,6')
        
        for node in G.nodes():
            if node in nodes_to_sever:
                dot.node(node, style='filled', fillcolor='#ff4b4b', fontcolor='white')
            elif node in reachable:
                dot.node(node, style='filled', fillcolor='#4b7bff', fontcolor='white')
            else:
                dot.node(node, style='dashed', color='gray', fontcolor='gray')
                
        for u, v in G.edges():
            if u not in nodes_to_sever and v not in nodes_to_sever:
                dot.edge(u, v)
                
        st.graphviz_chart(dot)

# ==========================================
# TAB 3: HEATMAP VALIDATION
# ==========================================
with tab3:
    st.header("Empirical Validation (N=5)")
    st.markdown("We validate MAIR against mandatory sprint incidents and three historical **AI Incident Database (AIID)** records. The heatmap below immediately identifies severity clusters.")
    
    # Dataframe
    data = {
        'Incident': ['HF Sandbox Escape', 'Wiki-Editing', 'Bing Chat / Sydney', 'ChaosGPT', 'Chevy Chatbot'],
        'Egress': [3, 1, 1, 1, 1],
        'Escalation': [3, 3, 1, 2, 1],
        'Blast Radius': [3, 3, 3, 1, 2],
        'Detection': [2, 3, 2, 1, 1],
        'Intent': [2, 2, 1, 3, 1]
    }
    df = pd.DataFrame(data).set_index('Incident')
    df['Total Severity'] = df.sum(axis=1)
    
    col_heat, col_table = st.columns([1.5, 1])
    
    with col_heat:
        # Heatmap (drop total severity for the heatmap)
        fig_heat = px.imshow(
            df.drop(columns=['Total Severity']), 
            color_continuous_scale='Reds',
            range_color=[1, 3],
            aspect="auto",
            title="MAIR Dimension Heatmap"
        )
        fig_heat.update_xaxes(side="top")
        st.plotly_chart(fig_heat, use_container_width=True)
        
    with col_table:
        st.dataframe(
            df.style.background_gradient(subset=['Total Severity'], cmap='Reds'),
            use_container_width=True
        )
        st.markdown("""
        **Key Insights:**
        * High-severity incidents cluster heavily on **Escalation** and **Blast Radius**.
        * The Chevy Chatbot and ChaosGPT differ drastically in **Intent** and **Escalation**, accurately reflecting why ChaosGPT triggers EU Art 55 despite lower blast radius.
        """)

# ==========================================
# TAB 4: PREVENTIVE ENGINE
# ==========================================
with tab4:
    st.header("Forward-Looking: Active Prevention Engine (Track 1)")
    st.markdown("MAIR isn't just a retrospective filing cabinet. By mapping MAIR dimensions to real-time telemetry, it becomes an automated **Active Containment Engine**.")
    
    st.subheader("1. Real-Time Telemetry Mapping")
    rules_df = pd.DataFrame({
        "MAIR Dimension": ["Egress Vector", "Escalation Depth", "Blast Radius", "Detection Latency", "Intent Ambiguity"],
        "Preventive Signal to Monitor (Sysdig/Falco)": [
            "Anomalous outbound API calls, unapproved pip installs",
            "Container escape syscalls, cross-namespace K8s requests",
            "Data exfiltration volume spikes, external DB queries",
            "Heartbeat timeouts from internal safety monitors",
            "Hidden chain-of-thought divergence, deception heuristics"
        ]
    })
    st.table(rules_df)
    
    st.subheader("2. Automated Containment Policy")
    st.info("""
    Instead of waiting for human review, infrastructure can trigger automated responses based on rolling MAIR score projections:
    * **If Live Score >= 8 (MEDIUM):** Throttle model API bandwidth, alert human-in-the-loop.
    * **If Live Score >= 11 (HIGH):** Quarantine container to isolated subnet, snapshot memory.
    * **If Live Score >= 13 (CRITICAL):** SIGKILL autonomous agent processes, trigger legal/compliance hold.
    """)
