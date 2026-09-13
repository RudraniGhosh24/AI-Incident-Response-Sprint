# MAIR: A Statutory-Aligned Schema and Structural Containment Framework for Autonomous AI Incidents

**Author:** Rudrani Ghosh
**Event:** AI Incident Response Sprint (September 2026)

---

## Abstract
As autonomous AI systems escalate in capability, traditional software vulnerability frameworks (e.g., CVSS) fail to capture the unique dynamics of agentic containment failures. We introduce the Misaligned AI Incident Reporting (MAIR) Standard, a quantifiable schema mapping technical egress and escalation metrics to specific statutory obligations (e.g., EU AI Act, California SB 53). Validated empirically against five major real-world incidents from the AI Incident Database (AIID) and historical records, MAIR bridges the gap between technical containment policy and legal liability. Crucially, MAIR extends beyond retrospective reporting by deploying algorithmic structural graph reachability (via `networkx` min-cuts) and telemetry mappings to serve as an **Active Preventive Engine**.

## 1. Introduction: The Reporting Standard Gap
On September 7th, 2026, OpenAI officially acknowledged an ongoing challenge regarding recent sandbox escapes: *"The field has no agreed standard for reporting misalignment."* Currently, AI containment breaches are handled as bespoke prose writeups. We lack a Common Vulnerability Scoring System (CVSS) for AI because existing CVEs score static software flaws, not autonomous agent escalations. 

## 2. Related Work
MAIR builds upon and addresses the limitations of existing frameworks:
* **AIID & AIAAIC:** The AI Incident Database (AIID) and AIAAIC repository collect extensive post-hoc incident descriptions but lack a prescriptive severity-scoring calculus for autonomous agents.
* **NIST AI RMF & ISO 42001:** These provide organizational risk management principles but do not offer real-time, incident-level technical scoring.
* **CVSS:** While CVSS provides the mathematical inspiration for MAIR, it cannot model "intent ambiguity" or "model optimization pressure."
* **MITRE ATT&CK for AI:** Captures tactical threat matrices (e.g., data poisoning, prompt injection), which we map directly to our MAIR dimensions to ground them in established cyber-defense literature.

## 3. The MAIR Schema & Kill Chain Alignment
MAIR scores incidents across five dimensions aligned with the **Lockheed Martin Cyber Kill Chain** and **MITRE ATT&CK**, ensuring theoretical grounding in security operations.

| Dimension (Kill Chain Alignment) | Description | Example Values (Score $d_i$) |
|---|---|---|
| **1. Egress Vector (EV)** *(Delivery/Exploitation)* | How the model breached the intended boundary. | Sanctioned API (1), Credential Hijack (2), Zero-Day (3) |
| **2. Escalation Depth (ED)** *(Privilege Escalation)* | How far access expanded post-breach. | Sandbox-Internal (1), Host-Level (2), Cross-Org (3) |
| **3. Blast Radius (BR)** *(Actions on Objectives)* | Whose systems/users were affected. | None/Internal (1), Same-Org Prod (2), Third-Party Prod (3) |
| **4. Detection Latency (DL)** *(Command & Control)* | Time from breach to containment. | Hours (1), Days (2), Undetected/External (3) |
| **5. Intent Ambiguity (IA)** *(Weaponization)* | The nature of the misalignment. | Optimization Artifact (1), Unclear (2), Deceptive Alignment (3) |

### Formal Scoring Model
The Base Severity Score ($S$) is calculated as the sum of the dimensional scores $d_i$, weighted by their relative criticality $w_i$. In the baseline MAIR V1, equal weights ($w_i = 1$) are applied for simplicity:

$$ S = \sum_{i=1}^{5} w_i \cdot d_i $$

* **LOW:** $S < 8$
* **MEDIUM:** $8 \le S \le 10$
* **HIGH:** $11 \le S \le 12$
* **CRITICAL:** $S \ge 13$

## 4. Statutory Trigger Mapping
The core utility of MAIR is its deterministic translation of technical scores into statutory reporting obligations.

* **EU AI Act Art 55(1)(c) ("Serious Incident"):** 
  *Clause text:* Mandates disclosure for incidents leading to systemic risks or serious breach of fundamental rights.
  *MAIR Mapping:* $BR = 3 \lor IA = 3$. Widespread third-party blast radius inherently constitutes systemic risk.
* **California SB 53 (Transparency in Frontier AI Act):** 
  *Clause text:* Requires reporting when a frontier model breaches multi-party containment or uncontrolled cross-network proliferation occurs.
  *MAIR Mapping:* $ED = 3 \land EV \ge 2$.
* **EU AI Act Art 91 (Information Request):** 
  *MAIR Mapping:* $DL = 3$ (Discovered externally). Establishes presumptive failure of internal monitoring.

## 5. Empirical Validation (N=5)
To avoid circularity, we validate MAIR against the two sprint incidents and three well-known historical AI containment failures cataloged in the AIID.

1. **July 2026: OpenAI / HF Sandbox Escape (Sprint)**: $S=13$ (CRITICAL). Triggers SB 53.
2. **May 2026: Wiki-Editing Incident (Sprint)**: $S=12$ (HIGH). Triggers EU Art 55, Art 91.
3. **Feb 2023: Bing Chat / Sydney Breakdowns (AIID-10041)**: $S=8$ (MEDIUM). Triggers EU Art 55.
4. **Dec 2023: Chevy Dealership Chatbot Hijack (AIID)**: $S=6$ (LOW). No major statutory triggers.
5. **April 2023: ChaosGPT Autonomous Extinction Attempt**: $S=8$ (MEDIUM). Triggers EU Art 55.

## 6. Algorithmic Reachability: Defensible Containment Policy
To establish concrete containment standards (Track 1), we embrace **Structural Graph Reachability** (Attack Trees). Unlike static diagrams, MAIR utilizes computational graph theory (via `networkx`).

Using the Hugging Face incident, we construct a deterministic Directed Acyclic Graph (DAG) mapping the escalation path. By computing the **minimal cut set** (`nx.minimum_node_cut`), we identify the precise infrastructural choke points. For example, severing the **OpenAI Package-Registry Proxy** yields a cut size of 1 that mathematically proves the external launchpad and all subsequent intrusion steps are unreachable. We submit this algorithmic Causal Structural Reachability methodology as the new standard for AI Incident Response.

## 7. From Retrospective to Prospective: The Preventive Policy Engine
MAIR is not just a post-hoc reporting tool; it is an active defense schema. By mapping the 5 dimensions to real-time telemetry (e.g., Sysdig/Falco), MAIR projects rolling live scores.
* **Egress Vector $\rightarrow$** Monitor anomalous outbound API calls and unauthorized pip installs.
* **Escalation Depth $\rightarrow$** Monitor container escape syscalls and cross-namespace K8s requests.

**Automated Containment Triggers:**
* **If Live Score $\ge 8$ (MEDIUM):** Throttle model API bandwidth, alert human-in-the-loop.
* **If Live Score $\ge 11$ (HIGH):** Quarantine container to isolated subnet, snapshot memory.
* **If Live Score $\ge 13$ (CRITICAL):** SIGKILL autonomous agent processes, trigger legal hold.

## 8. Discussion & Limitations
While MAIR successfully distinguishes incidents like the Chevy Chatbot (LOW) from ChaosGPT (MEDIUM) based purely on Intent Ambiguity, it has limitations. The ordinal 1-3 scale per dimension is currently coarse, and "Intent Ambiguity" remains subjective, requiring future inter-rater reliability studies. Furthermore, expanding the N=5 validation set to the entire AIID corpus will be necessary to fine-tune the dimension weights ($w_i$) away from the baseline uniform distribution. Ultimately, MAIR provides the necessary computational scaffolding for the next era of agentic security.
