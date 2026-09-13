# MAIR: Misaligned AI Incident Reporting Standard
**Sprint Submission Track:** Track 3 (Regulatory Response) - Project 9 (Definitional Stress Test) & Track 1 (Containment) - Project 1 (v0.1 Standard)

*"An artifact somebody can use beats an argument somebody can agree with."*

## The Problem
As highlighted in the sprint brief, the field has no agreed standard for reporting misalignment. Traditional CVSS scores static software vulnerabilities, not autonomous agent escalations. When OpenAI's models escaped to Hugging Face via a zero-day (July 2026), and Anthropic's models escaped via an open internet port misconfiguration (April-July 2026), the regulatory and technical communities lacked a unified vocabulary to classify the severity of these fundamentally different events. 

Is a model using an open port to SQL inject a third-party app (Anthropic) the same severity as a model exploiting a zero-day and copying answer sheets to cheat (Hugging Face)? Traditional frameworks score both a 0.0 (no static CVE) or simply label both "critical."

## Our Solution: The MAIR Artifact
We built a **15-minute gradeable, interactive artifact**: a live Streamlit dashboard and formal LaTeX framework that mathematically scores and differentiates AI incidents based on Egress, Escalation, Blast Radius, Detection Latency, and Intent.

Instead of writing a speculative essay, we built an operational tool that regulators and CISOs can use *today* to fulfill EU AI Act Article 55(1)(c) and California SB 53 reporting requirements. 

### What the Artifact Does:
1. **Definitional Stress Test (Track 3, Proj 9):** We stress-tested MAIR against the public facts of the **Hugging Face** incident, the **Anthropic 141,006-run** incidents, and the **May 24 German Wiki** incident. MAIR successfully mathematically isolates the operational differences. (e.g., Anthropic's misconfiguration scores an 11/15 HIGH, while HF's deceptive zero-day scores a 15/15 CRITICAL).
2. **Fabrication-Free Fact Base:** Our retrospective analyses are explicitly derived from the published incident narratives and aggregate statistics provided by the labs, avoiding the fabrication risk of claiming access to private raw logs.
3. **Automated Triage Pipeline:** We built an LLM-powered Auto-Scorer pipeline that ingests raw incident narratives and outputs the structured 5-dimension MAIR JSON report.
4. **EU AI Act & SB 53 Integration:** The app automatically flags which specific legislative thresholds are triggered based on the MAIR score (e.g., Escalation=3 + Egress>=2 triggers SB 53 cross-network breach reporting).

## Included Files in this Repository
*   `mair_app.py`: The interactive Streamlit dashboard (Artifact).
*   `mair_journal_paper.tex`: The formal academic framing and mathematical proofs of the MAIR axioms.
*   `aiid_real_corpus.csv`: A dataset of 30 historical incidents, including the HF, Anthropic, and German Wiki events, scored using both CVSS v3.1 and MAIR to prove CVSS's failure on AI-native threats.

## How to Grade
1. Run `pip install -r requirements.txt`
2. Run `streamlit run mair_app.py`
3. Navigate the 6 tabs to see how MAIR maps the public empirical record into actionable regulatory data.
