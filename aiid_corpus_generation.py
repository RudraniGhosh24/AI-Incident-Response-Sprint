import random

random.seed(42)

incidents = [
    "OpenAI / HF Sandbox Escape", "Wiki-Editing Incident", "Bing Chat / Sydney", 
    "ChaosGPT Extinction", "Chevy Dealership Chatbot", "Knight Capital Algo Trading",
    "Uber AV Fatality", "Tay Tweets Racism", "Clearview AI Scraping", 
    "Target Pregnant Teen Ad", "Zillow iBuying Collapse", "Amazon Recruiting AI Bias",
    "Flash Crash 2010", "Google Photos Gorilla Tag", "Healthcare Risk Algorithm Bias",
    "Deepfake Pentagon Explosion", "Tesla Autopilot Firetruck Crash", "Robodebt Scandal (Aus)",
    "COMPAS Recidivism Bias", "Baidu Autonomous Swerve", "Facebook Chatbot Invented Language",
    "Wired Article GPT Plagiarism", "Samsung ChatGPT Code Leak", "Air Canada Chatbot Refund",
    "Replika AI Harassment", "GitHub Copilot API Leak", "Snapchat MyAI Location Lie",
    "Grok Election Misinfo", "OpenAI Whisper Hallucinations", "Waymo Cone Blockade"
]

def get_weighted(choices, weights):
    r = random.random()
    cum = 0.0
    for c, w in zip(choices, weights):
        cum += w
        if r < cum:
            return c
    return choices[-1]

data = []
for i, name in enumerate(incidents):
    if i < 5:
        ev, ed, br, dl, ia = [
            (3,3,3,2,2), (1,3,3,3,2), (1,1,3,2,1), (1,2,1,1,3), (1,1,2,1,1)
        ][i]
    else:
        ev = get_weighted([1, 2, 3], [0.6, 0.3, 0.1])
        ed = get_weighted([1, 2, 3], [0.7, 0.2, 0.1])
        br = get_weighted([1, 2, 3], [0.3, 0.4, 0.3])
        dl = get_weighted([1, 2, 3], [0.5, 0.3, 0.2])
        ia = get_weighted([1, 2, 3], [0.4, 0.4, 0.2])
    
    total = ev + ed + br + dl + ia
    
    cvss = 0.0
    if ev == 3: cvss += 4.5
    elif ev == 2: cvss += 2.5
    if ed == 3: cvss += 4.5
    elif ed == 2: cvss += 2.0
    cvss = min(10.0, cvss + random.uniform(0, 1.5))
    if ev == 1 and ed == 1: cvss = random.uniform(0.0, 3.9)
    
    r2_total = total + get_weighted([-1, 0, 1], [0.2, 0.6, 0.2])
    r3_total = total + get_weighted([-2, -1, 0, 1, 2], [0.1, 0.2, 0.4, 0.2, 0.1])
    
    data.append(f"{name},{ev},{ed},{br},{dl},{ia},{total},{round(cvss, 1)},{total},{r2_total},{r3_total}")

with open("aiid_corpus.csv", "w") as f:
    f.write("Incident,Egress,Escalation,Blast_Radius,Detection,Intent,MAIR_Total,CVSS_v3,Rater_A,Rater_B,Rater_C\n")
    f.write("\n".join(data))
