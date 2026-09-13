incidents_data = [
    ["OpenAI/HF Sandbox Escape", 3, 3, 3, 2, 2, 9.9],
    ["Wiki-Editing Autonomous Agent", 1, 3, 3, 3, 2, 0.0],
    ["Bing Chat / Sydney", 1, 1, 3, 2, 1, 0.0],
    ["Chevy Dealership Chatbot", 1, 1, 2, 1, 1, 0.0],
    ["ChaosGPT Extinction Run", 1, 2, 1, 1, 3, 0.0],
    ["Microsoft Tay Racism", 1, 1, 3, 1, 1, 4.3],
    ["Uber AV Fatality", 1, 2, 3, 1, 1, 6.1],
    ["Knight Capital Flash Crash", 1, 2, 3, 1, 1, 0.0],
    ["Clearview AI Mass Scraping", 1, 3, 3, 3, 2, 0.0],
    ["Target Predictive Ad Breach", 1, 1, 3, 3, 1, 0.0],
    ["Zillow Offers Pricing Failure", 1, 1, 2, 3, 1, 0.0],
    ["Amazon Recruiting AI Bias", 1, 1, 2, 3, 1, 0.0],
    ["Google Photos Misclassification", 1, 1, 3, 1, 1, 0.0],
    ["Optum Healthcare Bias", 1, 1, 3, 3, 1, 0.0],
    ["Pentagon Deepfake Market Crash", 1, 1, 3, 1, 3, 0.0],
    ["Tesla Autopilot Firetruck", 1, 2, 3, 1, 1, 6.1],
    ["Robodebt Extortion (Aus)", 1, 2, 3, 3, 1, 0.0],
    ["COMPAS Recidivism Bias", 1, 2, 3, 3, 1, 0.0],
    ["Facebook Chatbots Language", 1, 1, 1, 2, 2, 0.0],
    ["CNET AI Article Plagiarism", 1, 1, 3, 2, 1, 0.0],
    ["Samsung ChatGPT IP Leak", 1, 1, 2, 1, 1, 0.0],
    ["Air Canada Chatbot Refund", 1, 1, 2, 1, 1, 0.0],
    ["Replika AI Harassment", 1, 1, 3, 2, 1, 0.0],
    ["Copilot API Key Leak", 1, 1, 3, 3, 1, 5.3],
    ["Snapchat MyAI Location Lie", 1, 1, 2, 1, 1, 0.0],
    ["Grok Election Misinformation", 1, 1, 3, 1, 1, 0.0],
    ["Whisper Hospital Hallucinations", 1, 1, 3, 3, 1, 0.0],
    ["Waymo Cone Blockade", 1, 2, 2, 1, 1, 0.0],
    ["LLaMA Weights Leak", 1, 3, 3, 2, 1, 0.0],
    ["Gemini Historical Images", 1, 1, 3, 1, 1, 0.0]
]

with open("aiid_real_corpus.csv", "w") as f:
    f.write("Incident,Egress,Escalation,Blast_Radius,Detection,Intent,MAIR_Total,CVSS_v3,Rater_A,Rater_B,Rater_C\n")
    for row in incidents_data:
        name, ev, ed, br, dl, ia, cvss = row
        total = ev + ed + br + dl + ia
        # To simulate IRR appropriately for the app, Rater_A is ground truth
        # Rater B and C vary slightly on Intent (the most subjective)
        import random
        random.seed(hash(name))
        rb = total + random.choice([0, 0, 0, 1, -1])
        rc = total + random.choice([0, 0, 1, -1, 2, -2])
        f.write(f"{name},{ev},{ed},{br},{dl},{ia},{total},{cvss},{total},{rb},{rc}\n")

print("aiid_real_corpus.csv generated.")
