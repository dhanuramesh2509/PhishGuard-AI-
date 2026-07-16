from flask import Flask, render_template, request
import joblib
from feature_extraction import extract_features
from datetime import datetime
from urllib.parse import urlparse
from werkzeug.utils import secure_filename
import csv
import cv2
import os
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from flask import send_file
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Image,
    Table,
    TableStyle
)

from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib import colors
from reportlab.lib.units import inch

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)

# Load trained model
model = joblib.load("MODEL/url_model.pkl")


# -----------------------------
# URL Validation
# -----------------------------
def is_valid_url(url):
    parsed = urlparse(url)
    return parsed.scheme in ("http", "https") and parsed.netloc != ""
# -----------------------------
# Threat Intelligence Engine
# -----------------------------
def generate_threat_report(url, prediction):

    import re

    findings = []

    risk = "🟢 LOW RISK"
    recommendation = "Safe to visit."
    threat_score = 15

    # HTTPS
    if url.startswith("https://"):
        findings.append("✅ HTTPS Enabled")
    else:
        findings.append("❌ Uses HTTP")
        threat_score += 20

    # URL Shortener
    shorteners = [
        "bit.ly",
        "tinyurl",
        "goo.gl",
        "t.co",
        "ow.ly",
        "buff.ly",
        "cutt.ly",
        "rebrand.ly",
        "is.gd"
    ]

    if any(short in url.lower() for short in shorteners):
        findings.append("⚠ URL Shortener Detected")
        threat_score += 25

    # IP Address
    ip_pattern = r"(?:\d{1,3}\.){3}\d{1,3}"

    if re.search(ip_pattern, url):
        findings.append("⚠ Uses IP Address")
        threat_score += 25
    else:
        findings.append("✅ Domain Name Used")

    # Long URL
    if len(url) > 75:
        findings.append("⚠ Long URL")
        threat_score += 15
    else:
        findings.append("✅ Normal URL Length")

    # @ Symbol
    if "@" in url:
        findings.append("⚠ '@' Symbol Found")
        threat_score += 15

    # Hyphen
    if "-" in url:
        findings.append("⚠ Hyphen Found")
        threat_score += 10

    if prediction == "🚨 Phishing Website":
        threat_score += 30

    threat_score = min(threat_score, 100)

    if threat_score >= 75:
        risk = "🔴 HIGH RISK"
        recommendation = "Avoid visiting this website."

    elif threat_score >= 40:
        risk = "🟡 MEDIUM RISK"
        recommendation = "Proceed with caution."

    else:
        risk = "🟢 LOW RISK"
        recommendation = "Website appears safe."

    return risk, findings, recommendation, threat_score


# -----------------------------
# Create scan history file
# -----------------------------
if not os.path.exists("scan_history.csv"):
    with open("scan_history.csv", "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Date & Time", "Website", "Prediction", "Confidence", "Scan Type"])


# -----------------------------
# Home Page
# -----------------------------
@app.route("/")
def home():
    return render_template("index.html")

# -----------------------------
# Predict URL
# -----------------------------
@app.route("/predict", methods=["POST"])
def predict():

    url = request.form["url"].strip()

    if url == "":
        return render_template(
            "result.html",
            prediction="❌ Please enter a URL.",
            confidence=0,
            website="",
            scan_time=datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            color="red",
            message="Please enter a website URL."
        )

    if not is_valid_url(url):
        return render_template(
            "result.html",
            prediction="❌ Invalid URL",
            confidence=0,
            website=url,
            scan_time=datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            color="red",
            message="URL must start with http:// or https://"
        )

    try:

        # Extract Features
        features = extract_features(url)

        # AI Prediction
        prediction = model.predict([features])[0]

        # Confidence Score
        probability = model.predict_proba([features])
        confidence = round(max(probability[0]) * 100, 2)

        # Prediction Result
        if prediction == 1:
            result = "✅ Legitimate Website"
            color = "green"
        else:
            result = "🚨 Phishing Website"
            color = "red"

        # Threat Intelligence
        risk, findings, recommendation, threat_score = generate_threat_report(url, result)

        # Save Scan History
        with open("scan_history.csv", "a", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
                url,
                result,
                f"{confidence}%",
                "🌐 URL Scan"
            ])

        return render_template(
            "result.html",
            prediction=result,
            confidence=confidence,
            website=url,
            scan_time=datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            color=color,
            message="This prediction is based on Machine Learning and Threat Intelligence.",
            risk=risk,
            findings=findings,
            recommendation=recommendation,
            threat_score=threat_score
        )

    except Exception as e:
        return render_template(
            "result.html",
            prediction="❌ Error During Prediction",
            confidence=0,
            website=url,
            scan_time=datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            color="red",
            message=str(e)
        )


# -----------------------------
# Dashboard
# -----------------------------
@app.route("/dashboard")
def dashboard():

    df = pd.read_csv("scan_history.csv")

    total = len(df)

    legitimate = len(
        df[df["Prediction"].str.contains("Legitimate", na=False)]
    )

    phishing = len(
        df[df["Prediction"].str.contains("Phishing", na=False)]
    )

    url_scans = len(
        df[df["Scan Type"].str.contains("URL", na=False)]
    )

    qr_scans = len(
        df[df["Scan Type"].str.contains("QR", na=False)]
    )

    # Average Confidence
    if total > 0:
        average = round(
            df["Confidence"]
            .str.replace("%", "", regex=False)
            .astype(float)
            .mean(),
            2
        )
    else:
        average = 0

    # Generate Pie Chart
    os.makedirs("static/charts", exist_ok=True)

    plt.figure(figsize=(5, 5))

    plt.pie(
        [legitimate, phishing],
        labels=["Legitimate", "Phishing"],
        autopct="%1.1f%%",
        startangle=90
    )

    plt.title("Website Scan Results")

    plt.savefig("static/charts/pie_chart.png")

    plt.close()

    recent_scans = df.tail(10).iloc[::-1].to_dict(orient="records")

    return render_template(
        "dashboard.html",
        total=total,
        legitimate=legitimate,
        phishing=phishing,
        average=average,
        url_scans=url_scans,
        qr_scans=qr_scans,
        recent_scans=recent_scans
    )


# -----------------------------
# Run App
# -----------------------------
@app.route("/about")
def about():
    return render_template("about.html")
@app.route("/qr")
def qr():
    return render_template("qr_scanner.html")
@app.route("/scan_qr", methods=["POST"])
def scan_qr():

    if "qr_image" not in request.files:
        return "No file uploaded."

    file = request.files["qr_image"]

    if file.filename == "":
        return "No file selected."

    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    file.save(filepath)

    detector = cv2.QRCodeDetector()
    image = cv2.imread(filepath)

    data, points, _ = detector.detectAndDecode(image)

    if not data:
        return "❌ No QR Code detected."

    url = data.strip()

    if not is_valid_url(url):
        return "❌ QR Code does not contain a valid URL."

    # Extract Features
    features = extract_features(url)

    # Predict
    prediction = model.predict([features])[0]

    # Confidence
    probability = model.predict_proba([features])
    confidence = round(max(probability[0]) * 100, 2)

    # Result
    if prediction == 1:
        result = "✅ Legitimate Website"
        color = "green"
    else:
        result = "🚨 Phishing Website"
        color = "red"

    # Threat Report
    risk, findings, recommendation, threat_score = generate_threat_report(url, result)

    # Save History
    with open("scan_history.csv", "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
            url,
            result,
            f"{confidence}%",
            "📱 QR Scan"
        ])

    return render_template(
        "result.html",
        prediction=result,
        confidence=confidence,
        website=url,
        scan_time=datetime.now().strftime("%d-%m-%Y %H:%M:%S"),
        color=color,
        message="Prediction generated from QR Code using AI.",
        risk=risk,
        findings=findings,
        recommendation=recommendation,
        threat_score=threat_score
    )
@app.route("/download_report")
def download_report():

    # Read latest scan
    df = pd.read_csv("scan_history.csv")
    latest = df.iloc[-1]

    pdf_file = "scan_report.pdf"

    doc = SimpleDocTemplate(
        pdf_file,
        rightMargin=30,
        leftMargin=30,
        topMargin=30,
        bottomMargin=30
    )

    styles = getSampleStyleSheet()

    # ---------------------------------
    # Custom Styles
    # ---------------------------------

    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontName="Helvetica-Bold",
        fontSize=24,
        alignment=TA_CENTER,
        textColor=colors.white,
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        "SubtitleStyle",
        parent=styles["Heading2"],
        fontName="Helvetica",
        fontSize=12,
        alignment=TA_CENTER,
        textColor=colors.white
    )

    heading_style = ParagraphStyle(
        "HeadingStyle",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=18,
        alignment=TA_CENTER,
        textColor=colors.HexColor("#0B3D91")
    )

    normal_style = ParagraphStyle(
        "NormalStyle",
        parent=styles["BodyText"],
        fontName="Helvetica",
        fontSize=13,
        leading=22,
        textColor=colors.HexColor("#2C3E50")
    )

    story = []

    # ---------------------------------
    # Logo
    # ---------------------------------

    logo_path = "static/images/logo.png"

    if os.path.exists(logo_path):
        logo = Image(logo_path, width=1.3 * inch, height=1.3 * inch)
        logo.hAlign = "CENTER"
        story.append(logo)

    story.append(Spacer(1, 12))

    # ---------------------------------
    # Blue Header
    # ---------------------------------

    header = Table(
        [[Paragraph("<b>PHISHGUARD AI</b>", title_style)]],
        colWidths=[520]
    )

    header.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#0B3D91")),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("TOPPADDING", (0,0), (-1,-1), 15),
        ("BOTTOMPADDING", (0,0), (-1,-1), 15),
    ]))

    story.append(header)

    story.append(Spacer(1,8))

    subtitle = Table(
        [[Paragraph("AI-Powered Cyber Threat Intelligence Platform", subtitle_style)]],
        colWidths=[520]
    )

    subtitle.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#1565C0")),
        ("BOTTOMPADDING",(0,0),(-1,-1),10),
        ("TOPPADDING",(0,0),(-1,-1),10),
    ]))

    story.append(subtitle)

    story.append(Spacer(1,20))

    story.append(
        Paragraph(
            "<b>SECURITY ANALYSIS REPORT</b>",
            heading_style
        )
    )

    story.append(Spacer(1,20))

    # ---------------------------------
    # Result Color
    # ---------------------------------

    prediction = latest["Prediction"]

    if "Legitimate" in prediction:
        pred_color = colors.HexColor("#2ECC71")
    else:
        pred_color = colors.HexColor("#E74C3C")

    # ---------------------------------
    # Report Table
    # ---------------------------------

    data = [
        ["Report Field", "Result"],
        ["Date & Time", latest["Date & Time"]],
        ["Website", latest["Website"]],
        ["Prediction", latest["Prediction"]],
        ["Confidence", latest["Confidence"]],
        ["Scan Type", latest["Scan Type"]]
    ]

    table = Table(data, colWidths=[170,350])

    table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#0B3D91")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),

        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,0),14),

        ("BOTTOMPADDING",(0,0),(-1,0),12),

        ("GRID",(0,0),(-1,-1),1,colors.lightgrey),

        ("BACKGROUND",(0,1),(-1,-1),colors.HexColor("#F8FBFF")),

        ("FONTNAME",(0,1),(-1,-1),"Helvetica"),

        ("FONTSIZE",(0,1),(-1,-1),12),

        ("BOTTOMPADDING",(0,1),(-1,-1),10),

        ("TOPPADDING",(0,1),(-1,-1),10),

        ("BACKGROUND",(1,3),(1,3),pred_color),

        ("TEXTCOLOR",(1,3),(1,3),colors.white),

        ("FONTNAME",(1,3),(1,3),"Helvetica-Bold"),

        ("ALIGN",(0,0),(-1,-1),"CENTER"),

        ("VALIGN",(0,0),(-1,-1),"MIDDLE")

    ]))

    story.append(table)

    story.append(Spacer(1,30))

    # ---------------------------------
    # Footer
    # ---------------------------------

    footer = Table(
        [[Paragraph(
            "<b>Generated by PhishGuard AI</b><br/>"
            "AI-Based Phishing Detection & Cyber Threat Intelligence Platform",
            ParagraphStyle(
                "footer",
                alignment=TA_CENTER,
                textColor=colors.white,
                fontSize=10
            )
        )]],
        colWidths=[520]
    )

    footer.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,-1),colors.HexColor("#0B3D91")),
        ("TOPPADDING",(0,0),(-1,-1),12),
        ("BOTTOMPADDING",(0,0),(-1,-1),12),
    ]))

    story.append(footer)

    # ---------------------------------

    doc.build(story)

    return send_file(pdf_file, as_attachment=True)


import os

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
