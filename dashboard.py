import streamlit as st
import numpy as np
from PIL import Image
from io import BytesIO
from datetime import datetime
import hashlib, secrets, struct, re, qrcode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from stego_engine import hide_secret_in_image, extract_secret_from_image
from analysis_engine import compute_ssim, generate_difference_image, generate_lsb_bitplane, render_rgb_histogram_image, chi_square_lsb_test
from video_steg import hide_secret_in_video, extract_secret_from_video

# 1. Page Configuration
st.set_page_config(
    page_title="STEGO VAULT | Secure Digital Steganography Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)
# 2. Session State Setup
if "activity_log" not in st.session_state:
    st.session_state.activity_log = []
if "dark_mode" not in st.session_state:
    st.session_state.dark_mode = True
if "last_analysis" not in st.session_state:
    st.session_state.last_analysis = None

from db_manager import log_user_activity, get_user_activity, clear_user_activity
from video_steg import hide_secret_in_video, extract_secret_from_video

def add_log(action: str, status: str, details: str):
    user = st.session_state.get("user_email", "guest@stegovault.com")
    log_user_activity(user, action, status, details)

# 3. Sidebar Navigation (Exact Requested Layout)
with st.sidebar:
    st.markdown("# 🛡️ STEGO VAULT")
    st.caption("Secure Digital Steganography Platform")
    st.markdown("---")
    menu = st.radio(
            "NAVIGATION",
            [
                "📊 Dashboard",
                "🔒 Hide Secret",
                "🔓 Extract Secret",
                "🔬 Security Analysis",
                "🕵️ Steganalysis",
                "📜 History"
            ],
            label_visibility="collapsed"
        )

    
    st.markdown("---")
    st.session_state.dark_mode = st.toggle("🌙 Dark Cybersecurity Mode", value=st.session_state.dark_mode)
    st.info("🛡️ Engine: AES-256 + Random LSB Core")
# 4. Dynamic Dark / Light Cybersecurity Theme Styling
if st.session_state.dark_mode:
    app_bg = "radial-gradient(circle at top right, #1a0b2e, #0a0a0f 65%)"
    text_color = "#f1f5f9"
    sidebar_bg = "#0d0d14"
    card_bg = "rgba(22, 22, 36, 0.92)"
    input_bg = "#161624"
    input_text = "#ffffff"
    h1_color = "#b69cff"
    h2_color = "#00ff88"
    card_title_color = "#c084fc"
    card_val_color = "#00ff88"
else:
    app_bg = "#ffffff"
    text_color = "#0f172a"
    sidebar_bg = "#f1f5f9"
    card_bg = "#f8fafc"
    input_bg = "#ffffff"
    input_text = "#0f172a"
    h1_color = "#5b21b6"
    h2_color = "#047857"
    card_title_color = "#6d28d9"
    card_val_color = "#059669"

st.markdown(f"""
<style>
@import url('https://googleapis.com');

html, body, [class*="css"] {{
    font-family: 'Poppins', 'Inter', sans-serif !important;
}}
.stApp {{
    background: {app_bg} !important;
    color: {text_color} !important;
}}
[data-testid="stSidebar"] {{
    background-color: {sidebar_bg} !important;
    border-right: 1px solid #7947db;
}}
[data-testid="stSidebar"] .stRadio label,
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] p,
[data-testid="stSidebar"] p, [data-testid="stSidebar"] span {{
    color: {text_color} !important;
    font-size: 16px !important;
    font-weight: 500 !important;
}}
[data-testid="stSidebar"] .stRadio div[role="radiogroup"] label:hover p {{
    color: {h2_color} !important;
}}
h1 {{
    color: {h1_color} !important;
    font-weight: 700 !important;
}}
h2, h3 {{
    color: {h2_color} !important;
    font-weight: 600 !important;
}}
p, li, label, .stMarkdown {{
    color: {text_color} !important;
}}
.cyber-card {{
    background: {card_bg} !important;
    border: 1px solid #7947db;
    border-radius: 12px;
    padding: 18px;
    box-shadow: 0 4px 14px rgba(121, 71, 219, 0.15);
    margin-bottom: 15px;
}}
.cyber-card h4 {{
    color: {card_title_color} !important;
    margin: 0;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}
.cyber-card p {{
    color: {card_val_color} !important;
    font-size: 20px;
    font-weight: 700;
    margin: 6px 0 0 0;
}}
.stTextInput > label, .stTextArea > label {{
    color: {text_color} !important;
    font-size: 14px !important;
    font-weight: 500 !important;
}}
.stTextInput > div > div > input, .stTextArea > div > div > textarea {{
    background-color: {input_bg} !important;
    color: {input_text} !important;
    caret-color: {h2_color} !important;
    border: 1px solid #7947db !important;
    border-radius: 8px !important;
    font-size: 15px !important;
}}
.stButton > button {{
    background: linear-gradient(90deg, #7947db, #a855f7);
    color: #ffffff !important;
    border: 1px solid #00ff88;
    border-radius: 8px;
    padding: 10px 22px;
    font-weight: 600;
    width: 100%;
}}
.stButton > button:hover {{
    background: linear-gradient(90deg, #9333ea, #00ff88);
    color: #0a0a0f !important;
    box-shadow: 0 0 15px rgba(0, 255, 136, 0.6);
}}
div[data-testid="stAlert"] > div, [data-baseweb="notification"] {{
    background-color: #1e1b38 !important;
    border: 1px solid #7947db !important;
    color: #f8fafc !important;
}}
div[data-testid="stAlert"] *, [data-baseweb="notification"] * {{
    color: #f8fafc !important;
}}
/* File Uploader आणि Secret Message Textarea गडद/स्पष्ट दिसण्यासाठी */
[data-testid="stFileUploaderDropzone"],
div[data-baseweb="textarea"],
div[data-baseweb="textarea"] textarea {{
    background-color: {input_bg} !important;
    color: {input_text} !important;
    border-color: #7947db !important;
}}
[data-testid="stFileUploaderDropzone"] *,
[data-testid="stFileUploaderDropzone"] button {{
    color: {text_color} !important;
}}
[data-testid="stFileUploaderDropzone"] button {{
    background-color: #26233d !important;
    border: 1px solid #7947db !important;
    color: #ffffff !important;
}}
[data-testid="stFileUploaderDropzone"] small,
[data-testid="stFileUploaderDropzone"] span {{
    color: {text_color} !important;
}}
[data-testid="stFileUploaderDropzone"] button {{
    background-color: #6c4ce6 !important;
    border: 1px solid #7947db !important;
    color: #ffffff !important;
}}
[data-testid="stFileUploaderDropzone"] button * {{
    color: #ffffff !important;
}}
header[data-testid="stHeader"] {{
    background: transparent !important;
}}
textarea, [data-baseweb="base-input"] {{
    background-color: {input_bg} !important;
    color: {input_text} !important;
}}
</style>

""", unsafe_allow_html=True)
def generate_project_qr() -> BytesIO:
    qr = qrcode.QRCode(version=1, box_size=5, border=2)
    qr.add_data("STEGO VAULT | Hide in Plain Sight. | AES-256-GCM + Random LSB Steganography")
    qr.make(fit=True)
    img = qr.make_image(fill_color="#4c1d95", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf
def check_password_strength(password: str):
    if not password:
        return "None", 0
    score = 0
    if len(password) >= 8:
        score += 25
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 25
    if re.search(r"\d", password):
        score += 25
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 25
    labels = {0: "None", 25: "Weak 🔴", 50: "Moderate 🟠", 75: "Strong 🟡", 100: "Military-Grade 🟢"}
    return labels.get(score, "Weak 🔴"), score

# ==========================================
# PAGE 1: DASHBOARD
# ==========================================
if menu == "📊 Dashboard":
    st.markdown("""
    <div style="
        background-color: #13131a;
        border: 1px solid #2d1b4e;
        border-radius: 16px;
        padding: 32px 20px;
        text-align: center;
        box-shadow: 0 8px 25px rgba(0, 0, 0, 0.4);
        margin-bottom: 24px;
    ">
        <div style="
            color: #7c83fd;
            font-size: 36px;
            font-weight: 700;
            letter-spacing: 2px;
            margin-bottom: 6px;
        ">STEGO VAULT</div>
        <div style="
            color: #2ecc71;
            font-size: 20px;
            font-weight: 600;
            margin-bottom: 8px;
        ">Hide in Plain Sight.</div>
        <div style="
            color: #94a3b8;
            font-size: 15px;
            font-weight: 400;
        ">A Python-Based Secure Image Steganography System</div>
    </div>
    """, unsafe_allow_html=True)

    c1, c2, c3, c4 = st.columns(4)
    
    with c1:
        st.markdown('<div class="cyber-card"><h4>🔒 Encryption Core</h4><p>AES-256-GCM</p></div>', unsafe_allow_html=True)
    with c2:
        st.markdown('<div class="cyber-card"><h4>🔑 Key Derivation</h4><p>PBKDF2 (200K)</p></div>', unsafe_allow_html=True)
    with c3:
        st.markdown('<div class="cyber-card"><h4>🖼️ Stego Method</h4><p>LSB Spatial</p></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="cyber-card"><h4>📜 Session Events</h4><p>{len(st.session_state.activity_log)} Logged</p></div>', unsafe_allow_html=True)

    st.markdown("---")
    col_left, col_right = st.columns([2, 1], gap="large")
    with col_left:
        st.markdown("### 🧭 Platform Architecture & Modules")
        st.markdown("""
        * **🔒 Hide Secret:** Encrypt plain text with AES-256 and embed bits invisibly into lossless PNG carriers.
        * **🔓 Extract Secret:** Verify cryptographic tags and extract hidden payloads using your master key.
        * **🔬 Security Analysis:** Inspect pixel distortion (PSNR / MSE), SHA-256 checksums, and capacity metrics.
        * **📜 History:** Monitor real-time audit logs of all encryption and extraction attempts.
        """)
    with col_right:
        st.markdown("### 📱 Project QR Identity")
        st.image(generate_project_qr(), caption="Scan for Platform Metadata", width=210)
# PAGE 3: EXTRACT SECRET
# ==========================================
elif menu == "🔓 Extract Secret":
    st.markdown("# 🔓 Extract Secret Message or File")
    st.markdown("Reconstruct the **password-seeded random pixel path**, decrypt AES-256, and decompress.")
    
    d1, d2 = st.columns(2, gap="large")
    with d1:
        st.markdown("### 🖼️ 1. Upload Stego Image")
        stego_file = st.file_uploader("Upload Encoded PNG Vault", type=["png"], key="ext_img")
        if stego_file:
            stego_preview = Image.open(stego_file)
            sw, sh = stego_preview.size
            st.image(stego_preview, caption="Stego Vault Preview", use_container_width=True)
            st.info(f"📁 `{stego_file.name}` | 💾 `{len(stego_file.getvalue())/1024:.1f} KB` | 📐 `{sw}x{sh} px`")

    with d2:
        st.markdown("### 🔑 2. Decryption Key")
        dec_pass = st.text_input("Master Decryption Key", type="password", placeholder="Enter exact password used during hiding...")
        
        if st.button("🔓 EXTRACT & DECRYPT PAYLOAD"):
            if not stego_file or not dec_pass:
                st.error("⚠️ Please upload a Stego PNG image and enter the password!")
            else:
                try:
                    with st.spinner("Tracing random pixel permutation & verifying AES-GCM tag..."):
                        raw_bytes, out_filename, is_file = extract_secret_from_image(stego_preview, dec_pass)
                        st.session_state["extracted_data"] = {
                            "bytes": raw_bytes,
                            "filename": out_filename,
                            "is_file": is_file
                        }
                    st.snow()
                    add_log("Extract Secret", "✅ SUCCESS", f"Extracted {out_filename} ({len(raw_bytes)} B) from {stego_file.name}")
                except Exception:
                    st.session_state.pop("extracted_data", None)
                    add_log("Extract Secret", "❌ DENIED", f"Auth failed on {stego_file.name}")
                    st.error("🚨 **Access Denied:** Wrong password, tampered image, or no hidden vault!")

        if "extracted_data" in st.session_state:
            ext = st.session_state["extracted_data"]
            st.success("✅ **Authentication Verified! Payload Recovered:**")
            if ext["is_file"]:
                st.info(f"📄 Recovered Hidden File: **`{ext['filename']}`** ({len(ext['bytes']):,} Bytes)")
                st.download_button(
                    label=f"⬇️ DOWNLOAD RECOVERED FILE ({ext['filename']})",
                    data=ext["bytes"],
                    file_name=ext["filename"],
                    mime="application/octet-stream"
                )
            else:
                st.text_area("Decrypted Secret Message", value=ext["bytes"].decode("utf-8", errors="replace"), height=160)

# ==========================================
# PAGE 4: SECURITY ANALYSIS
# ==========================================
elif menu == "🔬 Security Analysis":
    st.markdown("# 🔬 Steganographic & Cryptographic Quality Analysis")
    st.markdown("Evaluate **PSNR, MSE, SSIM, Difference Image**, and **RGB Histogram** integrity.")
    
    if st.session_state.last_analysis and "orig_img_obj" in st.session_state:
        data = st.session_state.last_analysis
        orig_obj = st.session_state["orig_img_obj"]
        stego_obj = st.session_state["stego_img_obj"]
        ssim_val = compute_ssim(orig_obj, stego_obj)
        
        a1, a2, a3, a4 = st.columns(4)
        with a1: st.markdown(f'<div class="cyber-card"><h4>📈 PSNR Quality</h4><p>{data["psnr"]:.2f} dB</p></div>', unsafe_allow_html=True)
        with a2: st.markdown(f'<div class="cyber-card"><h4>🧬 SSIM Index</h4><p>{ssim_val:.6f}</p></div>', unsafe_allow_html=True)
        with a3: st.markdown(f'<div class="cyber-card"><h4>🎯 MSE</h4><p>{data["mse"]:.6f}</p></div>', unsafe_allow_html=True)
        with a4: st.markdown(f'<div class="cyber-card"><h4>📦 Compressed Payload</h4><p>{data["payload_bytes"]} B</p></div>', unsafe_allow_html=True)

        st.markdown("### 🔍 Visual & Pixel-Difference Comparison")
        v1, v2, v3 = st.columns(3)
        with v1:
            st.image(orig_obj, caption="1. Original Cover Image", use_container_width=True)
        with v2:
            st.image(stego_obj, caption="2. Stego Vault Image", use_container_width=True)
        with v3:
            diff_img = generate_difference_image(orig_obj, stego_obj)
            st.image(diff_img, caption="3. Pixel Difference Map (255x Amplified)", use_container_width=True)

        st.markdown("### 📊 RGB Channel Histogram Comparison")
        h1, h2 = st.columns(2)
        with h1:
            st.image(render_rgb_histogram_image(orig_obj, "Original Image"), use_container_width=True)
        with h2:
            st.image(render_rgb_histogram_image(stego_obj, "Stego Vault Image"), use_container_width=True)

        st.markdown("### 🔐 SHA-256 Cryptographic Fingerprints")
        st.text_input("Original Carrier SHA-256 Hash", value=data["orig_hash"], disabled=True)
        st.text_input("Stego Vault SHA-256 Hash", value=data["stego_hash"], disabled=True)
    else:
        st.warning("⚠️ Go to **Hide Secret** and lock a message/file first to generate live quality metrics and histograms!")

elif menu == "🕵️ Steganalysis":
    st.markdown("# 🕵️ Statistical & Visual Steganalysis Lab")
    st.markdown("Demonstrate why **Password-Seeded Random LSB** defeats Chi-Square attacks compared to sequential hiding.")
    
    stego_test_file = st.file_uploader("Upload Any Image (Original, Sequential Stego, or StegoVault PNG)", type=["png", "jpg", "jpeg"], key="steg_lab")
    
    if stego_test_file:
        lab_img = Image.open(stego_test_file).convert("RGB")
        res = chi_square_lsb_test(lab_img)
        
        m1, m2, m3 = st.columns(3)
        with m1: st.markdown(f'<div class="cyber-card"><h4>📐 Chi-Square (χ²)</h4><p>{res["chi_square"]}</p></div>', unsafe_allow_html=True)
        with m2: st.markdown(f'<div class="cyber-card"><h4>⚖️ Normalized χ²/df</h4><p>{res["norm_chi"]}</p></div>', unsafe_allow_html=True)
        with m3: st.markdown(f'<div class="cyber-card"><h4>🛡️ Attack Verdict</h4><p>{res["risk"]}</p></div>', unsafe_allow_html=True)
        
        if "DETECTED" in res["verdict"]:
            st.error(res["verdict"])
        else:
            st.success(res["verdict"])

        col_a, col_b = st.columns(2)
        with col_a:
            st.image(lab_img, caption="Uploaded Suspect Image", use_container_width=True)
        with col_b:
            lsb_vis = generate_lsb_bitplane(lab_img)
            st.image(lsb_vis, caption="Extracted LSB Bit-Plane (Bit 0 Noise Map)", use_container_width=True)
# ==========================================
# PAGE 5: HISTORY
# ==========================================
elif menu == "🔒 Hide Secret":
    st.markdown("# 🔒 Hide Secret Message or File")
    st.markdown("Embed encrypted text or documents inside an **Image (PNG/JPG)** or **Video (MP4/AVI)**.")
    
    c1, c2 = st.columns(2, gap="large")
    with c1:
        st.markdown("### 🖼️ / 🎬 1. Upload Carrier (Image or Video)")
        uploaded_file = st.file_uploader(
            "Select Image (PNG/JPG) or Video (MP4/AVI/MOV — Max 25 MB)",
            type=["png", "jpg", "jpeg", "mp4", "avi", "mov"],
            key="hide_carrier"
        )
        is_video_carrier = False
        max_bytes = 0
        cover_img = None

        if uploaded_file:
            file_ext = uploaded_file.name.split(".")[-1].lower()
            f_bytes = uploaded_file.getvalue()
            f_mb = len(f_bytes) / (1024 * 1024)
            f_kb = len(f_bytes) / 1024

            if file_ext in ["mp4", "avi", "mov"]:
                is_video_carrier = True
                if f_mb > 25.0:
                    st.error(f"🚨 Video size ({f_mb:.1f} MB) exceeds the 25 MB limit! Please upload a smaller clip.")
                else:
                    import cv2, tempfile, os
                    with tempfile.NamedTemporaryFile(delete=False, suffix=f".{file_ext}") as tmp:
                        tmp.write(f_bytes)
                        tmp_path = tmp.name
                    cap = cv2.VideoCapture(tmp_path)
                    w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
                    h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
                    total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
                    cap.release()
                    os.remove(tmp_path)
                    
                    max_bytes = (w * h * 3) // 8 - 64
                    st.video(f_bytes)
                    st.info(f"🎬 `{uploaded_file.name}` | 💾 `{f_mb:.2f} MB / 25 MB` | 📐 `{w}x{h} px` ({total_frames} frames) | 📊 Max: `{max_bytes:,} Bytes`")
            else:
                cover_img = Image.open(uploaded_file)
                w, h = cover_img.size
                max_bytes = (w * h * 3) // 8 - 64
                st.image(cover_img, caption="Carrier Preview", use_container_width=True)
                st.info(f"📁 `{uploaded_file.name}` | 💾 `{f_kb:.1f} KB` | 📐 `{w}x{h} px` | 📊 Max Capacity: `{max_bytes:,} Bytes` (~{max_bytes//3:,} Marathi chars)")

    with c2:
            
        st.markdown("### 📦 2. Choose Payload Type & Key")
        if is_video_carrier:
            payload_type = "📝 Secret Text (English / मराठी)"
            st.caption("🎬 Video Carrier Mode: Supports encrypted text payloads.")
        else:
            payload_type = st.radio(
                "What do you want to hide?",
                [
                    "📝 Secret Text (English / मराठी)",
                    "📄 Secret File (PDF, DOCX, TXT, ZIP)",
                    "🎬 Secret Video (MP4, AVI, MOV — Max 5 MB)"
                ]
            )

        raw_payload = None
        payload_name = "message.txt"
        is_file_mode = False

        if payload_type.startswith("📝"):
            secret_msg = st.text_area("Secret Message", height=120, placeholder="Type confidential message here...")
            if secret_msg:
                raw_payload = secret_msg.encode("utf-8")
                used_bytes = len(raw_payload)
                if max_bytes > 0:
                    st.caption(f"✍️ Length: **{len(secret_msg):,} chars** | 📦 Size: **{used_bytes:,} / {max_bytes:,} Bytes**")
                else:
                    st.caption(f"✍️ Length: **{len(secret_msg):,} chars** | 📦 Size: **{used_bytes:,} Bytes**")

        elif payload_type.startswith("📄"):
            secret_doc = st.file_uploader("Upload Secret Document", type=["pdf", "txt", "docx", "csv", "json", "zip"], key="secret_doc")
            if secret_doc:
                raw_payload = secret_doc.getvalue()
                payload_name = secret_doc.name
                is_file_mode = True
                st.caption(f"📄 File: `{payload_name}` | 📦 Original Size: **{len(raw_payload):,} Bytes** (Will be Zlib-compressed)")

        else:
            secret_vid = st.file_uploader("Upload Secret Video (Max 5 MB)", type=["mp4", "avi", "mov", "webm"], key="secret_vid")
            if secret_vid:
                vid_bytes = secret_vid.getvalue()
                vid_mb = len(vid_bytes) / (1024 * 1024)
                if vid_mb > 5.0:
                    st.error(f"🚨 Video size ({vid_mb:.2f} MB) exceeds the 5.0 MB limit! Please upload a smaller clip.")
                elif uploaded_file and len(vid_bytes) > max_bytes:
                    st.error(f"🚨 Video ({len(vid_bytes):,} B) is larger than this image's capacity ({max_bytes:,} B)! Use a higher-resolution carrier image.")
                else:
                    raw_payload = vid_bytes
                    payload_name = secret_vid.name
                    is_file_mode = True
                    st.caption(f"🎬 Video: `{payload_name}` | 💾 Size: **{vid_mb:.2f} MB / 5.0 MB** ({len(vid_bytes):,} Bytes)")

        if uploaded_file and raw_payload and max_bytes > 0 and len(raw_payload) > (max_bytes * 0.30):
            st.warning("⚠️ Payload exceeds 30% capacity—statistical stealth may decrease.")

        enc_pass = st.text_input("🔑 Master Security Key (Password)", type="password", placeholder="Enter strong password...", key="hide_pass")
        s_label, s_score = check_password_strength(enc_pass)
        st.progress(s_score / 100)
        st.caption(f"🛡️ Key Strength: **{s_label}**")

        if st.button("🛡️ COMPRESS, ENCRYPT & HIDE IN CARRIER"):
            if not uploaded_file or not raw_payload or not enc_pass:
                st.error("⚠️ Please provide a carrier (image/video), secret text/file, and security key!")
            elif is_video_carrier and (len(uploaded_file.getvalue()) / (1024 * 1024)) > 25.0:
                st.error("🚨 Video exceeds the 25 MB limit!")
            else:
                try:
                    if is_video_carrier:
                        with st.spinner("Encrypting & embedding into lossless video frame (FFV1)..."):
                            stego_vid_bytes = hide_secret_in_video(uploaded_file.getvalue(), secret_msg, enc_pass)
                            st.session_state["stego_out"] = stego_vid_bytes
                            st.session_state["stego_out_type"] = "video"
                        st.balloons()
                        add_log("Hide Video", "✅ SUCCESS", f"Locked {len(secret_msg)} chars in video {uploaded_file.name}")
                    else:
                        with st.spinner("Compressing (Zlib) -> Encrypting (AES-256) -> Random Pixel Embedding..."):
                            stego_img, packed_len = hide_secret_in_image(
                                cover_img, raw_payload, enc_pass, filename=payload_name, is_file=is_file_mode
                            )
                            buf = BytesIO()
                            stego_img.save(buf, format="PNG")
                            stego_bytes = buf.getvalue()
                            
                            orig_rgb = cover_img.convert("RGB")
                            stego_rgb = stego_img.convert("RGB")
                            orig_arr = np.array(orig_rgb, dtype=np.float64)
                            steg_arr = np.array(stego_rgb, dtype=np.float64)
                            mse = np.mean((orig_arr - steg_arr) ** 2)
                            psnr = 100.0 if mse == 0 else 20 * np.log10(255.0 / np.sqrt(mse))
                            
                            st.session_state["stego_out"] = stego_bytes
                            st.session_state["stego_out_type"] = "image"
                            st.session_state["orig_img_obj"] = orig_rgb
                            st.session_state["stego_img_obj"] = stego_rgb
                            st.session_state.last_analysis = {
                                "orig_hash": hashlib.sha256(uploaded_file.getvalue()).hexdigest(),
                                "stego_hash": hashlib.sha256(stego_bytes).hexdigest(),
                                "mse": mse,
                                "psnr": psnr,
                                "payload_bytes": packed_len,
                                "raw_bytes": len(raw_payload)
                            }
                        st.balloons()
                        add_log("Hide Secret", "✅ SUCCESS", f"Embedded {payload_name} ({packed_len} B) into {uploaded_file.name}")
                except Exception as e:
                    add_log("Hide Secret", "❌ FAILED", str(e))
                    st.error(f"❌ Error: {str(e)}")

        if "stego_out" in st.session_state:
            st.success("✅ **Secret Locked Successfully!**")
            if st.session_state.get("stego_out_type") == "video":
                st.download_button("⬇️ DOWNLOAD STEGO VIDEO (.AVI)", st.session_state["stego_out"], "stegovault_video.avi", "video/x-msvideo")
            else:
                st.download_button("⬇️ DOWNLOAD STEGO IMAGE (.PNG)", st.session_state["stego_out"], "stegovault_locked.png", "image/png")
elif menu == "📜 History":
    st.markdown("# 📜 Vault Activity & Audit History (SQLite Persistent)")
    user = st.session_state.get("user_email", "guest@stegovault.com")
    logs = get_user_activity(user)
    
    if logs:
        for log in logs:
            st.markdown(f"""
            <div class="cyber-card" style="padding: 12px 18px; margin-bottom: 10px;">
                <span style="color: #9333ea; font-weight: 600;">🕒 {log['Timestamp']}</span> &nbsp;|&nbsp;
                <span style="color: #00ff88; font-weight: 700;">{log['Module']}</span> &nbsp;|&nbsp;
                <span><b>{log['Status']}</b></span><br>
                <span style="font-size: 14px; opacity: 0.9;">{log['Details']}</span>
            </div>
            """, unsafe_allow_html=True)
            
        if st.button("🗑️ CLEAR MY AUDIT HISTORY"):
            clear_user_activity(user)
            st.rerun()
    else:
        st.info("No activity recorded in database for this account yet.")
