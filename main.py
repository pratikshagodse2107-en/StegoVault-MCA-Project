import streamlit as st
from db_manager import register_user, verify_user, log_user_activity, get_user_activity, clear_user_activity
st.set_page_config(
    page_title="STEGO VAULT | Secure Login",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "user_email" not in st.session_state:
    st.session_state.user_email = ""
if "auth_mode" not in st.session_state:
    st.session_state.auth_mode = "login"
if "users_db" not in st.session_state:
    st.session_state.users_db = {"admin@stegovault.com": "Admin@123"}
if "logged_out" not in st.session_state:
    st.session_state.logged_out = False

# ==========================================
# 1. जर लॉगिन झाले नसेल तर LOGIN PAGE दाखवा
# ==========================================
if st.session_state.logged_out:
    st.markdown("""
    <style>
    .stApp { background-color: #0e0c18; color: #ffffff; }
    [data-testid="stSidebar"] { display: none; }
    </style>
    <div style="max-width:520px; margin:90px auto; background:#161426; border:1px solid #7c5dfa; border-radius:16px; padding:40px 30px; text-align:center;">
        <div style="font-size:42px;">🛡️</div>
        <h2 style="color:#9d94f7;">STEGO VAULT</h2>
        <h3 style="color:#2ecc71;">Session Securely Terminated</h3>
        <p style="color:#94a3b8;">You have been safely logged out of your secure workspace.</p>
    </div>
    """, unsafe_allow_html=True)
    st.stop()
elif not st.session_state.authenticated:
    st.markdown("""
    <style>
    @import url('https://googleapis.com');
    html, body, [class*="css"] { font-family: 'Poppins', 'Inter', sans-serif; }
    .stApp { background-color: #0e0c18; color: #ffffff; }
    [data-testid="stSidebar"] { display: none; }

    .login-header { text-align: center; padding-top: 10px; padding-bottom: 15px; }
    .shield-badge {
        display: inline-flex; align-items: center; justify-content: center;
        width: 48px; height: 48px; border-radius: 12px;
        background: rgba(124, 93, 250, 0.15); border: 2px solid #9d8df1;
        color: #9d8df1; font-size: 24px; margin-bottom: 10px;
    }
    .brand-title { color: #9d94f7; font-size: 28px; font-weight: 700; letter-spacing: 1.5px; margin: 0; }
    .brand-sub { color: #8f8ca3; font-size: 12px; letter-spacing: 2px; text-transform: uppercase; margin-top: 4px; }
    .welcome-text { color: #ffffff; font-size: 22px; font-weight: 700; margin-top: 22px; margin-bottom: 4px; }
    .signin-sub { color: #9ca3af; font-size: 14px; margin-bottom: 18px; }

    .stTextInput > label { color: #c4c1d4 !important; font-size: 13px !important; font-weight: 500 !important; }
    .stTextInput > div > div > input {
        background-color: #211f2e !important; color: #ffffff !important;
        border: 1px solid #353148 !important; border-radius: 10px !important;
        padding: 14px 16px !important; font-size: 15px !important;
    }
    .stTextInput > div > div > input:focus {
        border-color: #7c5dfa !important; box-shadow: 0 0 0 1px #7c5dfa !important;
    }
    div[data-testid="stFormSubmitButton"] > button, .stButton > button {
        background-color: #6c4ce6 !important; color: #ffffff !important;
        border: none !important; border-radius: 10px !important;
        padding: 14px 20px !important; font-size: 15px !important;
        font-weight: 600 !important; letter-spacing: 1px !important;
        width: 100% !important; margin-top: 10px !important;
    }
    div[data-testid="stFormSubmitButton"] > button:hover, .stButton > button:hover {
        background-color: #7c5dfa !important; box-shadow: 0 4px 20px rgba(108, 76, 230, 0.5) !important;
    }
    </style>
    """, unsafe_allow_html=True)

    _, center_col, _ = st.columns([1, 1.4, 1])
    with center_col:
        if st.session_state.auth_mode == "login":
            st.markdown("""
            <div class="login-header">
                <div class="shield-badge">🛡️</div>
                <div class="brand-title">STEGO VAULT</div>
                <div class="brand-sub">SECURE DIGITAL STEGANOGRAPHY</div>
                <div class="welcome-text">Welcome Back!</div>
                <div class="signin-sub">Sign in to access your secure workspace</div>
            </div>
            """, unsafe_allow_html=True)
            with st.form("login_form"):
                email = st.text_input("Email Address", placeholder="Enter your registered email")
                password = st.text_input("Password", type="password", placeholder="••••••••••••")
                submitted = st.form_submit_button("SIGN IN")

                if submitted:
                    ok, msg = verify_user(email, password)
                    if ok:
                        st.session_state.authenticated = True
                        st.session_state.user_email = email.strip().lower()
                        log_user_activity(st.session_state.user_email, "Authentication", "✅ LOGIN", "User signed in via PBKDF2 verification")
                        st.rerun()
                    else:
                        st.error(f"🚨 {msg}")

            if st.button("Don't have an account?  Create Account", key="go_register"):
                st.session_state.auth_mode = "register"
                st.rerun()

        else:
            st.markdown("""
            <div class="login-header">
                <div class="shield-badge">🛡️</div>
                <div class="brand-title">STEGO VAULT</div>
                <div class="brand-sub">SECURE DIGITAL STEGANOGRAPHY</div>
                <div class="welcome-text">Create Secure Account</div>
                <div class="signin-sub">Register to initialize your encrypted vault</div>
            </div>
            """, unsafe_allow_html=True)

            with st.form("register_form"):
                new_email = st.text_input("Email Address", placeholder="Enter your email")
                new_pass = st.text_input("Create Password (min 6 chars)", type="password", placeholder="Create a strong password")
                confirm_pass = st.text_input("Confirm Password", type="password", placeholder="Re-enter password")
                reg_submit = st.form_submit_button("CREATE ACCOUNT")

                if reg_submit:
                    if new_pass != confirm_pass:
                        st.error("⚠️ Passwords do not match!")
                    else:
                        ok, msg = register_user(new_email, new_pass)
                        if ok:
                            st.success(f"✅ {msg}")
                            st.session_state.auth_mode = "login"
                            st.rerun()
                        else:
                            st.error(f"⚠️ {msg}")

            if st.button("← Back to Sign In"):
                st.session_state.auth_mode = "login"
                st.rerun()
# ==========================================
# 2. लॉगिन झाल्यावर थेट तुमचा dashboard.py चालवा
# ==========================================
else:
    with st.sidebar:
        st.caption(f"👤 User: `{st.session_state.user_email}`")
        if st.button("🚪 Logout", key="main_logout"):
            st.session_state.authenticated = False
            st.session_state.user_email = ""
            st.session_state.logged_out = True

            st.rerun()
        st.markdown("---")

    # dashboard.py मधील st.set_page_config वगळून बाकीचा संपूर्ण कोड रन करा
    with open("dashboard.py", "r", encoding="utf-8") as f:
        dash_code = f.read()
    
    # दुसऱ्यांदा set_page_config रन होऊ नये म्हणून ती ओळ वगळणे
    lines = dash_code.splitlines()
    filtered_lines = []
    skip = False
    for line in lines:
        if line.strip().startswith("st.set_page_config"):
            skip = True
            continue
        if skip and line.strip() == ")":
            skip = False
            continue
        if not skip:
            filtered_lines.append(line)
            
    exec("\n".join(filtered_lines))
