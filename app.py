import streamlit as st
import pandas as pd
import plotly.express as px
import re

# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Cybersecurity Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# PROFESSIONAL LIGHT THEME
# ============================================================

st.markdown("""
<style>

.main {
    background-color: #f7f9fc;
    color: #1f2937;
}

.stMarkdown p,
.stMarkdown li,
.stMarkdown span,
.stMarkdown strong {
    color: #1f2937;
}

h1, h2, h3, h4 {
    color: #111827 !important;
    font-weight: 700;
}

.stCaption,
[data-testid="stCaptionContainer"] {
    color: #4b5563 !important;
}

[data-testid="stMetric"] {
    background-color: #ffffff;
    border: 1px solid #d1d5db;
    padding: 15px;
    border-radius: 10px;
}

[data-testid="stMetricLabel"] {
    color: #4b5563 !important;
}

[data-testid="stMetricValue"] {
    color: #111827 !important;
    font-weight: 700;
}

section[data-testid="stSidebar"] {
    background-color: #111827;
}

section[data-testid="stSidebar"] .stMarkdown p,
section[data-testid="stSidebar"] .stMarkdown span,
section[data-testid="stSidebar"] .stMarkdown strong,
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] div {
    color: #f9fafb !important;
}

section[data-testid="stSidebar"] div[role="radiogroup"] label {
    color: #f9fafb !important;
}

input,
textarea {
    color: #111827 !important;
    background-color: #ffffff !important;
}

div[data-baseweb="select"] {
    background-color: #ffffff !important;
}

div[data-baseweb="select"] * {
    color: #111827 !important;
}

div[role="listbox"] {
    background-color: #ffffff !important;
}

div[role="option"] {
    color: #111827 !important;
}

.stButton > button {
    border-radius: 8px;
    font-weight: 600;
    color: #111827 !important;
    background-color: #ffffff !important;
    border: 1px solid #d1d5db;
}

.stButton > button:hover {
    border-color: #111827;
}

[data-testid="stDataFrame"] {
    background-color: #ffffff;
}

[data-testid="stAlert"] p {
    color: #1f2937 !important;
}

.security-banner {
    padding: 15px;
    border-radius: 10px;
    background-color: #ffffff;
    border: 1px solid #d1d5db;
    margin-bottom: 20px;
    color: #1f2937 !important;
}

.security-banner b {
    color: #111827 !important;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
}

</style>
""", unsafe_allow_html=True)


# ============================================================
# DATA LOADING
# ============================================================

DATA_FILE = "data/threat_intelligence_dataset.csv"


@st.cache_data
def load_data():

    data = pd.read_csv(DATA_FILE)

    data["timestamp"] = pd.to_datetime(
        data["timestamp"],
        errors="coerce"
    )

    data["first_seen"] = pd.to_datetime(
        data["first_seen"],
        errors="coerce"
    )

    data["last_seen"] = pd.to_datetime(
        data["last_seen"],
        errors="coerce"
    )

    return data


df = load_data()


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def validate_indicator(value, indicator_type):

    value = str(value).strip()

    # ---------------- IP ----------------

    if indicator_type == "IP":

        pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

        if not re.match(pattern, value):
            return False

        return all(
            0 <= int(part) <= 255
            for part in value.split(".")
        )

    # ---------------- DOMAIN ----------------

    if indicator_type == "Domain":

        return bool(
            re.match(
                r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
                value
            )
        )

    # ---------------- URL ----------------

    if indicator_type == "URL":

        return bool(
            re.match(
                r"^https?://",
                value
            )
        )

    # ---------------- SHA-256 ----------------

    if indicator_type == "SHA-256":

        return bool(
            re.match(
                r"^[a-fA-F0-9]{64}$",
                value
            )
        )

    # ---------------- CVE ----------------

    if indicator_type == "CVE":

        return bool(
            re.match(
                r"^CVE-\d{4}-\d+$",
                value
            )
        )

    return len(value) > 0


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title(
    "🛡️ Cybersecurity Center"
)

st.sidebar.caption(
    "Threat Intelligence & Security Awareness Platform"
)

page = st.sidebar.radio(
    "Navigation",
    [
        "Executive Dashboard",
        "Threat Intelligence",
        "IOC Analyzer",
        "Vulnerability Awareness",
        "SOC Investigation",
        "Awareness Center",
        "Awareness Quiz"
    ]
)

st.sidebar.markdown("---")

st.sidebar.info(
    "Defensive cybersecurity demonstration using "
    "synthetic threat-intelligence data."
)

st.sidebar.markdown("---")

st.sidebar.caption(
    "Local analysis only • No external indicator connections"
)


# ============================================================
# EXECUTIVE DASHBOARD
# ============================================================

if page == "Executive Dashboard":

    st.title(
        "🛡️ Cybersecurity Awareness & Threat Intelligence Dashboard"
    )

    st.markdown(
        """
        <div class="security-banner">
            <b>Defensive Security Platform</b><br>
            Monitor synthetic threat intelligence, analyze indicators,
            prioritize risks, track vulnerabilities, and improve
            cybersecurity awareness.
        </div>
        """,
        unsafe_allow_html=True
    )

    total = len(df)

    critical = len(
        df[df["severity"] == "Critical"]
    )

    high = len(
        df[df["severity"] == "High"]
    )

    active = len(
        df[
            df["status"].isin(
                [
                    "NEW",
                    "UNDER_REVIEW",
                    "MONITORING"
                ]
            )
        ]
    )

    open_investigations = len(
        df[
            df["status"].isin(
                [
                    "NEW",
                    "UNDER_REVIEW"
                ]
            )
        ]
    )

    avg_confidence = round(
        df["confidence_score"].mean(),
        1
    )

    vulnerabilities = df["cve_id"].notna().sum()

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Total Threat Records",
        f"{total:,}"
    )

    col2.metric(
        "Critical Threats",
        critical
    )

    col3.metric(
        "High Threats",
        high
    )

    col4.metric(
        "Active Indicators",
        active
    )

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Open Investigations",
        open_investigations
    )

    col2.metric(
        "Average Confidence",
        f"{avg_confidence}%"
    )

    col3.metric(
        "Vulnerabilities Tracked",
        f"{vulnerabilities:,}"
    )

    st.markdown("---")

    daily = (
        df.set_index("timestamp")
        .resample("D")
        .size()
        .reset_index(name="Threats")
    )

    fig = px.line(
        daily,
        x="timestamp",
        y="Threats",
        title="Threat Observations Over Time",
        markers=True
    )

    fig.update_layout(
        template="plotly_white",
        height=400
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    col1, col2 = st.columns(2)

    with col1:

        severity_counts = (
            df["severity"]
            .value_counts()
            .reset_index()
        )

        severity_counts.columns = [
            "Severity",
            "Count"
        ]

        fig = px.bar(
            severity_counts,
            x="Severity",
            y="Count",
            title="Threats by Severity",
            text="Count"
        )

        fig.update_layout(
            template="plotly_white"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    with col2:

        category_counts = (
            df["threat_category"]
            .value_counts()
            .reset_index()
        )

        category_counts.columns = [
            "Category",
            "Count"
        ]

        fig = px.pie(
            category_counts,
            names="Category",
            values="Count",
            title="Threat Category Distribution"
        )

        fig.update_layout(
            template="plotly_white"
        )

        st.plotly_chart(
            fig,
            use_container_width=True
        )

    indicator_counts = (
        df["indicator_type"]
        .value_counts()
        .reset_index()
    )

    indicator_counts.columns = [
        "Indicator Type",
        "Count"
    ]

    fig = px.bar(
        indicator_counts,
        x="Indicator Type",
        y="Count",
        title="IOC Distribution"
    )

    fig.update_layout(
        template="plotly_white"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )

    st.subheader(
        "Recent Threat Observations"
    )

    recent = (
        df.sort_values(
            "timestamp",
            ascending=False
        )
        .head(15)
    )

    st.dataframe(
        recent[
            [
                "threat_id",
                "threat_name",
                "threat_category",
                "indicator_type",
                "severity",
                "risk_score",
                "confidence_score",
                "status"
            ]
        ],
        use_container_width=True,
        hide_index=True
    )


# ============================================================
# THREAT INTELLIGENCE
# ============================================================

elif page == "Threat Intelligence":

    st.title(
        "🔎 Threat Intelligence Explorer"
    )

    st.caption(
        "Search, filter and analyze local threat-intelligence observations."
    )

    col1, col2, col3 = st.columns(3)

    with col1:

        category = st.selectbox(
            "Threat Category",
            ["All"]
            + sorted(
                df["threat_category"]
                .dropna()
                .unique()
            )
        )

    with col2:

        severity = st.selectbox(
            "Severity",
            ["All"]
            + sorted(
                df["severity"]
                .dropna()
                .unique()
            )
        )

    with col3:

        indicator = st.selectbox(
            "Indicator Type",
            ["All"]
            + sorted(
                df["indicator_type"]
                .dropna()
                .unique()
            )
        )

    search = st.text_input(
        "Search Threat ID, Threat Name or Indicator"
    )

    filtered = df.copy()

    if category != "All":

        filtered = filtered[
            filtered["threat_category"]
            == category
        ]

    if severity != "All":

        filtered = filtered[
            filtered["severity"]
            == severity
        ]

    if indicator != "All":

        filtered = filtered[
            filtered["indicator_type"]
            == indicator
        ]

    if search:

        mask = (
            filtered["threat_id"]
            .astype(str)
            .str.contains(
                search,
                case=False,
                na=False
            )
            |
            filtered["threat_name"]
            .astype(str)
            .str.contains(
                search,
                case=False,
                na=False
            )
            |
            filtered["indicator_value"]
            .astype(str)
            .str.contains(
                search,
                case=False,
                na=False
            )
        )

        filtered = filtered[mask]

    st.metric(
        "Matching Threat Records",
        f"{len(filtered):,}"
    )

    st.dataframe(
        filtered[
            [
                "threat_id",
                "timestamp",
                "threat_name",
                "threat_category",
                "indicator_type",
                "indicator_value",
                "severity",
                "risk_score",
                "confidence_score",
                "status"
            ]
        ],
        use_container_width=True,
        hide_index=True
    )

    st.subheader(
        "Risk Score Distribution"
    )

    fig = px.histogram(
        filtered,
        x="risk_score",
        nbins=20,
        title="Risk Score Distribution"
    )

    fig.update_layout(
        template="plotly_white"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


# ============================================================
# IOC ANALYZER
# ============================================================

elif page == "IOC Analyzer":

    st.title(
        "🔍 IOC Analyzer"
    )

    st.info(
        "Indicators are analyzed as data only. "
        "This application never connects to, visits, or probes "
        "submitted IP addresses, domains, URLs, or hashes."
    )

    indicator_type = st.selectbox(
        "Indicator Type",
        [
            "IP",
            "Domain",
            "URL",
            "SHA-256",
            "CVE"
        ]
    )

    value = st.text_input(
        "Enter Indicator",
        placeholder="Example: 192.0.2.10"
    )

    if st.button(
        "Analyze Indicator",
        type="primary"
    ):

        if not value:

            st.warning(
                "Please enter an indicator."
            )

        else:

            valid = validate_indicator(
                value,
                indicator_type
            )

            if valid:

                st.success(
                    "Indicator format is valid."
                )

            else:

                st.error(
                    "Indicator format is invalid."
                )

            matches = df[
                (
                    df["indicator_type"]
                    == indicator_type
                )
                &
                (
                    df["indicator_value"]
                    .astype(str)
                    .str.lower()
                    == value.lower()
                )
            ]

            st.subheader(
                "Local Intelligence Results"
            )

            if len(matches) == 0:

                st.info(
                    "No matching record was found "
                    "in the local dataset."
                )

            else:

                record = matches.iloc[0]

                col1, col2, col3 = st.columns(3)

                col1.metric(
                    "Risk Score",
                    record["risk_score"]
                )

                col2.metric(
                    "Confidence",
                    f'{record["confidence_score"]}%'
                )

                col3.metric(
                    "Severity",
                    record["severity"]
                )

                st.dataframe(
                    matches,
                    use_container_width=True,
                    hide_index=True
                )

                st.subheader(
                    "Recommended Defensive Actions"
                )

                st.markdown("""
                - Review internal authorized security telemetry.
                - Check related indicators.
                - Review relevant email, endpoint or network logs.
                - Document analyst findings.
                - Escalate confirmed incidents through the
                  organization's incident-response process.
                """)


# ============================================================
# VULNERABILITY AWARENESS
# ============================================================

elif page == "Vulnerability Awareness":

    st.title(
        "🛡️ Vulnerability Awareness"
    )

    st.caption(
        "Track synthetic CVE observations and prioritize defensive review."
    )

    vulnerabilities = df[
        df["cve_id"].notna()
    ].copy()

    st.metric(
        "Vulnerabilities Tracked",
        f"{len(vulnerabilities):,}"
    )

    col1, col2 = st.columns(2)

    with col1:

        severity_filter = st.multiselect(
            "Filter Severity",
            sorted(
                vulnerabilities["severity"]
                .dropna()
                .unique()
            ),
            default=sorted(
                vulnerabilities["severity"]
                .dropna()
                .unique()
            )
        )

    with col2:

        cve_search = st.text_input(
            "Search CVE"
        )

    filtered = vulnerabilities[
        vulnerabilities["severity"]
        .isin(severity_filter)
    ]

    if cve_search:

        filtered = filtered[
            filtered["cve_id"]
            .astype(str)
            .str.contains(
                cve_search,
                case=False,
                na=False
            )
        ]

    display_vulnerabilities = (
        filtered[
            [
                "cve_id",
                "threat_category",
                "severity",
                "risk_score",
                "confidence_score",
                "description"
            ]
        ]
        .drop_duplicates()
    )

    st.dataframe(
        display_vulnerabilities,
        use_container_width=True,
        hide_index=True
    )

    st.subheader(
        "Vulnerability Severity Distribution"
    )

    counts = (
        vulnerabilities["severity"]
        .value_counts()
        .reset_index()
    )

    counts.columns = [
        "Severity",
        "Count"
    ]

    fig = px.bar(
        counts,
        x="Severity",
        y="Count",
        title="Tracked Vulnerabilities by Severity"
    )

    fig.update_layout(
        template="plotly_white"
    )

    st.plotly_chart(
        fig,
        use_container_width=True
    )


# ============================================================
# SOC INVESTIGATION
# ============================================================

elif page == "SOC Investigation":

    st.title(
        "🚨 SOC Investigation View"
    )

    st.caption(
        "Prioritize observations for defensive security investigation."
    )

    status_filter = st.multiselect(
        "Investigation Status",
        sorted(
            df["status"]
            .dropna()
            .unique()
        ),
        default=[
            "NEW",
            "UNDER_REVIEW",
            "MONITORING"
        ]
    )

    soc_df = (
        df[
            df["status"]
            .isin(status_filter)
        ]
        .sort_values(
            "risk_score",
            ascending=False
        )
    )

    st.metric(
        "Investigation Candidates",
        f"{len(soc_df):,}"
    )

    st.dataframe(
        soc_df[
            [
                "threat_id",
                "threat_name",
                "indicator_type",
                "indicator_value",
                "severity",
                "risk_score",
                "confidence_score",
                "source_name",
                "status"
            ]
        ].head(50),
        use_container_width=True,
        hide_index=True
    )

    st.subheader(
        "SOC Defensive Workflow"
    )

    st.markdown("""
    **1. Detect** → Identify a security observation.

    **2. Validate** → Confirm indicator format and evidence quality.

    **3. Enrich** → Review category, source, confidence and related indicators.

    **4. Prioritize** → Consider risk and confidence together.

    **5. Investigate** → Review authorized internal security telemetry.

    **6. Respond** → Escalate, monitor, resolve or mark false positive.

    **7. Document** → Record the investigation outcome.
    """)

    st.subheader(
        "Recommended Defensive Actions"
    )

    st.markdown("""
    - Review authorized security telemetry.
    - Validate observations against internal logs.
    - Check related indicators and observations.
    - Review email, endpoint or network security telemetry.
    - Prioritize high-risk and high-confidence observations.
    - Document investigation decisions.
    - Escalate confirmed incidents through the organization's
      incident-response process.
    """)


# ============================================================
# AWARENESS CENTER
# ============================================================

elif page == "Awareness Center":

    st.title(
        "🎓 Cybersecurity Awareness Center"
    )

    st.caption(
        "Practical defensive security awareness guidance."
    )

    modules = {

        "Phishing": [
            "Check the sender carefully.",
            "Be cautious with urgent requests.",
            "Never provide credentials through suspicious links.",
            "Verify unexpected payment or account requests.",
            "Be cautious with unexpected attachments and QR codes."
        ],

        "Password Security": [
            "Use unique passwords.",
            "Avoid password reuse.",
            "Use a password manager.",
            "Prefer long passphrases.",
            "Never share passwords."
        ],

        "MFA Security": [
            "Enable MFA wherever available.",
            "Prefer phishing-resistant authentication.",
            "Never approve unexpected MFA requests.",
            "Report suspicious authentication prompts."
        ],

        "Safe Browsing": [
            "Verify websites before entering credentials.",
            "Avoid downloading files from unknown sources.",
            "Keep browsers updated.",
            "Be cautious with unexpected redirects."
        ],

        "Ransomware Awareness": [
            "Maintain reliable backups.",
            "Apply security updates.",
            "Use least privilege.",
            "Use appropriate endpoint security.",
            "Report suspicious activity quickly."
        ],

        "Social Engineering": [
            "Verify unusual requests.",
            "Do not rely only on caller ID or display names.",
            "Be cautious with urgency and authority-based pressure.",
            "Confirm sensitive requests through trusted channels."
        ],

        "Secure Wi-Fi": [
            "Use trusted networks.",
            "Protect home Wi-Fi with strong credentials.",
            "Avoid sensitive activity on untrusted networks.",
            "Keep networking equipment updated."
        ],

        "Data Privacy": [
            "Share sensitive information only when necessary.",
            "Use approved storage locations.",
            "Avoid exposing confidential information publicly.",
            "Follow organizational data-handling policies."
        ],

        "Incident Reporting": [
            "Report suspicious activity quickly.",
            "Preserve relevant evidence.",
            "Do not investigate beyond your authorization.",
            "Follow your organization's incident-response process."
        ]
    }

    topic = st.selectbox(
        "Select Awareness Topic",
        list(modules.keys())
    )

    st.subheader(topic)

    for item in modules[topic]:

        st.markdown(
            f"✅ {item}"
        )


# ============================================================
# AWARENESS QUIZ
# ============================================================

elif page == "Awareness Quiz":

    st.title(
        "🧠 Cybersecurity Awareness Quiz"
    )

    st.caption(
        "Educational assessment for cybersecurity awareness."
    )

    questions = [

        (
            "What should you do with an unexpected credential request?",
            [
                "Click the link",
                "Verify the request",
                "Forward it",
                "Ignore security guidance"
            ],
            "Verify the request"
        ),

        (
            "Which is safer for account security?",
            [
                "Password reuse",
                "Unique passwords",
                "Sharing passwords",
                "Short passwords"
            ],
            "Unique passwords"
        ),

        (
            "What should you do with an unexpected MFA approval request?",
            [
                "Approve it",
                "Ignore it and report if suspicious",
                "Share the code",
                "Disable MFA"
            ],
            "Ignore it and report if suspicious"
        ),

        (
            "What is a good ransomware defense?",
            [
                "No backups",
                "Reliable backups",
                "Password reuse",
                "Disabling updates"
            ],
            "Reliable backups"
        ),

        (
            "What should you do with a suspicious email attachment?",
            [
                "Open immediately",
                "Verify before opening",
                "Forward it",
                "Rename it"
            ],
            "Verify before opening"
        ),

        (
            "Which is a common phishing warning sign?",
            [
                "Unexpected urgency",
                "Normal communication",
                "Known internal process",
                "Scheduled meeting"
            ],
            "Unexpected urgency"
        ),

        (
            "What should you do after noticing suspicious activity?",
            [
                "Ignore it",
                "Report it through the proper channel",
                "Share it publicly",
                "Delete all evidence"
            ],
            "Report it through the proper channel"
        ),

        (
            "Which practice improves password security?",
            [
                "Using the same password everywhere",
                "Using unique passwords",
                "Sharing passwords",
                "Writing passwords publicly"
            ],
            "Using unique passwords"
        )
    ]

    answers = {}

    for i, (
        question,
        options,
        answer
    ) in enumerate(
        questions,
        start=1
    ):

        answers[i] = st.radio(
            f"{i}. {question}",
            options,
            key=f"question_{i}"
        )

    if st.button(
        "Submit Quiz",
        type="primary"
    ):

        score = 0

        for i, (
            question,
            options,
            answer
        ) in enumerate(
            questions,
            start=1
        ):

            if answers[i] == answer:
                score += 1

        percentage = int(
            (score / len(questions)) * 100
        )

        st.markdown("---")

        st.metric(
            "Awareness Score",
            f"{percentage}%"
        )

        if percentage <= 40:

            st.warning(
                "Needs Improvement"
            )

        elif percentage <= 60:

            st.info(
                "Basic"
            )

        elif percentage <= 80:

            st.success(
                "Good"
            )

        else:

            st.success(
                "Strong"
            )

        st.write(
            f"You answered {score} out of "
            f"{len(questions)} questions correctly."
        )

        st.info(
            "This educational score is for awareness learning "
            "and is not an employee fitness or competency judgment."
        )


# ============================================================
# FOOTER
# ============================================================

st.sidebar.markdown("---")

st.sidebar.caption(
    "Cybersecurity Awareness & Threat Intelligence Dashboard"
)

st.sidebar.caption(
    "Synthetic data • Defensive use • Local analysis"
)