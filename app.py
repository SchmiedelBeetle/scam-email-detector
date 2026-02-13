# app.py
import streamlit as st
from scanner import scan_text

st.title("Scam Message Detector (V1)")
st.write("Paste an email or text message below and click Scan.")

text = st.text_area("Message", height=220)

if st.button("Scan"):
    result = scan_text(text)

    st.subheader("Result")
    st.metric("Risk Score", result["score"])
    st.write("**Label:**", result["label"])

    st.subheader("Why it was flagged")
    for r in result["reasons"]:
        st.write("- " + r)

    # Evidence section (optional)
    if result["evidence"]:
        st.subheader("Evidence (debug info)")
        st.json(result["evidence"])
