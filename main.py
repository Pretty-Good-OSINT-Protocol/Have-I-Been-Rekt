import streamlit as st
import requests

def main():
    st.set_page_config(page_title="PGOP CLI", layout="centered")
    st.title("Pretty Good OSINT Protocol (PGOP)")
    st.write("This is the command-line entry point for modular OSINT tools.")

    st.subheader("Feature Preview")
    st.markdown("- Wallet & domain lookups")
    st.markdown("- Contract inspection")
    st.markdown("- AI-powered summaries")

if __name__ == "__main__":
    main()
