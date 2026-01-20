import streamlit as st
from contextlib import contextmanager

def inject_base_css():
    st.markdown(
        """
        <style>
        /* center content and limit width */
        .reportview-container .main .block-container{
            max-width: 900px;
            padding-top: 1rem;
            padding-left: 2rem;
            padding-right: 2rem;
        }
        /* card style for forms */
        .card {
            background: #ffffff;
            border: 1px solid #e6e9ef;
            border-radius: 8px;
            padding: 18px;
            box-shadow: 0 2px 6px rgba(15,15,15,0.04);
            margin-bottom: 12px;
        }
        .form-title {
            font-weight: 600;
            margin-bottom: 8px;
            color: #111827;
        }
        .small-note {
            color: #6b7280;
            font-size: 12px;
            margin-top: 6px;
        }
        /* slightly narrower sidebar */
        .css-1d391kg {width: 260px;}

        /* centered modal-like card (no overlay) */
        .modal-card-center {
            display: flex;
            align-items: start;
            justify-content: center;
            padding-top: 40px;
        }
        .modal-card {
            width: 540px;
            background: #fff;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 8px 30px rgba(2,6,23,0.12);
        }
        </style>
        """,
        unsafe_allow_html=True
    )

@contextmanager
def centered_container():
    try:
        yield
    finally:
        pass
