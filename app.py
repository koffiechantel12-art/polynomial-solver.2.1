import os
import sys
import streamlit as st
import sqlite3

sys.path.append(os.path.dirname(__file__))

from auth import init_db, verify_user, create_user, admin_create_user, get_user, list_users, delete_user, add_history, get_history, set_recovery, recover_password, search_users, advanced_search_users, set_role
from solver import parse_coeffs, compute_roots, eval_poly, root_multiplicities
from utils import plot_polynomial, fig_to_bytes, history_to_csv, poly_to_latex, complex_to_latex
from ui import inject_base_css
import numpy as np
import pandas as pd
import re

def is_strong_password(password: str):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""


init_db()
inject_base_css()
st.set_page_config(page_title="Polynomial Solver", layout="centered")
st.set_page_config(
    page_title="Polynomial Solver",
    layout="centered",
    initial_sidebar_state="collapsed"
)

st.markdown(
    """
    <style>
        section[data-testid="stSidebar"] {
            display: none;
        }
    </style>
    """,
    unsafe_allow_html=True
)
def safe_rerun():
    try:
        st.rerun()
    except AttributeError:
        try:
            st.experimental_rerun()
        except Exception:
            pass

# session defaults
if 'user' not in st.session_state:
    st.session_state.user = None
if '_view' not in st.session_state:
    st.session_state._view = None
st.title("Polynomial Solver")

# -------- Account page (landing) --------
def render_account():
    st.header("Sign In")
    username = st.text_input("Username", key="login_user")
    password = st.text_input("Password", type="password", key="login_pw")
    if st.button("Sign In"):
        result = verify_user(username, password)

        if result == "EXPIRED":
            st.warning("Your password has expired. Please create a new password.")
            st.session_state.user = {"username": username}
            st.session_state._view = "force_password_reset"
            safe_rerun()
            return


        if result:
            detail = get_user(username)
            st.session_state.user = {
                "username": detail["username"],
                "is_admin": detail["is_admin"],
                "role": detail.get("role", "admin" if detail.get("is_admin") else "user"),
                "must_set_recovery": detail.get("must_set_recovery", False)
            }
            st.session_state._view = None
            safe_rerun()
            return

        else:
            st.error("Invalid credentials")



    if not st.session_state.get("user"):
        left, right = st.columns(2)
        with left:
            st.markdown('<div class="card"><div class="form-title">Create account</div></div>', unsafe_allow_html=True)
            if st.button("Create account"):
                st.session_state._view = "signup"
                safe_rerun()
        with right:
            st.markdown('<div class="card"><div class="form-title">Forgot password</div></div>', unsafe_allow_html=True)
            if st.button("Forgot password"):
                st.session_state._view = "recover"
                st.session_state.pop("fp_username", None)
                st.session_state.pop("fp_question", None)
                safe_rerun()

    if st.session_state.get("_view") == "signup":
        st.markdown('<div class="modal-card-center"><div class="modal-card">', unsafe_allow_html=True)
        st.markdown("### Create account")
        with st.form("signup_page_form"):
            new_user = st.text_input("Username", key="page_new_user")
            new_pw = st.text_input("Password", type="password", key="page_new_pw")
            confirm_pw = st.text_input("Confirm password", type="password", key="page_confirm_pw")
            st.caption(
                "Password must be at least 8 characters and include uppercase, lowercase, number, and special character."
            )
            if confirm_pw and new_pw != confirm_pw:
                st.warning("Passwords do not match yet.")

            rec_q = st.text_input("Recovery question (optional)", key="page_rec_q")
            rec_a = st.text_input("Recovery answer (optional)", type="password", key="page_rec_a")
            submit = st.form_submit_button("Create account")
        if st.button("Cancel", key="signup_cancel"):
            st.session_state["_view"] = None
            safe_rerun()
        if submit:
            if not new_user or not new_pw or not confirm_pw:
                st.error("Provide username, password, and confirmation.")
            elif new_pw != confirm_pw:
                st.error("Passwords do not match.")
            is_valid, msg = is_strong_password(new_pw)
            if not is_valid:
                st.error(msg)
                return

            elif new_user == "ad":
                st.error("This username is reserved.")
            else:
                ok = create_user(new_user, new_pw, rec_q or None, rec_a or None)
                if ok:
                    st.success("Account created. You may sign in now.")
                    st.session_state["_view"] = None
                    safe_rerun()
                else:
                    st.error("Create failed (username may already exist).")
        st.markdown('</div></div>', unsafe_allow_html=True)

    if st.session_state.get("_view") == "recover":
        st.markdown('<div class="modal-card-center"><div class="modal-card">', unsafe_allow_html=True)
        st.markdown("### Recover password")
        if not st.session_state.get("fp_question"):
            with st.form("recover_find"):
                fp_user = st.text_input("Username to recover", key="page_fp_user")
                find = st.form_submit_button("Find")
            if st.button("Cancel", key="recover_cancel"):
                st.session_state["_view"] = None
                st.session_state["fp_username"] = None
                st.session_state["fp_question"] = None
                safe_rerun()
            if find:
                if not fp_user:
                    st.error("Enter a username.")
                else:
                    conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), "data.db"))
                    c = conn.cursor(); c.execute("SELECT recovery_q FROM users WHERE username=?", (fp_user,))
                    row = c.fetchone(); conn.close()
                    if not row or not row[0]:
                        st.error("User not found or no recovery question set.")
                    else:
                        st.session_state.fp_username = fp_user
                        st.session_state.fp_question = row[0]
                        safe_rerun()
        else:
            st.write("Recovery question:")
            st.info(st.session_state.fp_question)
            with st.form("recover_reset"):
                fp_ans = st.text_input("Answer", type="password", key="page_fp_ans")
                fp_new = st.text_input("New password", type="password", key="page_fp_new")
                reset = st.form_submit_button("Reset password")
            if st.button("Cancel", key="recover_reset_cancel"):
                st.session_state["_view"] = None
                st.session_state["fp_username"] = None
                st.session_state["fp_question"] = None
                safe_rerun()
            if reset:
                if not fp_ans or not fp_new:
                    st.error("Answer and new password required.")
                elif len(fp_new) < 6:
                    st.error("New password must be at least 6 characters.")
                else:
                    ok = recover_password(st.session_state.fp_username, fp_ans, fp_new)
                    if ok:
                        st.success("Password reset successful. You can sign in now.")
                        st.session_state["_view"] = None
                        st.session_state["fp_username"] = None
                        st.session_state["fp_question"] = None
                        safe_rerun()
                    else:
                        st.error("Incorrect answer or failed to reset.")
        st.markdown('</div></div>', unsafe_allow_html=True)

    if st.session_state.get("_view") == "setup_recovery" or (st.session_state.get("user") and st.session_state.user.get("must_set_recovery")):
        st.markdown('<div class="modal-card-center"><div class="modal-card">', unsafe_allow_html=True)
        st.markdown("### Set recovery question (required)")
        st.write("Your account was created by an administrator. For security, please set a recovery question and answer now.")
        with st.form("setup_recovery_form"):
            q = st.text_input("Recovery question", key="setup_q")
            a = st.text_input("Recovery answer", type="password", key="setup_a")
            submit = st.form_submit_button("Save recovery info")
        if submit:
            if not q or not a or len(a) < 3:
                st.error("Provide a question and an answer (at least 3 chars).")
            else:
                ok = set_recovery(st.session_state.user['username'], q, a)
                if ok:
                    st.session_state.user['must_set_recovery'] = False
                    st.session_state._view = None
                    st.success("Recovery info saved. You may continue.")
                    safe_rerun()
                else:
                    st.error("Failed to save recovery info.")
        st.markdown('</div></div>', unsafe_allow_html=True)
        return

# -------- Solver page --------
def render_solver():
    if not st.session_state.user:
        st.info("Please sign in on the Account page to use the solver.")
        return
    st.header("Solve & Plot Polynomial")
    controls, plot_col = st.columns([1,2])
    with controls:
        coeff_text = st.text_input("Coefficients (highest->lowest)", "1,0,-2,1")
        range_min, range_max = st.slider("Plot range", -50.0, 50.0, (-10.0,10.0), step=0.5)
        compute = st.button("Compute & Plot")
    with plot_col:
        if compute:
            try:
                coeffs = parse_coeffs(coeff_text)
                roots = compute_roots(coeffs)
                xs = np.linspace(range_min, range_max, 600)
                ys = eval_poly(coeffs, xs)
                poly_tex = poly_to_latex(coeffs)

                fig = plot_polynomial(
                    xs,
                    ys,
                    coeff_text,
                    poly_latex=poly_tex
                )

                st.pyplot(fig, use_container_width=True)
                # Show nicely formatted polynomial (LaTeX)
                poly_tex = poly_to_latex(coeffs)
                st.subheader("Polynomial")
                st.latex(poly_tex)
                # Show roots with multiplicities
                st.subheader("Roots")
                groups = root_multiplicities(roots)
                # construct LaTeX list like (r)^{m}, ...
                root_items = []
                for r, m in groups:
                    rtex = complex_to_latex(r, precision=6)
                    if m > 1:
                        root_items.append(f"({rtex})^{{{m}}}")
                    else:
                        root_items.append(f"({rtex})")
                st.markdown("$$" + "\\; ,\\; ".join(root_items) + "$$")
                # save history
                add_history(st.session_state.user['username'], coeff_text, str([str(r) for r in roots]))
                # downloads
                png = fig_to_bytes(fig, 'png')
                jpg = fig_to_bytes(fig, 'jpg')
                st.download_button("Download PNG", png.getvalue(), file_name="polynomial.png", mime="image/png")
                st.download_button("Download JPG", jpg.getvalue(), file_name="polynomial.jpg", mime="image/jpeg")
            except Exception as e:
                st.error(str(e))

# -------- History page --------
def render_history():
    if not st.session_state.user:
        st.info("Please sign in on the Account page to view history.")
        return
    st.header("History")
    # Only show the "show all" option to admins; regular users see only their own history
    show_all = False
    if st.session_state.user.get('is_admin'):
        show_all = st.checkbox("Show all users' history", value=False, key="admin_show_all")
    rows = get_history(None if show_all else st.session_state.user['username'])
    if rows:
        df = pd.DataFrame(rows, columns=["id","username","expression","roots","timestamp"])
        st.dataframe(df, use_container_width=True)
        csv = history_to_csv(rows)
        st.download_button("Export history CSV", csv, file_name="history.csv", mime="text/csv")
    else:
        st.write("No history")

# -------- Admin page --------
def render_admin():
    if not st.session_state.user or not st.session_state.user.get("is_admin"):
        st.warning("Admin access required. Sign in as 'ad' on the Account page.")
        return

    st.header("Admin")

    # --- Create user (top, distinct card) ---
    with st.container():
        st.subheader("Create user (admin)")
        st.markdown("Create a new user account. The user will be required to set their recovery question on first login.")
        with st.form("admin_create_form"):
            cu_name = st.text_input("New username", key="admin_new_user")
            cu_pw = st.text_input("New password", type="password", key="admin_new_pw")
            cu_phone = st.text_input("Phone (optional)", key="admin_new_phone", placeholder="+1234567890")
            cu_role = st.selectbox("Role", ["user", "admin"], index=0, key="admin_new_role")
            st.caption(
                "Password must be at least 8 characters and include uppercase, lowercase, number, and special character."
            )
            create_submit = st.form_submit_button("Create user")
        if create_submit:
            if not cu_name or not cu_pw:
                st.error("Provide username and password.")
            elif cu_name == "ad":
                st.error("Username reserved.")
            else:
                is_valid, msg = is_strong_password(cu_pw)
                if not is_valid:
                    st.error(msg)
                    return
                ok = admin_create_user(cu_name, cu_pw, phone=cu_phone or None, role=cu_role)
                if ok:
                    st.success(f"User '{cu_name}' created. They must set a recovery question on first login.")
                else:
                    st.error("Create failed (user or phone may already exist).")

    st.markdown("---")

    # --- Search users (separate section) ---
    with st.container():
        st.subheader("Search users")
        st.markdown("Search and manage existing users. Use the Search button to run the query.")
        with st.form("admin_search_form"):
            q = st.text_input("Query", key="admin_search_q")
            case_sensitive = st.checkbox("Case sensitive", value=False, key="admin_search_case")
            admin_filter = st.selectbox("Role", ["All", "Users only", "Admins only"], index=0, key="admin_search_role")
            per_page = st.selectbox("Results per page", [10,20,50,100], index=1, key="admin_search_pp")
            search_submit = st.form_submit_button("Search")
        if search_submit:
            role_val = None if admin_filter == "All" else (True if admin_filter == "Admins only" else False)
            try:
                rows = advanced_search_users(q or "", mode='fuzzy', fuzzy_threshold=75, limit=1000, is_admin=role_val, case_sensitive=case_sensitive)
            except Exception as e:
                st.error("Search failed: " + str(e))
                rows = []
            st.session_state.admin_search_results = rows
            st.session_state.admin_search_page = 0

        # display results if present
        results = st.session_state.get("admin_search_results", [])
        if not results:
            st.info("No results. Use the Search button to run a query.")
        else:
            # when rendering results, include phone and remove pagination buttons
            for u in results:
                cols = st.columns([2,2,1,1,1])  # username, phone, role, created_at, actions
                cols[0].write(f"**{u['username']}**")
                cols[1].write(u.get("phone",""))
                current_role = u.get("role") or ("admin" if u.get("is_admin") else "user")
                role_choice = cols[2].selectbox(
                    "Role",
                    ["user", "admin"],
                    index=0 if current_role == "user" else 1,
                    key=f"role_{u['username']}",
                    label_visibility="collapsed"
                )
                cols[3].write(u.get("created_at",""))
                if cols[4].button(f"Update role", key=f"role_save_{u['username']}"):
                    if u["username"] == "ad" and role_choice != "admin":
                        st.warning("The 'ad' account must remain an admin.")
                    else:
                        ok = set_role(u["username"], role_choice)
                        if ok:
                            u["role"] = role_choice
                            u["is_admin"] = role_choice == "admin"
                            st.success(f"Updated role for {u['username']}")
                        else:
                            st.error("Role update failed.")
                if cols[4].button(f"View history", key=f"hist_{u['username']}"):
                    st.session_state.admin_view_history = u['username']
                if cols[4].button(f"Delete {u['username']}", key=f"del_{u['username']}"):
                    if u['username']=="ad":
                        st.warning("Protected account; cannot delete admin 'ad'.")
                    else:
                        ok = delete_user(u['username'])
                        if ok:
                            st.success(f"Deleted {u['username']}")
                            st.session_state.admin_search_results = [r for r in st.session_state.admin_search_results if r['username'] != u['username']]
                            safe_rerun()
                        else:
                            st.error("Delete failed")

    # --- View history panel (below search) ---
    if st.session_state.get("admin_view_history"):
        target = st.session_state.admin_view_history
        st.subheader(f"History for {target}")
        rows = get_history(target)
        if rows:
            import pandas as pd
            df = pd.DataFrame(rows, columns=["id","username","expression","roots","timestamp"])
            st.dataframe(df, use_container_width=True)
            csv = history_to_csv(rows)
            st.download_button("Export history CSV", csv, file_name=f"{target}_history.csv", mime="text/csv")
        else:
            st.write("No history for this user.")
        if st.button("Close history", key="close_hist"):
            st.session_state.pop("admin_view_history", None)
            safe_rerun()

# Page dispatch
if not st.session_state.get("user"):
    render_account()
else:
    tabs = ["Solver", "History"]
    if st.session_state.user.get("is_admin"):
        tabs.append("Admin")
    tab1, tab2, *tab3 = st.tabs(tabs)
    with tab1:
        render_solver()
    with tab2:
        render_history()
    if tab3:
        with tab3[0]:
            render_admin()
    st.markdown("---")
    if st.button("Sign Out"):
        st.session_state.user = None
        st.session_state._view = None
        safe_rerun()


st.caption("If signed in, use the tabs to navigate to Solver / History / Admin.")
