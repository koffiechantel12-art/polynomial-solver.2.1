import io, csv
from matplotlib.figure import Figure
import matplotlib.pyplot as plt
from datetime import datetime


def plot_polynomial(xs, ys, coeff_text, poly_latex=None):
    fig, ax = plt.subplots(figsize=(8, 5))

    ax.plot(xs, ys, linewidth=2)
    ax.set_xlabel("x")
    ax.set_ylabel("y")
    ax.grid(True)

    # Title
    ax.set_title("Polynomial Plot", fontsize=14)

    # Draw equation ON the figure (this is the key part)
    if poly_latex:
        ax.text(
            0.5, -0.18,
            f"${poly_latex}$",
            transform=ax.transAxes,
            fontsize=14,
            ha="center"
        )

    return fig


def fig_to_bytes(fig, fmt='png'):
    buf = io.BytesIO()
    fig.savefig(buf, format=fmt, bbox_inches='tight')
    buf.seek(0)
    return buf

def history_to_csv(rows):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id","username","expression","roots","timestamp"])
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode('utf-8')

def poly_to_latex(coeffs):
	# coeffs: list highest->lowest
	deg = len(coeffs) - 1
	terms = []
	for i, c in enumerate(coeffs):
		p = deg - i
		if abs(c) < 1e-12:
			continue
		sign = "-" if c < 0 else "+"
		a = abs(c)
		if p == 0:
			t = f"{a:g}"
		elif p == 1:
			t = ("" if abs(a-1) < 1e-12 else f"{a:g}") + "x"
		else:
			t = ("" if abs(a-1) < 1e-12 else f"{a:g}") + f"x^{{{p}}}"
		terms.append((sign, t))
	if not terms:
		return r"0"
	# assemble with correct signs
	first_sign, first_term = terms[0]
	result = ("" if first_sign == "+" else "-") + first_term
	for s, t in terms[1:]:
		result += f" {s} {t}"
	return result

def complex_to_latex(z, precision=6):
	real = round(z.real, precision)
	imag = round(z.imag, precision)
	if abs(imag) < 1e-12:
		return f"{real:g}"
	if abs(real) < 1e-12:
		return f"{imag:g}\\,i"
	sign = "+" if imag >= 0 else "-"
	return f"{real:g} {sign} {abs(imag):g}\\,i"
