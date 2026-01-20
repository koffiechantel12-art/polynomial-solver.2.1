import numpy as np

def parse_coeffs(text):
    # expect comma-separated coefficients highest->lowest, e.g. "1,0,-2,1"
    try:
        coeffs = [float(x.strip()) for x in text.split(",") if x.strip()!='']
        if not coeffs:
            raise ValueError
        return coeffs
    except Exception:
        raise ValueError("Invalid coefficient list")

def compute_roots(coeffs):
    roots = np.roots(coeffs)
    # convert to readable string
    return roots

def eval_poly(coeffs, xs):
    ys = np.polyval(coeffs, xs)
    return ys

def root_multiplicities(roots, tol=1e-6):
	# roots: numpy array of complex values
	groups = []
	used = [False] * len(roots)
	for i, r in enumerate(roots):
		if used[i]:
			continue
		count = 1
		for j in range(i+1, len(roots)):
			if not used[j] and abs(roots[j] - r) < tol:
				count += 1
				used[j] = True
		groups.append((r, count))
	# sort by real then imag
	groups.sort(key=lambda x: (round(x[0].real,6), round(x[0].imag,6)))
	return groups
