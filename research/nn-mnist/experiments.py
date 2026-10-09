import os, sys, gzip, struct, time, json
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

RAW = sys.argv[1]          # path to MNIST/raw
OUT = sys.argv[2]          # output dir for plots/json
os.makedirs(OUT, exist_ok=True)
np.random.seed(0)

def load_idx(path):
    with open(path, "rb") as f:
        magic, = struct.unpack(">I", f.read(4))
        if magic == 2051:
            n, r, c = struct.unpack(">III", f.read(12))
            return np.frombuffer(f.read(), np.uint8).reshape(n, r*c)
        elif magic == 2049:
            n, = struct.unpack(">I", f.read(4))
            return np.frombuffer(f.read(), np.uint8)
        raise ValueError(magic)

imgs = load_idx(os.path.join(RAW, "train-images-idx3-ubyte"))
lbls = load_idx(os.path.join(RAW, "train-labels-idx1-ubyte"))
X_all = imgs.astype(np.float64).T / 255.0      # 784 x 60000
Y_all = lbls.astype(np.int64)

# Keep it tractable on CPU while staying representative.
N_TRAIN, N_TEST = 20000, 5000
X_train, Y_train = X_all[:, :N_TRAIN], Y_all[:N_TRAIN]
X_test,  Y_test  = X_all[:, N_TRAIN:N_TRAIN+N_TEST], Y_all[N_TRAIN:N_TRAIN+N_TEST]

def sigmoid(Z): return 1.0 / (1.0 + np.exp(-np.clip(Z, -500, 500)))
def dsigmoid(A): return A * (1 - A)
def softmax(Z):
    e = np.exp(Z - np.max(Z, axis=0, keepdims=True))
    return e / e.sum(axis=0, keepdims=True)
def one_hot(Y):
    oh = np.zeros((Y.size, 10)); oh[np.arange(Y.size), Y] = 1
    return oh.T

def init_params(sizes, rng):
    # sizes = [784, h, h, ..., 10].  Xavier-ish init for stable sigmoid training.
    Ws, bs = [], []
    for i in range(len(sizes)-1):
        fan_in = sizes[i]
        Ws.append(rng.standard_normal((sizes[i+1], sizes[i])) * np.sqrt(1.0/fan_in))
        bs.append(np.zeros((sizes[i+1], 1)))
    return Ws, bs

def forward(Ws, bs, X):
    A = X; cache = [X]
    L = len(Ws)
    for i in range(L):
        Z = Ws[i].dot(A) + bs[i]
        A = softmax(Z) if i == L-1 else sigmoid(Z)
        cache.append(A)
    return cache

def backward(Ws, bs, cache, Y):
    L = len(Ws); m = Y.size
    Yoh = one_hot(Y)
    dWs = [None]*L; dbs = [None]*L
    dZ = cache[-1] - Yoh                      # softmax+CE
    for i in reversed(range(L)):
        A_prev = cache[i]
        dWs[i] = dZ.dot(A_prev.T) / m
        dbs[i] = np.sum(dZ, axis=1, keepdims=True) / m
        if i > 0:
            dA = Ws[i].T.dot(dZ)
            dZ = dA * dsigmoid(A_prev)        # A_prev is sigmoid activation
    return dWs, dbs

def accuracy(Ws, bs, X, Y):
    A = forward(Ws, bs, X)[-1]
    return np.mean(np.argmax(A, axis=0) == Y)

def train(sizes, alpha, iters, seed=0, record_every=10):
    rng = np.random.default_rng(seed)
    Ws, bs = init_params(sizes, rng)
    hist_it, hist_tr = [], []
    for it in range(iters):
        cache = forward(Ws, bs, X_train)
        dWs, dbs = backward(Ws, bs, cache, Y_train)
        for i in range(len(Ws)):
            Ws[i] -= alpha * dWs[i]; bs[i] -= alpha * dbs[i]
        if it % record_every == 0 or it == iters-1:
            hist_it.append(it)
            hist_tr.append(float(np.mean(np.argmax(cache[-1],axis=0)==Y_train)))
    return Ws, bs, hist_it, hist_tr

results = {}

# ---------- Experiment 1: learning rate alpha in (0,1) ----------
ITERS = 300
alphas = [0.01, 0.05, 0.1, 0.25, 0.5, 0.75, 1.0]
exp1 = {}
t0=time.time()
for a in alphas:
    Ws,bs,hit,htr = train([784,10,10], a, ITERS)
    te = accuracy(Ws,bs,X_test,Y_test)
    exp1[a] = {"it":hit,"train":htr,"test":float(te),"final_train":htr[-1]}
    print(f"[alpha] a={a:<5} test={te:.4f} train={htr[-1]:.4f}  ({time.time()-t0:.1f}s)")
results["alpha"]=exp1

# ---------- Experiment 2: hidden-layer width (1 hidden layer) ----------
widths = [1,3,5,10,20,30,50,100]
exp2 = {}
for h in widths:
    Ws,bs,hit,htr = train([784,h,10], 0.5, ITERS)
    te = accuracy(Ws,bs,X_test,Y_test)
    exp2[h] = {"it":hit,"train":htr,"test":float(te),"final_train":htr[-1]}
    print(f"[width] h={h:<4} test={te:.4f} train={htr[-1]:.4f}  ({time.time()-t0:.1f}s)")
results["width"]=exp2

# ---------- Experiment 3: number of hidden layers (width 10 each) ----------
depths = [1,3,5,10,20,30,50,100]
exp3 = {}
for L in depths:
    sizes = [784] + [10]*L + [10]
    Ws,bs,hit,htr = train(sizes, 0.5, ITERS)
    te = accuracy(Ws,bs,X_test,Y_test)
    exp3[L] = {"it":hit,"train":htr,"test":float(te),"final_train":htr[-1]}
    print(f"[depth] L={L:<4} test={te:.4f} train={htr[-1]:.4f}  ({time.time()-t0:.1f}s)")
results["depth"]=exp3

with open(os.path.join(OUT,"results.json"),"w") as f:
    json.dump(results,f)
print("DONE total", round(time.time()-t0,1),"s")
