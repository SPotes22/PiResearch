import json, os, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

OUT = sys.argv[1]
R = json.load(open(os.path.join(OUT,"results.json")))
plt.rcParams.update({"figure.dpi":120, "font.size":10})

def fk(d): return sorted((float(k),v) for k,v in d.items())

# ---- Fig 1: alpha ----
alpha = fk(R["alpha"])
fig, (ax1, ax2) = plt.subplots(1,2, figsize=(11,4.2))
for a,v in alpha:
    ax1.plot(v["it"], v["train"], marker='o', ms=3, label=f"α={a:g}")
ax1.set(xlabel="Iteración", ylabel="Precisión (train)",
        title="Curva de entrenamiento según α", ylim=(0,1)); ax1.grid(alpha=.3); ax1.legend(fontsize=8)
xs=[a for a,_ in alpha]
ax2.plot(xs,[v["test"] for _,v in alpha], 'o-', label="Test")
ax2.plot(xs,[v["final_train"] for _,v in alpha], 's--', label="Train final")
ax2.set(xlabel="Tasa de aprendizaje α", ylabel="Precisión final",
        title="Precisión final vs α", ylim=(0,1)); ax2.grid(alpha=.3); ax2.legend()
fig.tight_layout(); fig.savefig(os.path.join(OUT,"fig1_alpha.png")); plt.close(fig)

# ---- Fig 2: width ----
w = fk(R["width"])
fig, (ax1, ax2) = plt.subplots(1,2, figsize=(11,4.2))
for h,v in w:
    ax1.plot(v["it"], v["train"], marker='o', ms=3, label=f"{int(h)}")
ax1.set(xlabel="Iteración", ylabel="Precisión (train)",
        title="Entrenamiento según nº de neuronas (1 capa oculta)", ylim=(0,1)); ax1.grid(alpha=.3)
ax1.legend(title="neuronas", fontsize=8, ncol=2)
xs=[h for h,_ in w]
ax2.plot(xs,[v["test"] for _,v in w], 'o-', label="Test")
ax2.plot(xs,[v["final_train"] for _,v in w], 's--', label="Train final")
ax2.set(xscale="log", xlabel="Neuronas en la capa oculta (log)", ylabel="Precisión final",
        title="Precisión vs ancho de la capa", ylim=(0,1)); ax2.grid(alpha=.3, which="both"); ax2.legend()
ax2.set_xticks(xs); ax2.set_xticklabels([int(h) for h in xs])
fig.tight_layout(); fig.savefig(os.path.join(OUT,"fig2_width.png")); plt.close(fig)

# ---- Fig 3: depth ----
d = fk(R["depth"])
fig, (ax1, ax2) = plt.subplots(1,2, figsize=(11,4.2))
for L,v in d:
    ax1.plot(v["it"], v["train"], marker='o', ms=3, label=f"{int(L)}")
ax1.axhline(0.1, color='k', ls=':', lw=1, label="azar (0.10)")
ax1.set(xlabel="Iteración", ylabel="Precisión (train)",
        title="Entrenamiento según nº de capas ocultas (10 neuronas c/u)", ylim=(0,1)); ax1.grid(alpha=.3)
ax1.legend(title="capas", fontsize=8, ncol=2)
xs=[L for L,_ in d]
ax2.plot(xs,[v["test"] for _,v in d], 'o-', label="Test")
ax2.plot(xs,[v["final_train"] for _,v in d], 's--', label="Train final")
ax2.axhline(0.1, color='k', ls=':', lw=1, label="azar (0.10)")
ax2.set(xscale="log", xlabel="Nº de capas ocultas (log)", ylabel="Precisión final",
        title="Precisión vs profundidad", ylim=(0,1)); ax2.grid(alpha=.3, which="both"); ax2.legend()
ax2.set_xticks(xs); ax2.set_xticklabels([int(L) for L in xs])
fig.tight_layout(); fig.savefig(os.path.join(OUT,"fig3_depth.png")); plt.close(fig)
print("plots saved to", OUT, os.listdir(OUT))
