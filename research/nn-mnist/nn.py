# /// script
# dependencies = [
#     "marimo",
#     "matplotlib==3.10.8",
#     "numpy==2.4.2",
#     "plotly==6.7.0",
#     "torch==2.10.0",
#     "torchvision==0.25.0",
#     "typst==0.14.8",
# ]
# requires-python = ">=3.14"
# ///

import marimo

__generated_with = "0.25.0"
app = marimo.App(width="medium")


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    # Neural networks
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    ## Perceptron: the core concept

    A perceptron is one of the earliest neuron models (1950s - 1960s).

    ### How it works:

    - Takes several **binary inputs** $(x_1, x_2, \ldots)$ and produces a single **binary output**
    - Each input has a weight $(w_1, w_2, \ldots)$ expressing its importance
    - Computes a weighted sum $\sum w_jx_j$ and compares it to a threshold.
    - Modern notation replaces the threshold with a bias $b$
    $$
      \hat{y} = \begin{cases}
          0 \;\; \text{if}\;\; \sum_j w_j \cdot x_j \leq \text{threshold}\\
          1 \;\; \text{if}\;\; \sum_j w_j \cdot x_j > \text{threshold}\\
      \end{cases}
    $$

    or more common these days:

    $$
      \hat{y} = \begin{cases}
          0 \;\; \text{if}\;\; \sum_j w_j \cdot x_j + b \leq 0\\
          1 \;\; \text{if}\;\; \sum_j w_j \cdot x_j +b > 0 \\
      \end{cases}
    $$


    The threshold is represented by $b$.
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.vstack(
        [
            mo.image(
                src="perceptron.png",
                width="50%",
                style={"margin": "0 auto", "display": "block"},
            ),
        ]
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    We call $\{w_1, w_2, w_3, b \}$ the parameters of the perceptron. Knowing its values we can relicate its behavior.
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    ### Play with a perceptron
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    x1 = mo.ui.switch(label="x₁")
    x2 = mo.ui.switch(label="x₂")
    x3 = mo.ui.switch(label="x₃")
    w1 = mo.ui.slider(-2, 2, step=0.1, value=1.0, label="w₁")
    w2 = mo.ui.slider(-2, 2, step=0.1, value=1.0, label="w₂")
    w3 = mo.ui.slider(-2, 2, step=0.1, value=1.0, label="w₃")
    b = mo.ui.slider(-3, 3, step=0.1, value=-1.5, label="b (bias)")

    mo.vstack(
        [
            mo.hstack(
                [
                    mo.vstack(
                        [mo.md("**Inputs**"), mo.hstack([x1, x2, x3], gap="2rem")]
                    ),
                ]
            ),
            mo.hstack(
                [
                    mo.vstack(
                        [mo.md("**Weights**"), mo.hstack([w1, w2, w3], gap="1rem")]
                    ),
                    mo.vstack([mo.md("**Bias**"), b]),
                ],
                gap="3rem",
            ),
        ]
    )
    return b, w1, w2, w3, x1, x2, x3


@app.cell(hide_code=True)
def _(b, mo, w1, w2, w3, x1, x2, x3):
    net = (
        w1.value * int(x1.value)
        + w2.value * int(x2.value)
        + w3.value * int(x3.value)
        + b.value
    )
    output = 1 if net > 0 else 0
    color = "#2f9e44" if output == 1 else "#e03131"


    def term(w, x):
        return f"{{\\color{{#1971c2}}{w:.1f}}}({{\\color{{#e67700}}{x}}}) "


    eq = (
        f"{term(w1.value, int(x1.value))}"
        f"+ {term(w2.value, int(x2.value))}"
        f"+ {term(w3.value, int(x3.value))}"
        f"+ ({{\\color{{#c2255c}}{b.value:.1f}}}) = {net:.2f}"
    )

    mo.vstack(
        [
            mo.md(f"**Net input:** $\\ {eq}$"),
            mo.Html(
                f'<div style="font-size:1.4rem;font-weight:bold;color:{color}">Output ŷ = {output}</div>'
            ),
        ]
    )
    return


@app.cell(hide_code=True)
def _(b, np, w1, w2, w3, x1, x2, x3):
    import plotly.graph_objects as go

    _x = np.linspace(-3, 3, 500)
    _y = np.where(_x > 0, 1, 0)

    _net = (
        w1.value * int(x1.value)
        + w2.value * int(x2.value)
        + w3.value * int(x3.value)
        + b.value
    )
    _out = 1 if _net > 0 else 0

    _fig = go.Figure()

    _fig.add_trace(
        go.Scatter(
            x=_x,
            y=_y,
            mode="lines",
            line=dict(color="#1971c2", width=3),
            hovertemplate="net = %{x:.2f}<br>ŷ = %{y}<extra></extra>",
            name="step",
        )
    )

    _fig.add_vline(x=_net, line=dict(color="#e67700", width=2, dash="dash"))

    _fig.add_trace(
        go.Scatter(
            x=[_net],
            y=[_out],
            mode="markers",
            marker=dict(
                size=14, color="#e67700", line=dict(color="white", width=2)
            ),
            hovertemplate=f"net = {_net:.2f}<br>ŷ = {_out}<extra></extra>",
            name="current",
            showlegend=False,
        )
    )

    _fig.update_layout(
        title="Step function (perceptron activation)",
        xaxis_title="net input",
        yaxis_title="ŷ",
        yaxis=dict(tickvals=[0, 1], range=[-0.2, 1.4]),
        height=350,
        margin=dict(l=40, r=20, t=50, b=40),
        showlegend=False,
    )
    _fig
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    ## NAND gate
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    x1_nand = mo.ui.switch(label="x₁")
    x2_nand = mo.ui.switch(label="x₂")
    mo.hstack([x1_nand, x2_nand], gap="3rem", justify="start")
    return x1_nand, x2_nand


@app.cell(hide_code=True)
def _(mo):
    reset_nand = mo.ui.button(label="↺ Reset")
    return (reset_nand,)


@app.cell(hide_code=True)
def _(mo, reset_nand):
    _r = reset_nand.value
    w1_nand = mo.ui.slider(-5, 5, step=1, value=-2, label="w₁")
    w2_nand = mo.ui.slider(-5, 5, step=1, value=-2, label="w₂")
    b_nand = mo.ui.slider(-5, 5, step=1, value=3, label="b")
    mo.hstack([reset_nand, w1_nand, w2_nand, b_nand], gap="2rem")
    return b_nand, w1_nand, w2_nand


@app.cell(hide_code=True)
def _(b_nand, w1_nand, w2_nand, x1_nand, x2_nand):
    import plotly.graph_objects as _go

    _W = [w1_nand.value, w2_nand.value]
    _b = b_nand.value
    _v1, _v2 = int(x1_nand.value), int(x2_nand.value)
    _net = _W[0] * _v1 + _W[1] * _v2 + _b
    _out = 1 if _net > 0 else 0


    def _nc(v):
        return "#a5d8ff" if v else "#dee2e6"


    def _bc(v):
        return "#1971c2" if v else "#adb5bd"


    def _wc(w):
        return "#1971c2" if w > 0 else "#e03131"


    _nodes = [
        dict(
            x=0, y=1.2, label=f"x\u2081<br>{_v1}", color=_nc(_v1), border=_bc(_v1)
        ),
        dict(
            x=0, y=-1.2, label=f"x\u2082<br>{_v2}", color=_nc(_v2), border=_bc(_v2)
        ),
        dict(
            x=2.5,
            y=0,
            label=f"\u03a3<br>{'→1' if _out else '→0'}",
            color="#b2f2bb" if _out else "#ffc9c9",
            border="#2f9e44" if _out else "#e03131",
        ),
    ]
    _edges = [(0, 1.2, 2.5, 0, _W[0]), (0, -1.2, 2.5, 0, _W[1])]

    _fig = _go.Figure()

    for _x0, _y0, _x1e, _y1e, _w in _edges:
        _fig.add_trace(
            _go.Scatter(
                x=[_x0, _x1e],
                y=[_y0, _y1e],
                mode="lines",
                line=dict(color=_wc(_w), width=3),
                showlegend=False,
                hoverinfo="skip",
            )
        )
        _fig.add_annotation(
            x=(_x0 + _x1e) / 2,
            y=(_y0 + _y1e) / 2,
            text=f"<b>w={_w}</b>",
            showarrow=False,
            font=dict(size=13, color=_wc(_w)),
            bgcolor="white",
            borderpad=2,
        )

    _fig.add_trace(
        _go.Scatter(
            x=[1.25],
            y=[-2.8],
            mode="markers+text",
            marker=dict(
                size=44, color="#fcc2d7", line=dict(color="#c2255c", width=2)
            ),
            text=["1"],
            textposition="middle center",
            textfont=dict(size=14, color="#c2255c"),
            showlegend=False,
            hoverinfo="skip",
        )
    )
    _fig.add_trace(
        _go.Scatter(
            x=[1.25, 2.5],
            y=[-2.8, 0],
            mode="lines",
            line=dict(color="#c2255c", width=2, dash="dash"),
            showlegend=False,
            hoverinfo="skip",
        )
    )
    _fig.add_annotation(
        x=2.0,
        y=-1.6,
        text=f"<b>b={_b}</b>",
        showarrow=False,
        font=dict(size=13, color="#c2255c"),
        bgcolor="white",
        borderpad=2,
    )

    for _n in _nodes:
        _fig.add_trace(
            _go.Scatter(
                x=[_n["x"]],
                y=[_n["y"]],
                mode="markers+text",
                marker=dict(
                    size=56,
                    color=_n["color"],
                    line=dict(color=_n["border"], width=2.5),
                ),
                text=[_n["label"]],
                textposition="middle center",
                textfont=dict(size=13),
                showlegend=False,
                hoverinfo="skip",
            )
        )

    _fig.add_annotation(
        x=3.6,
        y=0,
        ax=2.9,
        ay=0,
        text="",
        showarrow=True,
        arrowhead=2,
        arrowwidth=2.5,
        arrowcolor="#2f9e44" if _out else "#e03131",
        xref="x",
        yref="y",
        axref="x",
        ayref="y",
    )
    _fig.add_annotation(
        x=3.7,
        y=0,
        text=f"<b>\u0177 = {_out}</b>",
        showarrow=False,
        xanchor="left",
        font=dict(size=18, color="#2f9e44" if _out else "#e03131"),
        xref="x",
        yref="y",
        bgcolor="white",
        borderpad=4,
    )

    _fig.update_layout(
        title=f"NAND gate — net input = {_net}",
        xaxis=dict(
            range=[-0.8, 4.5], showgrid=False, zeroline=False, showticklabels=False
        ),
        yaxis=dict(
            range=[-3.5, 2.2],
            showgrid=False,
            zeroline=False,
            showticklabels=False,
            scaleanchor="x",
        ),
        height=420,
        plot_bgcolor="white",
        margin=dict(l=20, r=20, t=50, b=20),
    )
    _fig
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    ## Simple neural network

    We can arrange perceptrons to form a neural network. In the following image we have 7 perceptrons:

    - 2 in the first column (blue)
    - 4 in the second column (grren)
    - 1 in the last column (orange)

    We use the term layer instead of column. The neural network has an input layer, one hidden layer and an output layer.
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.vstack(
        [
            mo.image(
                src="neural-network-2-4-1.png",
                width="80%",
                style={"margin": "0 auto", "display": "block"},
            ),
        ]
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    ## Sigmoid neurons

    Perceptrons have a big problem, when they are chained in a network a samll change in any of it weights might produce a big change in the output. A sigmoid neuron is a modified version that allow small changes in __weights and bias__ to produce small changes in the outpt.

    The sigmoid (logistic) function is defined as:

    $$
    \sigma(z) \equiv \frac{1}{1+e^{-z}}
    $$


    In our case $z = w \cdot x + b$ so it becomes:

    $$
    \sigma(z) = \frac{1}{1+ e^{-\sum_j w_j x_j - b}}
    $$

    **Relationship to the perceptron**: the sigmoid neuron is a smoothed-out perceptron. When $w \cdot x + b$ is:

    - A large positive the output approaches to 1.
    - A large negative the output approaches to 0.

    So far is the same as a perceptron. The difference is at modest values, where the somooth $\sigma$ makes the output chenge linearly with small adjustments to the weights and bias.
    """)
    return


@app.cell(hide_code=True)
def _(np):
    import plotly.graph_objects as _go2

    _z = np.linspace(-6, 6, 400)
    _sigma = 1 / (1 + np.exp(-_z))

    _fig = _go2.Figure()
    _fig.add_trace(
        _go2.Scatter(
            x=_z,
            y=_sigma,
            mode="lines",
            line=dict(color="#1971c2", width=2.5),
            hovertemplate="z = %{x:.2f}<br>σ(z) = %{y:.4f}<extra></extra>",
        )
    )
    _fig.add_hline(y=0.5, line=dict(color="#adb5bd", width=1, dash="dot"))
    _fig.add_vline(x=0, line=dict(color="#adb5bd", width=1, dash="dot"))
    _fig.update_layout(
        title="Sigmoid function",
        xaxis=dict(title="z", zeroline=False),
        yaxis=dict(title="σ(z)", range=[-0.05, 1.05], zeroline=False),
        height=350,
        plot_bgcolor="white",
        margin=dict(l=20, r=20, t=50, b=40),
    )
    _fig
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    the diagram of the sigmid neuron should be:
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.vstack(
        [
            mo.image(
                src="deconstructed-sigmoid.png",
                width="50%",
                style={"margin": "0 auto", "display": "block"},
            ),
        ]
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    ### Play with a sigmoid neuron
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    x1_sig = mo.ui.switch(label="x₁")
    x2_sig = mo.ui.switch(label="x₂")
    x3_sig = mo.ui.switch(label="x₃")
    w1_sig = mo.ui.slider(-2, 2, step=0.1, value=1.0, label="w₁")
    w2_sig = mo.ui.slider(-2, 2, step=0.1, value=1.0, label="w₂")
    w3_sig = mo.ui.slider(-2, 2, step=0.1, value=1.0, label="w₃")
    b_sig = mo.ui.slider(-3, 3, step=0.1, value=-1.5, label="b (bias)")

    mo.vstack(
        [
            mo.hstack(
                [mo.vstack([mo.md("**Inputs**"), mo.hstack([x1_sig, x2_sig, x3_sig], gap="2rem")])]
            ),
            mo.hstack(
                [
                    mo.vstack([mo.md("**Weights**"), mo.hstack([w1_sig, w2_sig, w3_sig], gap="1rem")]),
                    mo.vstack([mo.md("**Bias**"), b_sig]),
                ],
                gap="3rem",
            ),
        ]
    )
    return b_sig, w1_sig, w2_sig, w3_sig, x1_sig, x2_sig, x3_sig


@app.cell(hide_code=True)
def _(b_sig, mo, w1_sig, w2_sig, w3_sig, x1_sig, x2_sig, x3_sig):
    import numpy as _np_sig

    _net_sig = (
        w1_sig.value * int(x1_sig.value)
        + w2_sig.value * int(x2_sig.value)
        + w3_sig.value * int(x3_sig.value)
        + b_sig.value
    )
    _sigma_out = 1 / (1 + _np_sig.exp(-_net_sig))
    _color_sig = f"hsl({int(_sigma_out * 120)}, 70%, 45%)"


    def _term_sig(w, x):
        return f"{{\\color{{#1971c2}}{w:.1f}}}({{\\color{{#e67700}}{x}}})"


    _eq_sig = (
        f"{_term_sig(w1_sig.value, int(x1_sig.value))}"
        f"+ {_term_sig(w2_sig.value, int(x2_sig.value))}"
        f"+ {_term_sig(w3_sig.value, int(x3_sig.value))}"
        f"+ ({{\\color{{#c2255c}}{b_sig.value:.1f}}}) = {_net_sig:.2f}"
    )

    mo.vstack(
        [
            mo.md(f"**Net input:** $\\ {_eq_sig}$"),
            mo.md(f"**Sigmoid output:** $\\sigma({_net_sig:.2f}) = \\dfrac{{1}}{{1+e^{{{-_net_sig:.2f}}}}}$"),
            mo.Html(
                f'''<div style="font-size:1.4rem;font-weight:bold;color:{_color_sig}">
                Output ŷ = {_sigma_out:.4f}
                </div>'''
            ),
        ]
    )
    return


@app.cell(hide_code=True)
def _(b_sig, w1_sig, w2_sig, w3_sig, x1_sig, x2_sig, x3_sig):
    import plotly.graph_objects as _go_sig
    import numpy as _np_sig2

    _z_sig = _np_sig2.linspace(-6, 6, 400)
    _curve_sig = 1 / (1 + _np_sig2.exp(-_z_sig))

    _net_plot = (
        w1_sig.value * int(x1_sig.value)
        + w2_sig.value * int(x2_sig.value)
        + w3_sig.value * int(x3_sig.value)
        + b_sig.value
    )
    _out_plot = 1 / (1 + _np_sig2.exp(-_net_plot))

    _fig_sig = _go_sig.Figure()

    _fig_sig.add_trace(
        _go_sig.Scatter(
            x=_z_sig,
            y=_curve_sig,
            mode="lines",
            line=dict(color="#1971c2", width=3),
            hovertemplate="z = %{x:.2f}<br>σ(z) = %{y:.4f}<extra></extra>",
            name="sigmoid",
        )
    )

    _fig_sig.add_vline(x=_net_plot, line=dict(color="#e67700", width=2, dash="dash"))

    _fig_sig.add_trace(
        _go_sig.Scatter(
            x=[_net_plot],
            y=[_out_plot],
            mode="markers",
            marker=dict(size=14, color="#e67700", line=dict(color="white", width=2)),
            hovertemplate=f"net = {_net_plot:.2f}<br>σ = {_out_plot:.4f}<extra></extra>",
            showlegend=False,
        )
    )

    _fig_sig.add_hline(y=0.5, line=dict(color="#adb5bd", width=1, dash="dot"))
    _fig_sig.add_vline(x=0, line=dict(color="#adb5bd", width=1, dash="dot"))

    _fig_sig.update_layout(
        title="Sigmoid function (sigmoid neuron activation)",
        xaxis_title="net input",
        yaxis_title="σ(z)",
        yaxis=dict(range=[-0.05, 1.05], zeroline=False),
        height=350,
        plot_bgcolor="white",
        margin=dict(l=40, r=20, t=50, b=40),
        showlegend=False,
    )
    _fig_sig
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    ## XOR function

    Let's design NN to learn the XOR function.
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    The **XOR** function is not linearly separable — a single perceptron cannot learn it.
    We need at least one hidden layer.

    | $x_1$ | $x_2$ | $x_1 \oplus x_2$ |
    |:-----:|:-----:|:----------------:|
    | 0 | 0 | 0 |
    | 0 | 1 | 1 |
    | 1 | 0 | 1 |
    | 1 | 1 | 0 |

    **Architecture:** 2 → 4 → 1 with sigmoid activations everywhere.

    **Training:** gradient descent minimising MSE loss,
    implemented from scratch with NumPy so every step is visible.
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.vstack(
        [
            mo.image(
                src="deconstructedxor.png",
                width="70%",
                style={"margin": "0 auto", "display": "block"},
            ),
        ]
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    ### Forward pass in matrix form

    **Input:**
    $$\mathbf{x} = \begin{bmatrix} x_1 \\ x_2 \end{bmatrix} \in \mathbb{R}^2$$

    **Hidden layer** ($2 \to 4$):
    $$\mathbf{z}^{(1)} = W^{(1)}\mathbf{x} + \mathbf{b}^{(1)}$$

    $$\begin{bmatrix} z_1^{(1)} \\ z_2^{(1)} \\ z_3^{(1)} \\ z_4^{(1)} \end{bmatrix} =
    \underbrace{\begin{bmatrix}
      w_{11} & w_{12} \\
      w_{21} & w_{22} \\
      w_{31} & w_{32} \\
      w_{41} & w_{42}
    \end{bmatrix}}_{W^{(1)}\,\in\,\mathbb{R}^{4\times 2}}
    \begin{bmatrix} x_1 \\ x_2 \end{bmatrix}
    +
    \underbrace{\begin{bmatrix} b_1^{(1)} \\ b_2^{(1)} \\ b_3^{(1)} \\ b_4^{(1)} \end{bmatrix}}_{\mathbf{b}^{(1)}\,\in\,\mathbb{R}^4}$$

    $$\mathbf{a}^{(1)} = \sigma\!\left(\mathbf{z}^{(1)}\right) \in \mathbb{R}^4$$

    **Output layer** ($4 \to 1$):
    $$z^{(2)} = \mathbf{w}^{(2)\top}\mathbf{a}^{(1)} + b^{(2)}$$



    $$z^{(2)} =
    \underbrace{\begin{bmatrix} w_1^{(2)} & w_2^{(2)} & w_3^{(2)} & w_4^{(2)}\end{bmatrix}}_{\mathbf{w}^{(2)\top}\,\in\,\mathbb{R}^{1\times 4}}\begin{bmatrix} a_1^{(1)} \\ a_2^{(1)} \\ a_3^{(1)} \\ a_4^{(1)} \end{bmatrix}+ b^{(2)}$$

    $$\hat{y} = \sigma\!\left(z^{(2)}\right) \in [0,1]$$

    **Loss (MSE over the 4 XOR examples):**
    $$\mathcal{L} = \frac{1}{4}\sum_{i=1}^{4}\left(\hat{y}^{(i)} - y^{(i)}\right)^2$$
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    ### Parameters $\Theta$

    All learnable values of the network are collected in:

    $$\Theta = \left\{ W^{(1)},\, \mathbf{b}^{(1)},\, \mathbf{w}^{(2)},\, b^{(2)} \right\}$$

    | Symbol | Shape | Description |
    |:------:|:-----:|:------------|
    | $W^{(1)}$ | $4 \times 2$ | Weight matrix — input → hidden. Row $i$ weights the connections arriving at hidden neuron $i$. |
    | $\mathbf{b}^{(1)}$ | $4 \times 1$ | Bias vector for the hidden layer. One bias per hidden neuron. |
    | $\mathbf{w}^{(2)}$ | $4 \times 1$ | Weight vector — hidden → output. |
    | $b^{(2)}$ | scalar | Bias for the output neuron. |

    Total trainable parameters: $4{\times}2 + 4 + 4 + 1 = \mathbf{17}$.
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    ### Dependency graph
    """)
    return


@app.cell(hide_code=True)
def _(mo):
    mo.vstack(
        [
            mo.image(
                src="depgraph.png",
                width="80%",
                style={"margin": "0 auto", "display": "block"},
            ),
        ]
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    ### Backward propagation

    Backprop applies the **chain rule** from loss back to every parameter in $\Theta$.

    ---

    #### Loss derivative — $\dfrac{\partial \mathcal{L}}{\partial \hat{y}}$

    The loss is the mean squared error over $N$ examples:

    $$\mathcal{L} \;=\; \frac{1}{N}\sum_{i=1}^{N}\bigl(\hat{y}^{(i)} - y^{(i)}\bigr)^{2}$$

    For a single example $i$, only one term in the sum depends on $\hat{y}^{(i)}$, so all other terms vanish when differentiating:

    $$\frac{\partial \mathcal{L}}{\partial \hat{y}^{(i)}}
    \;=\; \frac{1}{N}\,\frac{\partial}{\partial \hat{y}^{(i)}}\bigl(\hat{y}^{(i)} - y^{(i)}\bigr)^{2}
    \;=\; \frac{1}{N}\cdot 2\bigl(\hat{y}^{(i)} - y^{(i)}\bigr)
    \;=\; \frac{2}{N}\bigl(\hat{y}^{(i)} - y^{(i)}\bigr)$$

    Stacking over all $N$ examples gives the vector form:

    $$\boxed{\;\frac{\partial \mathcal{L}}{\partial \hat{\mathbf{y}}}
    \;=\; \frac{2}{N}\bigl(\hat{\mathbf{y}} - \mathbf{y}\bigr) \;\in\; \mathbb{R}^{N\times 1}\;}$$

    Intuition:

    - If the prediction matches the target ($\hat{y} = y$) the gradient is zero — nothing to fix.
    - The sign of $\hat{y} - y$ tells us **which direction** to push $\hat{y}$.
    - The magnitude tells us **how strongly**.

    This vector is the *error signal* that every step below propagates backward through the network.

    ---

    #### Sigmoid derivative

    $$\sigma'(z) \;=\; \sigma(z)\,\bigl(1 - \sigma(z)\bigr)$$

    ---

    #### Step 1 — error at the output, $\delta^{(2)}$

    We define the **output error** as the derivative of the loss with respect to the pre-activation $z^{(2)}$:

    $$\delta^{(2)} \;\triangleq\; \frac{\partial \mathcal{L}}{\partial z^{(2)}}$$

    $\mathcal{L}$ does not depend on $z^{(2)}$ directly — only through $\hat{y} = \sigma(z^{(2)})$. So we apply the **chain rule**:

    $$\frac{\partial \mathcal{L}}{\partial z^{(2)}}
    \;=\; \underbrace{\frac{\partial \mathcal{L}}{\partial \hat{y}}}_{\text{loss derivative}}
    \;\cdot\;
    \underbrace{\frac{\partial \hat{y}}{\partial z^{(2)}}}_{\text{activation derivative}}$$

    We already have the first factor. For the second one, since $\hat{y} = \sigma(z^{(2)})$ and using the sigmoid derivative:

    $$\frac{\partial \hat{y}}{\partial z^{(2)}}
    \;=\; \sigma'(z^{(2)})
    \;=\; \sigma(z^{(2)})\bigl(1 - \sigma(z^{(2)})\bigr)
    \;=\; \hat{y}\,(1 - \hat{y})$$

    Plugging both factors in, and noting both sides are vectors over the $N$ examples so the product is **element-wise** ($\odot$):

    $$\frac{\partial \mathcal{L}}{\partial z^{(2,i)}}
    \;=\; \frac{2}{N}\bigl(\hat{y}^{(i)} - y^{(i)}\bigr)\,\cdot\,\hat{y}^{(i)}\bigl(1 - \hat{y}^{(i)}\bigr)$$

    Stacked into vector form:

    $$\boxed{\;\delta^{(2)} \;=\; \underbrace{\frac{2}{N}(\hat{\mathbf{y}} - \mathbf{y})}_{\partial\mathcal{L}/\partial\hat{\mathbf{y}}}
    \;\odot\; \underbrace{\hat{\mathbf{y}}\,(1-\hat{\mathbf{y}})}_{\sigma'(\mathbf{z}^{(2)})}
    \;\in\; \mathbb{R}^{N\times 1}\;}$$

    Intuition:

    - The first factor says *how wrong* the prediction is.
    - The second factor — the sigmoid slope — is largest near $\hat{y}=0.5$ and tiny near $0$ or $1$. So a confidently-wrong neuron (e.g.\ $\hat{y}=0.99$ but $y=0$) receives a *smaller* gradient than a borderline one. This is the famous **saturation** behaviour of sigmoid networks.

    #### Gradients for output parameters

    Once $\delta^{(2)}$ is known, the parameters that produced $z^{(2)}$ get their gradients by another chain step. Since $z^{(2)} = \mathbf{a}^{(1)}\mathbf{w}^{(2)} + b^{(2)}$:

    $$\frac{\partial \mathcal{L}}{\partial \mathbf{w}^{(2)}} \;=\; {\mathbf{a}^{(1)}}^\top\, \delta^{(2)}, \qquad \frac{\partial \mathcal{L}}{\partial b^{(2)}} \;=\; \mathbf{1}^\top \delta^{(2)}$$

    ---

    #### Step 2 — error at the hidden layer, $\delta^{(1)}$

    We define the **hidden error** as the derivative of the loss with respect to the hidden pre-activation $\mathbf{z}^{(1)}$:

    $$\delta^{(1)} \;\triangleq\; \frac{\partial \mathcal{L}}{\partial \mathbf{z}^{(1)}}$$

    $\mathcal{L}$ does not depend on $\mathbf{z}^{(1)}$ directly. The dependency chain is

    $$\mathbf{z}^{(1)} \;\xrightarrow{\sigma}\; \mathbf{a}^{(1)} \;\xrightarrow{\mathbf{w}^{(2)},\,b^{(2)}}\; z^{(2)} \;\xrightarrow{\sigma}\; \hat{y} \;\xrightarrow{\text{MSE}}\; \mathcal{L}$$

    Everything past $\mathbf{a}^{(1)}$ has already been collapsed into $\delta^{(2)} = \partial\mathcal{L}/\partial z^{(2)}$. So the chain rule reduces to two factors:

    $$\frac{\partial \mathcal{L}}{\partial \mathbf{z}^{(1)}}
    \;=\; \underbrace{\frac{\partial \mathcal{L}}{\partial \mathbf{a}^{(1)}}}_{\text{error reaching the hidden activations}}
    \;\odot\;
    \underbrace{\frac{\partial \mathbf{a}^{(1)}}{\partial \mathbf{z}^{(1)}}}_{\text{activation derivative}}$$

    **Factor 1.** How does the error reach $\mathbf{a}^{(1)}$? Through the output linearity $z^{(2)} = \mathbf{a}^{(1)}\mathbf{w}^{(2)} + b^{(2)}$. For one example, neuron $j$ of the hidden layer is connected to the output by weight $w_j^{(2)}$, so:

    $$\frac{\partial z^{(2)}}{\partial a_j^{(1)}} \;=\; w_j^{(2)}
    \quad\Longrightarrow\quad
    \frac{\partial \mathcal{L}}{\partial a_j^{(1)}} \;=\; \delta^{(2)}\,w_j^{(2)}$$

    Stacked over all 4 hidden neurons and all $N$ examples, this is a single matrix product:

    $$\frac{\partial \mathcal{L}}{\partial \mathbf{a}^{(1)}}
    \;=\; \delta^{(2)}\,{\mathbf{w}^{(2)}}^{\!\top}
    \;\in\; \mathbb{R}^{N\times 4}$$

    Each row $i$ of $\delta^{(2)}$ (a scalar per example) gets spread across the 4 hidden neurons in proportion to ${\mathbf{w}^{(2)}}$.

    **Factor 2.** $\mathbf{a}^{(1)} = \sigma(\mathbf{z}^{(1)})$ element-wise, so the activation derivative is also element-wise:

    $$\frac{\partial \mathbf{a}^{(1)}}{\partial \mathbf{z}^{(1)}} \;=\; \sigma'(\mathbf{z}^{(1)}) \;=\; \mathbf{a}^{(1)}\bigl(1 - \mathbf{a}^{(1)}\bigr)$$

    **Combine.** Multiplying the two factors element-wise:

    $$\boxed{\;\delta^{(1)} \;=\; \underbrace{\delta^{(2)}\,{\mathbf{w}^{(2)}}^{\!\top}}_{\text{routed error},\ N\times 4}
    \;\odot\;
    \underbrace{\mathbf{a}^{(1)}\bigl(1 - \mathbf{a}^{(1)}\bigr)}_{\sigma'(\mathbf{z}^{(1)}),\ N\times 4}
    \;\in\; \mathbb{R}^{N\times 4}\;}$$

    Intuition:

    - A hidden neuron $j$ is "blamed" in proportion to its outgoing weight $w_j^{(2)}$. Hidden neurons that contribute strongly to the output get a strong error signal.
    - The sigmoid factor again kills the signal for saturated hidden units — another source of the **vanishing-gradient** problem in deeper sigmoid networks.

    #### Gradients for hidden parameters

    Once $\delta^{(1)}$ is known, the hidden parameters follow the same pattern as Step 1. Since $\mathbf{z}^{(1)} = \mathbf{x}\,W^{(1)} + \mathbf{b}^{(1)}$ (using the code's row-vector convention):

    $$\frac{\partial \mathcal{L}}{\partial W^{(1)}} \;=\; \mathbf{x}^\top\, \delta^{(1)}, \qquad \frac{\partial \mathcal{L}}{\partial \mathbf{b}^{(1)}} \;=\; \mathbf{1}^\top \delta^{(1)}$$

    ---

    #### Step 3 — gradient descent update

    $$\Theta \;\leftarrow\; \Theta - \eta\,\nabla_{\Theta}\,\mathcal{L}$$

    where $\eta$ is the **learning rate**.
    """)
    return


@app.cell
def _(np):
    # XOR dataset
    _X_xor = np.array([[0,0],[0,1],[1,0],[1,1]], dtype=float)
    _y_xor = np.array([[0],  [1],  [1],  [0]], dtype=float)

    def _sig(z):
        return 1 / (1 + np.exp(-z))

    def _sig_d(z):
        s = _sig(z)
        return s * (1 - s)

    # ---- initialise weights ----
    _rng = np.random.default_rng(42)
    W1_xor = _rng.standard_normal((2, 4)) * 0.5   # 2 inputs  -> 4 hidden
    b1_xor = np.zeros((1, 4))
    W2_xor = _rng.standard_normal((4, 1)) * 0.5   # 4 hidden  -> 1 output
    b2_xor = np.zeros((1, 1))

    # ---- training loop ----
    _lr = 1.0
    _loss_list = []

    for _epoch in range(2200):
        # forward
        _z1 = _X_xor @ W1_xor + b1_xor
        _a1 = _sig(_z1)
        _z2 = _a1 @ W2_xor + b2_xor
        _a2 = _sig(_z2)

        # MSE loss
        _loss = float(np.mean((_a2 - _y_xor) ** 2))
        _loss_list.append(_loss)

        # backward
        _dL_da2 = 2 * (_a2 - _y_xor) / len(_X_xor)
        _dL_dz2 = _dL_da2 * _sig_d(_z2)
        _dL_dW2 = _a1.T @ _dL_dz2
        _dL_db2 = _dL_dz2.sum(axis=0, keepdims=True)

        _dL_da1 = _dL_dz2 @ W2_xor.T
        _dL_dz1 = _dL_da1 * _sig_d(_z1)
        _dL_dW1 = _X_xor.T @ _dL_dz1
        _dL_db1 = _dL_dz1.sum(axis=0, keepdims=True)

        # update
        W2_xor -= _lr * _dL_dW2
        b2_xor = b2_xor - _lr * _dL_db2
        W1_xor -= _lr * _dL_dW1
        b1_xor -= _lr * _dL_db1

    losses_xor = np.array(_loss_list)
    return W1_xor, W2_xor, b1_xor, b2_xor, losses_xor


@app.cell(hide_code=True)
def _(W1_xor, W2_xor, b1_xor, b2_xor, mo):
    mat_W1 = mo.ui.matrix(
        W1_xor.T,
        min_value=-15, max_value=15, step=0.01, precision=3,
        row_labels=["h₁", "h₂", "h₃", "h₄"],
        column_labels=["x₁", "x₂"],
        label=r"$W^{(1)} \in \mathbb{R}^{4 \times 2}$",
        debounce=True,
    )
    mat_b1 = mo.ui.matrix(
        b1_xor.flatten(),
        min_value=-15, max_value=15, step=0.01, precision=3,
        row_labels=["h₁", "h₂", "h₃", "h₄"],
        label=r"$\mathbf{b}^{(1)} \in \mathbb{R}^{4}$",
        debounce=True,
    )
    mat_w2 = mo.ui.matrix(
        W2_xor,
        min_value=-15, max_value=15, step=0.01, precision=3,
        row_labels=["h₁", "h₂", "h₃", "h₄"],
        column_labels=["out"],
        label=r"$\mathbf{w}^{(2)} \in \mathbb{R}^{4}$",
        debounce=True,
    )
    mat_b2 = mo.ui.matrix(
        b2_xor,
        min_value=-15, max_value=15, step=0.01, precision=3,
        row_labels=["bias"],
        column_labels=["out"],
        label=r"$b^{(2)}$",
        debounce=True,
    )

    mo.hstack([mat_W1, mat_b1, mat_w2, mat_b2], gap="2rem", align="start")
    return mat_W1, mat_b1, mat_b2, mat_w2


@app.cell(hide_code=True)
def _(losses_xor, mat_W1, mat_b1, mat_b2, mat_w2, mo, np):
    import plotly.graph_objects as _go_xor

    _W1 = np.asarray(mat_W1.value).T          # widget is 4x2 (math), code needs 2x4
    _b1 = np.asarray(mat_b1.value)             # (4,) flat
    _W2 = np.asarray(mat_w2.value)             # (4,1)
    _b2 = float(np.asarray(mat_b2.value)[0, 0])

    _X_xor_r = np.array([[0,0],[0,1],[1,0],[1,1]], dtype=float)
    _y_xor_r = np.array([0, 1, 1, 0])

    _a1_r = 1 / (1 + np.exp(-(_X_xor_r @ _W1 + _b1)))
    _preds  = (1 / (1 + np.exp(-(_a1_r @ _W2 + _b2)))).flatten()

    _rows = []
    for (xi1, xi2), yt, yp in zip(_X_xor_r.astype(int), _y_xor_r, _preds):
        _ok = "✓" if abs(yp - yt) < 0.5 else "✗"
        _rows.append(f"| {xi1} | {xi2} | {yt} | {yp:.4f} | {_ok} |")

    _table = "\n".join([
        "| $x_1$ | $x_2$ | target | prediction | ok? |",
        "|:-----:|:-----:|:------:|:----------:|:---:|",
    ] + _rows)

    _fig_loss = _go_xor.Figure()
    _fig_loss.add_trace(_go_xor.Scatter(
        y=losses_xor[::50],
        x=list(range(0, len(losses_xor), 50)),
        mode="lines",
        line=dict(color="#1971c2", width=2),
        hovertemplate="epoch %{x}<br>loss %{y:.5f}<extra></extra>",
    ))
    _fig_loss.update_layout(
        title="Training loss (MSE)",
        xaxis_title="epoch",
        yaxis_title="loss",
        height=320,
        plot_bgcolor="white",
        margin=dict(l=40, r=20, t=50, b=40),
    )

    mo.hstack(
        [mo.md(_table), _fig_loss],
        gap="3rem",
        align="start",
    )
    return


@app.cell(hide_code=True)
def _(mo):
    mo.md(r"""
    ### Stepped backward propagation

    In the following demo you can interact with the training of the neural network.

    - **Reset button**: will drop any training done and reset the training to an initial state. Initial values for the parameters are chosen randomly.
    - **Step**: will train 1 epoch.
    - **Step N**: will train $N$ epochs.

    #### Pay attention to:

    - The initial loss will continously decrease when epochs increase.
    -
    """)
    return


@app.cell(hide_code=True)
def _(mo, np):
    def step_init_state():
        _rng = np.random.default_rng(123)
        return {
            "W1": _rng.standard_normal((2, 4)) * 0.5,
            "b1": np.zeros((1, 4)),
            "W2": _rng.standard_normal((4, 1)) * 0.5,
            "b2": np.zeros((1, 1)),
            "dW1": np.zeros((2, 4)),
            "db1": np.zeros((1, 4)),
            "dW2": np.zeros((4, 1)),
            "db2": np.zeros((1, 1)),
            "z1": np.zeros((4, 4)),
            "a1": np.zeros((4, 4)),
            "z2": np.zeros((4, 1)),
            "a2": np.zeros((4, 1)),
            "delta1": np.zeros((4, 4)),
            "delta2": np.zeros((4, 1)),
            "epoch": 0,
            "loss": None,
            "losses": [],
        }

    get_step_state, set_step_state = mo.state(step_init_state())
    return get_step_state, set_step_state, step_init_state


@app.cell(hide_code=True)
def _(get_step_state, mo, np, set_step_state, step_init_state):
    def _one_epoch(s):
        _X = np.array([[0,0],[0,1],[1,0],[1,1]], dtype=float)
        _y = np.array([[0],[1],[1],[0]], dtype=float)
        W1, b1, W2, b2 = s["W1"], s["b1"], s["W2"], s["b2"]

        _z1 = _X @ W1 + b1
        _a1 = 1 / (1 + np.exp(-_z1))
        _z2 = _a1 @ W2 + b2
        _a2 = 1 / (1 + np.exp(-_z2))
        _loss = float(np.mean((_a2 - _y) ** 2))

        _dL_da2 = 2 * (_a2 - _y) / len(_X)
        _delta2 = _dL_da2 * _a2 * (1 - _a2)
        _dW2 = _a1.T @ _delta2
        _db2 = _delta2.sum(axis=0, keepdims=True)

        _dL_da1 = _delta2 @ W2.T
        _delta1 = _dL_da1 * _a1 * (1 - _a1)
        _dW1 = _X.T @ _delta1
        _db1 = _delta1.sum(axis=0, keepdims=True)

        _lr = 1.0
        return {
            "W1": W1 - _lr * _dW1,
            "b1": b1 - _lr * _db1,
            "W2": W2 - _lr * _dW2,
            "b2": b2 - _lr * _db2,
            "dW1": _dW1, "db1": _db1, "dW2": _dW2, "db2": _db2,
            "z1": _z1, "a1": _a1, "z2": _z2, "a2": _a2,
            "delta1": _delta1, "delta2": _delta2,
            "epoch": s["epoch"] + 1,
            "loss": _loss,
            "losses": s["losses"] + [_loss],
        }

    def _do_step(_):
        set_step_state(_one_epoch(get_step_state()))

    def _do_n_steps(_):
        s = get_step_state()
        n = int(n_steps.value)
        for _ in range(n):
            s = _one_epoch(s)
        set_step_state(s)

    def _do_reset(_):
        set_step_state(step_init_state())

    n_steps = mo.ui.number(value=20, start=1, stop=10000, step=1, label="N")
    step_btn = mo.ui.button(label="Step ▶", kind="success", on_change=_do_step)
    step_n_btn = mo.ui.button(label="Step N ▶▶", kind="success", on_change=_do_n_steps)
    reset_step_btn = mo.ui.button(label="↺ Reset", on_change=_do_reset)
    precision_sel = mo.ui.dropdown(
        options=["2", "3", "4", "5", "6", "8"],
        value="4",
        label="decimals",
    )
    show_intermediates = mo.ui.switch(value=False, label="show intermediates")

    mo.hstack(
        [reset_step_btn, step_btn, step_n_btn, n_steps, precision_sel, show_intermediates],
        gap="1rem", justify="start", align="center",
    )
    return precision_sel, show_intermediates


@app.cell(hide_code=True)
def _(get_step_state, mo, np, precision_sel, show_intermediates):
    _s = get_step_state()
    _p = int(precision_sel.value)

    _loss_str = f"{_s['loss']:.{_p}f}" if _s["loss"] is not None else "—"

    _header = mo.md(
        f"**Epoch:** `{_s['epoch']}` &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"**Loss:** `{_loss_str}`"
    )

    _ex_labels = ["(0,0)", "(0,1)", "(1,0)", "(1,1)"]

    def _ro_mat(arr, label, row_labels=None, column_labels=None):
        _a = np.asarray(arr)
        kw = {}
        if row_labels is not None:
            kw["row_labels"] = row_labels
        if column_labels is not None:
            kw["column_labels"] = column_labels
        return mo.ui.matrix(
            _a,
            min_value=-1000, max_value=1000, step=0.01, precision=_p,
            disabled=True,
            label=label,
            **kw,
        )

    _params_row = mo.hstack(
        [
            _ro_mat(_s["W1"].T, r"$W^{(1)}$"),
            _ro_mat(_s["b1"].flatten(), r"$\mathbf{b}^{(1)}$"),
            _ro_mat(_s["W2"], r"$\mathbf{w}^{(2)}$"),
            _ro_mat(_s["b2"], r"$b^{(2)}$"),
        ],
        gap="2rem", align="start",
    )

    _grads_row = mo.hstack(
        [
            _ro_mat(_s["dW1"].T, r"$\partial \mathcal{L} / \partial W^{(1)}$"),
            _ro_mat(_s["db1"].flatten(), r"$\partial \mathcal{L} / \partial \mathbf{b}^{(1)}$"),
            _ro_mat(_s["dW2"], r"$\partial \mathcal{L} / \partial \mathbf{w}^{(2)}$"),
            _ro_mat(_s["db2"], r"$\partial \mathcal{L} / \partial b^{(2)}$"),
        ],
        gap="2rem", align="start",
    )

    _blocks = [
        _header,
        mo.md(r"#### **Parameters $\Theta$**:"),
        _params_row,
        mo.md(r"#### **Gradients $\nabla_\Theta\mathcal{L}$**:"),
        _grads_row,
    ]

    if show_intermediates.value:
        _acts_row = mo.hstack(
            [
                _ro_mat(_s["z1"], r"$\mathbf{z}^{(1)}$",
                        row_labels=_ex_labels,
                        column_labels=["h₁", "h₂", "h₃", "h₄"]),
                _ro_mat(_s["a1"], r"$\mathbf{a}^{(1)}$",
                        row_labels=_ex_labels,
                        column_labels=["h₁", "h₂", "h₃", "h₄"]),
                _ro_mat(_s["z2"], r"$z^{(2)}$",
                        row_labels=_ex_labels, column_labels=["out"]),
                _ro_mat(_s["a2"], r"$\hat{y} = a^{(2)}$",
                        row_labels=_ex_labels, column_labels=["out"]),
            ],
            gap="2rem", align="start",
        )
        _deltas_row = mo.hstack(
            [
                _ro_mat(_s["delta1"], r"$\delta^{(1)}$",
                        row_labels=_ex_labels,
                        column_labels=["h₁", "h₂", "h₃", "h₄"]),
                _ro_mat(_s["delta2"], r"$\delta^{(2)}$",
                        row_labels=_ex_labels, column_labels=["out"]),
            ],
            gap="2rem", align="start",
        )
        _blocks += [
            mo.md(r"#### **Forward activations** (one row per XOR example):"),
            _acts_row,
            mo.md(r"#### **Deltas** $\delta^{(\ell)} = \partial\mathcal{L}/\partial \mathbf{z}^{(\ell)}$:"),
            _deltas_row,
        ]

    mo.vstack(_blocks)
    return


@app.cell
def _():
    import marimo as mo
    import numpy as np
    import matplotlib.pyplot as plt

    return mo, np


if __name__ == "__main__":
    app.run()
