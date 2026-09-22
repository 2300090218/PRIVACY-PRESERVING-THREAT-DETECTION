# Federated Learning Specification

## 1. Overview & Architectural Motivation

Network Intrusion Detection Systems (NIDS) traditionally rely on sending massive volumes of security logs and PCAP captures to a central data warehouse for model training. This centralized paradigm introduces catastrophic privacy risks:
- Sensitive network topology, internal IP allocations, and hostnames are exposed to third-party cloud environments.
- Proprietary customer and internal user communications risk interception or exfiltration.
- Cross-organization collaboration is prohibited by stringent compliance mandates (GDPR, HIPAA).

**Federated Learning (FL)** resolves this challenge by bringing model computation to the data rather than bringing data to the model.

```
       +-------------------------------------------------------------+
       |               CENTRAL FEDERATED ORCHESTRATOR               |
       |  - Maintains Global Model Registry (global-v1, v2...)       |
       |  - Dispatches Global Weights to Registered Clients           |
       |  - Aggregates Client Model Updates via FedAvg               |
       |  - Evaluates Global Metric Performance                      |
       +-------------------------------------------------------------+
                     |                             |
      Dispatch Weights /                  Dispatch Weights /
      Receive Update ΔW1                  Receive Update ΔW2
                     |                             |
                     v                             v
        +-------------------------+   +-------------------------+
        | CLIENT 1: DMZ SENSOR    |   | CLIENT 2: INTERNAL NET  |
        | - Local Flow Telemetry  |   | - Local Flow Telemetry  |
        | - Local Epoch Training  |   | - Local Epoch Training  |
        | - L2 Gradient Clipping  |   | - L2 Gradient Clipping  |
        +-------------------------+   +-------------------------+
```

---

## 2. Mathematical Formulation: Federated Averaging (FedAvg)

The orchestrator implements the canonical **Federated Averaging (FedAvg)** algorithm (McMahan et al.):

Let $K$ be the number of active edge clients, each possessing a private local dataset $\mathcal{D}_k$ with $n_k = |\mathcal{D}_k|$ samples. The total sample count across all participating clients is:

$$n = \sum_{k=1}^K n_k$$

In each federated training round $t$:
1. The server broadcasts the current global parameters $W_t$ to all selected edge clients.
2. Each client $k$ initializes its local model with $W_t$ and executes $E$ local training epochs over mini-batches of its private dataset $\mathcal{D}_k$:
   $$W_{t+1}^k \leftarrow W_t - \eta \nabla \mathcal{L}_k(W_t)$$
3. Each client calculates its model delta or trained parameter matrix $W_{t+1}^k$ and securely transmits $(W_{t+1}^k, n_k)$ back to the orchestrator.
4. The central server computes the sample-weighted average:
   $$W_{t+1} = \sum_{k=1}^K \frac{n_k}{n} W_{t+1}^k$$

---

## 3. Privacy Safeguards in Federated Training

### 3.1 Strict Client-Side Data Retention
- Raw flow events and packet logs are never serialized or transmitted across the wire.
- Inspection of the wire protocol confirms that only parameter matrices and scalar sample counts are sent to `/api/federated/update`.

### 3.2 Gradient / Parameter L2 Norm Clipping
To protect against model inversion attacks and poisoned parameter submissions, client updates are bounded:

$$\bar{\Delta W}_k = \Delta W_k \cdot \min\left(1, \frac{C}{\|\Delta W_k\|_2}\right)$$

Where $C$ is the clipping threshold (default $C = 1.0$).

### 3.3 Differential Privacy (DP-FedAvg)
For environments requiring mathematical differential privacy guarantees, calibrated zero-mean Gaussian noise is added to the aggregated weights:

$$\tilde{W}_{t+1} = W_{t+1} + \mathcal{N}\left(0, \sigma^2 C^2 I\right)$$

---

## 4. Model Versioning & Lifecycle

Every completed federated round creates an immutable snapshot in `model_versions`:

| Field | Description | Example |
| :--- | :--- | :--- |
| `version` | Incremental semantic version | `global-v1`, `global-v2` |
| `training_round` | Round sequence number | `1`, `2`, `3` |
| `accuracy` | Hold-out benchmark accuracy | `0.9729` (97.29%) |
| `precision` | Weighted precision score | `0.9729` (97.29%) |
| `recall` | Weighted recall score | `0.9729` (97.29%) |
| `f1_score` | Harmonic mean F1 score | `0.9726` (97.26%) |
| `status` | Deployment state | `ACTIVE`, `SUPERSEDED`, `ARCHIVED` |

### Rollback & Promotion
Only models that maintain or exceed baseline benchmark metrics on the global hold-out evaluation set are automatically marked `ACTIVE` for real-time live detection. If a federated round degrades detection metrics below threshold, the orchestrator preserves the previous model version and logs an audit alert.

---

## 5. Demonstration & Testing Workflow

To initiate and observe a real federated learning round:
1. Navigate to the **Federated Learning** tab in the web dashboard.
2. Verify that edge clients are `ONLINE` (`client-dmz-01`, `client-finance-02`, `client-cloud-03`).
3. Click **"START FEDERATED ROUND"** or execute:
   ```bash
   curl -X POST http://localhost:8000/api/federated/start \
     -H "Authorization: Bearer <ADMIN_TOKEN>"
   ```
4. Observe the real-time WebSocket progress broadcasts (`training.started`, `training.progress`, `training.completed`, `model.updated`).
5. Verify that the global model version increments and newly evaluated hold-out metrics update on the dashboard without a page refresh.
