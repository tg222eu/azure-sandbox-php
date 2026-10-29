// main.bicepparam
// COMMITTED template - placeholder values only, safe for a public repo.
// For a real deploy, copy this to main.local.bicepparam (gitignored) and put
// your actual SSH public key in it.
using './main.bicep'

param location = 'swedencentral'

// Your SSH PUBLIC key (the contents of sandbox_key.pub). Placeholder here -
// replace in your local copy. This is the public half, safe to share, but we
// keep real infra values out of the committed file on principle.
param adminPublicKey = 'ssh-ed25519 AAAA_REPLACE_WITH_YOUR_PUBLIC_KEY sandbox-key'

// Your public IP /32 allowed to SSH in. Placeholder here (documentation-only
// range); put your REAL IP in main.local.bicepparam, never in this committed
// file. Find it by searching "what is my IP" in a browser.
param adminSourceIp = '203.0.113.4/32'

param adminUsername = 'azureuser'

param namePrefix = 'honeypot'

// Direct SSH is free and on by default; Bastion stays off unless you want it.
// (If you ever set this true, bastionSku defaults to 'Basic' in main.bicep.)
param deployBastion = false

// Deploy FALSE first (setup needs internet), then redeploy TRUE to lock down.
param sealed = false
