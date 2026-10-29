// main.bicepparam  —  PARAMETER TEMPLATE (committed, placeholders only)
// ---------------------------------------------------------------------------
// This file is a template. It contains NO real values and is safe to commit.
//
// To deploy:
//   1. Copy this file to  main.local.bicepparam   (gitignored, never pushed)
//   2. In that copy, replace the two <REPLACE_...> values below
//   3. Deploy with:
//        az deployment group create -g <your-rg> -f main.bicep -p main.local.bicepparam
// ---------------------------------------------------------------------------
using './main.bicep'

// Region for all resources.
param location = 'swedencentral'

// --- REPLACE in your local copy -------------------------------------------

// Your SSH PUBLIC key — the full one line from sandbox_key.pub.
// (Public half only. Safe to share; your PRIVATE key never goes in any file.)
param adminPublicKey = '<REPLACE_WITH_CONTENTS_OF_sandbox_key.pub>'

// Your public IP, with /32 on the end, so only you can SSH in.
// Find it: (Invoke-RestMethod ifconfig.me/ip)   or search "what is my IP".
param adminSourceIp = '<REPLACE_WITH_YOUR_PUBLIC_IP>/32'

// --- Usually leave these as-is --------------------------------------------

// Login account created on the VM.
param adminUsername = 'azureuser'

// Prefix for every resource name.
param namePrefix = 'honeypot'

// Deploy FALSE first (first boot needs internet to install everything),
// then redeploy TRUE to seal off egress before exposing the honeypot.
param sealed = false
