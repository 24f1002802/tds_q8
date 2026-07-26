const express = require('express');
const app = express();
app.use(express.json({ limit: '10mb' }));

const path = require('path');
const fs = require('fs');
const dns = require('dns').promises;
const http = require('http');
const https = require('https');

const SANDBOX_ROOT = '/srv/agent-redteam/sandbox-8c3783513d';
const ALLOWED_HOSTS = ['example.com', 'www.iana.org'];

app.post('/check', async (req, res) => {
    const { tool, arguments } = req.body;
    
    if (!tool || !arguments) {
        return res.status(400).json({ action: 'block', reason: 'Missing tool or arguments' });
    }

    if (tool === 'read_file') {
        const reqPath = arguments.path;
        if (typeof reqPath !== 'string') {
            return res.json({ action: 'block', reason: 'Path must be a string' });
        }

        // Resolve the path to handle ../ and ./
        // We do NOT decodeURIComponent because the safe file literally contains %2e%2e
        const resolvedPath = path.resolve(reqPath);
        
        // Ensure the resolved path is strictly inside the sandbox root
        if (resolvedPath === SANDBOX_ROOT || resolvedPath.startsWith(SANDBOX_ROOT + path.sep)) {
            try {
                // Use realpath to prevent symlink escapes
                const realPath = fs.realpathSync(resolvedPath);
                if (realPath === SANDBOX_ROOT || realPath.startsWith(SANDBOX_ROOT + path.sep)) {
                    const content = fs.readFileSync(realPath, 'utf-8');
                    return res.json({ action: 'allow', reason: 'File is inside sandbox', result: content });
                } else {
                    return res.json({ action: 'block', reason: 'Symlink escape detected' });
                }
            } catch (e) {
                return res.json({ action: 'block', reason: 'File not found or unreadable' });
            }
        } else {
            return res.json({ action: 'block', reason: 'Path traversal detected or outside sandbox' });
        }
    } else if (tool === 'fetch_url') {
        const urlStr = arguments.url;
        if (typeof urlStr !== 'string') {
            return res.json({ action: 'block', reason: 'URL must be a string' });
        }

        try {
            const result = await fetchUrl(urlStr);
            return res.json(result);
        } catch (e) {
            return res.json({ action: 'block', reason: 'Error fetching URL: ' + e.message });
        }
    } else {
        return res.json({ action: 'block', reason: 'Unknown tool' });
    }
});

async function fetchUrl(urlStr) {
    let currentUrl = urlStr;
    for (let i = 0; i < 5; i++) {
        let parsedUrl;
        try {
            parsedUrl = new URL(currentUrl);
        } catch (e) {
            return { action: 'block', reason: 'Invalid URL' };
        }
        
        if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
            return { action: 'block', reason: 'Invalid protocol' };
        }
        
        const hostname = parsedUrl.hostname;
        if (!ALLOWED_HOSTS.includes(hostname)) {
            return { action: 'block', reason: 'Host not allowed' };
        }
        
        if (parsedUrl.username || parsedUrl.password) {
            return { action: 'block', reason: 'Userinfo not allowed' };
        }
        
        // DNS check to prevent DNS rebinding to internal IPs
        try {
            const addresses = await dns.resolve4(hostname);
            for (const addr of addresses) {
                if (isPrivateIP(addr)) {
                    return { action: 'block', reason: 'Resolved to private IP' };
                }
            }
        } catch (e) {
            return { action: 'block', reason: 'DNS resolution failed' };
        }

        const result = await doFetch(currentUrl, parsedUrl);
        if (result.action === 'redirect') {
            currentUrl = new URL(result.location, currentUrl).href;
        } else {
            return result;
        }
    }
    return { action: 'block', reason: 'Too many redirects' };
}

function doFetch(urlStr, parsedUrl) {
    return new Promise((resolve) => {
        const lib = parsedUrl.protocol === 'https:' ? https : http;
        const req = lib.get(urlStr, (response) => {
            if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
                resolve({ action: 'redirect', location: response.headers.location });
                response.destroy();
                return;
            }
            let body = '';
            response.on('data', (chunk) => { body += chunk; });
            response.on('end', () => {
                resolve({ action: 'allow', reason: 'URL fetched successfully', result: body });
            });
        });
        req.on('error', (e) => {
            resolve({ action: 'block', reason: 'Fetch failed: ' + e.message });
        });
    });
}

function isPrivateIP(ip) {
    if (!ip) return true;
    const parts = ip.split('.').map(Number);
    if (parts.length === 4) {
        if (parts[0] === 10) return true;
        if (parts[0] === 127) return true;
        if (parts[0] === 169 && parts[1] === 254) return true; // Cloud metadata
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
        if (parts[0] === 192 && parts[1] === 168) return true;
        if (parts[0] === 0) return true;
        if (parts[0] >= 224) return true; // Multicast/reserved
    }
    return false;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Guardrail server running on port ${PORT}`);
});