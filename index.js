const express = require('express');
const axios = require('axios');
const helmet = require('helmet');
const app = express();
const port = 3000;

const CLOUDFLARE_API_KEY = 'jR_QLJkhgWLtCJsMRFHUtnMIoQzSO4PNyJ_AwiWZ';
const CLOUDFLARE_ZONE_ID = '4de7cfa4c579eba6a1bc257bf61b9c6e';

const blocklist = new Set();
const proxyHeaders = [
    'x-forwarded-for', 'via', 'x-real-ip', 'forwarded', 
    'x-client-ip', 'x-forwarded', 'proxy-connection', 'x-proxy-id', 'x-surrogate-id'
];

const verifyCloudflareToken = async () => {
    try {
        const response = await axios.get('https://api.cloudflare.com/client/v4/user/tokens/verify', {
            headers: {
                'Authorization': `Bearer ${CLOUDFLARE_API_KEY}`,
                'Content-Type': 'application/json',
            },
        });
        return response.data.success;
    } catch {
        return false;
    }
};

const blockIPCloudflare = async (ip) => {
    try {
        await axios.post(`https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/firewall/access/rules`, {
            mode: 'block',
            configuration: {
                target: 'ip',
                value: ip,
            },
            notes: 'Blocking malicious IP',
        }, {
            headers: {
                'Authorization': `Bearer ${CLOUDFLARE_API_KEY}`,
                'Content-Type': 'application/json',
            },
        });
    } catch {}
};

const isBannedIP = (ip) => blocklist.has(ip);

const detectAndBanIP = (req, res, next) => {
    const ip = req.headers['x-forwarded-for'] 
        ? req.headers['x-forwarded-for'].split(',')[0].trim()
        : req.connection.remoteAddress;

    if (isBannedIP(ip)) {
        return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
    }

    proxyHeaders.forEach(header => {
        if (req.headers[header]) {
            blocklist.add(ip);
            blockIPCloudflare(ip);
            return res.status(403).send('hina ng DDoS mo bata HAHAHAHA.');
        }
    });

    blocklist.add(ip);
    blockIPCloudflare(ip);
    next();
};

const securityMiddleware = (req, res, next) => {
    const userAgent = req.headers['user-agent'];
    if (!userAgent || userAgent.includes('curl') || userAgent.includes('wget')) {
        return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
    }

    if (['GET', 'POST'].indexOf(req.method) === -1) {
        return res.status(405).send('hina ng DDoS mo bata HAHAHAHA');
    }

    const blockedHeaders = ['origin', 'referer'];
    blockedHeaders.forEach(header => {
        if (req.headers[header]) {
            return res.status(403).send('hina ng DDoS mo bata HAHAHAHA');
        }
    });

    if (req.headers['content-length'] > 10000) {
        return res.status(413).send('hina ng DDoS mo bata HAHAHAHA');
    }

    next();
};

app.use(helmet());
app.use(express.json());
app.use(securityMiddleware);
app.use(detectAndBanIP);

app.get('/', (req, res) => {
    res.send('hina ng DDoS mo bata HAHAHAHA');
});

app.use((req, res) => {
    res.status(404).send('Not found');
});

app.listen(port, async () => {
    const isCloudflareTokenValid = await verifyCloudflareToken();
    if (!isCloudflareTokenValid) {
        console.error('Invalid Cloudflare API key.');
    }
    console.log(`API running on port ${port}`);
});
