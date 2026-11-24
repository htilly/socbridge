// Mock of the CISA KEV and FIRST EPSS feeds. Used by the end-to-end test.
import http from 'node:http';
const kev = { catalogVersion: 'e2e', dateReleased: '2026-11-20T00:00:00Z', count: 1, vulnerabilities: [{ cveID: 'CVE-2024-3094', vendorProject: 'Tukaani', product: 'xz', vulnerabilityName: 'XZ backdoor', dateAdded: '2026-11-18', dueDate: '2026-12-09', knownRansomwareCampaignUse: 'Unknown', requiredAction: 'Downgrade xz.', shortDescription: 'Backdoor.' }] };
const epss = '#model_version:v1,score_date:2026-11-20T00:00:00+0000\ncve,epss,percentile\nCVE-2023-4863,0.6,0.98\nCVE-2024-3094,0.85,0.99\nCVE-2024-6387,0.3,0.97\n';
http.createServer((req, res) => res.end(req.url === '/kev.json' ? JSON.stringify(kev) : epss)).listen(Number(process.env.MOCK_FEEDS_PORT ?? 19230), '127.0.0.1');
