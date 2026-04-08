const API_BASE = '/api';

export async function checkUrl(url) {
  const response = await fetch(`${API_BASE}/check-url?url=${encodeURIComponent(url)}`);
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Scan failed' }));
    throw new Error(error.detail || `HTTP ${response.status}`);
  }
  return response.json();
}

export async function getAnalytics() {
  const response = await fetch(`${API_BASE}/analytics`);
  if (!response.ok) throw new Error('Failed to fetch analytics');
  return response.json();
}

export async function getRecentScans(limit = 10) {
  const response = await fetch(`${API_BASE}/recent-scans?limit=${limit}`);
  if (!response.ok) throw new Error('Failed to fetch recent scans');
  return response.json();
}

export async function getSampleUrls() {
  const response = await fetch(`${API_BASE}/sample-urls`);
  if (!response.ok) throw new Error('Failed to fetch sample URLs');
  return response.json();
}
