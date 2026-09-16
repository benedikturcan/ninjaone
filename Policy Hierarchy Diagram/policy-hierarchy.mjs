// Credentials are read from environment variables so they never end up in the repository:
//   NINJA_REGION         e.g. 'eu' (default), 'app', 'ca', 'oc'
//   NINJA_CLIENT_ID      OAuth client ID (client_credentials, scope: monitoring)
//   NINJA_CLIENT_SECRET  OAuth client secret
//   NINJA_SESSION_KEY    sessionKey cookie of a logged-in web session (used for /swb/s4/policy)
const baseUrl = process.env.NINJA_REGION || 'eu';
const clientId = process.env.NINJA_CLIENT_ID;
const clientSecret = process.env.NINJA_CLIENT_SECRET;
const tokenUrl = `https://${baseUrl}.ninjarmm.com/ws`;
const apiUrl = `https://${baseUrl}.ninjarmm.com`;
// Global (system) WYSIWYG custom field that receives the combined report
const customFieldName = 'policyHierarchyReport';

// 'management' is required to write custom field values
async function fetchToken(scope = 'monitoring management') {
  const response = await fetch(`${tokenUrl}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: clientId,
      client_secret: clientSecret,
      scope,
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error('Token error response:', errorBody);
    throw new Error(`Token request failed: ${response.status} ${response.statusText}`);
  }

  const data = await response.json();
  return data.access_token;
}

const sessionKey = process.env.NINJA_SESSION_KEY;

let cachedToken = null;

async function fetchWithAuth(endpoint, options = {}) {
  if (!cachedToken) cachedToken = await fetchToken();
  const response = await fetch(`${apiUrl}${endpoint}`, {
    ...options,
    headers: {
      'Accept': 'application/json',
      ...options.headers,
      'Authorization': `Bearer ${cachedToken}`,
    },
  });

  if (!response.ok) {
    throw new Error(`API request failed: ${endpoint} ${response.status} ${response.statusText}`);
  }

  return response.json();
}

async function updateGlobalCustomField(fieldName, html) {
  if (!cachedToken) cachedToken = await fetchToken();
  const response = await fetch(`${apiUrl}/v2/system/custom-fields`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${cachedToken}`,
    },
    body: JSON.stringify({ [fieldName]: { html } }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    console.error('Custom field error response:', errorBody);
    throw new Error(`Custom field update failed: ${fieldName} ${response.status} ${response.statusText}`);
  }
}

async function fetchWithSession(policyId) {
  const response = await fetch(`${apiUrl}/swb/s4/policy/${policyId}`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'Cookie': `sessionKey=${sessionKey}`,
    },
  });

  if (!response.ok) {
    throw new Error(`Session API failed: /swb/s4/policy/${policyId} ${response.status} ${response.statusText}`);
  }

  return response.json();
}

function resolveName(key, value) {
  if (value.conditionName) return value.displayName ? `${value.displayName} (${key.slice(0, 8)})` : `${value.conditionName} (${key.slice(0, 8)})`;
  if (value.actionsetScheduleName) return `${value.actionsetScheduleName} (${key.slice(0, 8)})`;
  return key;
}

function extractOverrides(content, path = '') {
  const overrides = [];

  for (const [key, value] of Object.entries(content)) {
    const label = (value && typeof value === 'object') ? resolveName(key, value) : key;
    const currentPath = path ? `${path} › ${label}` : label;

    if (value && typeof value === 'object') {
      if (value.inheritance) {
        const inh = value.inheritance;
        if (inh.overridden === true || inh.inherited === false) {
          overrides.push({
            section: currentPath,
            overridden: inh.overridden,
            inherited: inh.inherited,
            sourcePolicyId: inh.sourcePolicyId,
          });
        }
      }

      if (!value.inheritance || typeof value === 'object') {
        const nested = extractOverrides(value, currentPath);
        overrides.push(...nested);
      }
    }
  }

  return overrides;
}

async function fetchChildPolicyOverrides(childPolicies) {
  const results = [];
  const batchSize = 5;

  for (let i = 0; i < childPolicies.length; i += batchSize) {
    const batch = childPolicies.slice(i, i + batchSize);
    const batchResults = await Promise.all(
      batch.map(async (policy) => {
        try {
          const data = await fetchWithSession(policy.id);
          const overrides = extractOverrides(data.policy.content);
          const uniqueSections = [...new Set(overrides.map(o => o.section.split(' › ')[0]))];
          return {
            policyId: policy.id,
            policyName: policy.name,
            parentPolicyId: policy.parentPolicyId,
            nodeClass: policy.nodeClass,
            overrides,
            overriddenSections: uniqueSections,
          };
        } catch (err) {
          return {
            policyId: policy.id,
            policyName: policy.name,
            parentPolicyId: policy.parentPolicyId,
            nodeClass: policy.nodeClass,
            overrides: [],
            overriddenSections: [],
            error: err.message,
          };
        }
      })
    );
    results.push(...batchResults);
  }

  return results;
}

function getPolicyChain(policyId, policyMap) {
  const chain = [];
  let current = policyMap.get(policyId);
  while (current) {
    chain.unshift(current);
    current = current.parentPolicyId ? policyMap.get(current.parentPolicyId) : null;
  }
  return chain;
}

async function fetchOverrideDetails(overrides, policyMap) {
  const devicePromises = overrides.results.map(async (entry) => {
    try {
      const device = await fetchWithAuth(`/v2/device/${entry.deviceId}`);
      const chain = getPolicyChain(device.policyId, policyMap);
      return {
        deviceId: entry.deviceId,
        deviceName: device.displayName || device.systemName || `Device ${entry.deviceId}`,
        nodeClass: device.nodeClass,
        policyId: device.policyId,
        policyChain: chain.map(p => p.name),
        overrides: entry.overrides,
      };
    } catch (err) {
      return {
        deviceId: entry.deviceId,
        deviceName: `Device ${entry.deviceId} (nicht erreichbar)`,
        nodeClass: 'UNKNOWN',
        policyId: null,
        policyChain: [],
        overrides: entry.overrides,
      };
    }
  });

  return Promise.all(devicePromises);
}

function buildPolicyTree(policies) {
  const policyMap = new Map();
  policies.forEach(p => policyMap.set(p.id, { ...p, children: [] }));

  const roots = [];
  policies.forEach(p => {
    if (p.parentPolicyId && policyMap.has(p.parentPolicyId)) {
      policyMap.get(p.parentPolicyId).children.push(policyMap.get(p.id));
    } else {
      roots.push(policyMap.get(p.id));
    }
  });

  return roots;
}

function generateOrgChartHTML(tree) {
  const renderNode = (policy, depth = 0) => {
    const badge = depth === 0 ? 'parent' : depth === 1 ? 'child' : 'child-child';
    const badgeLabel = depth === 0 ? 'Parent' : depth === 1 ? 'Child' : 'Child-Child';
    const ncClass = policy.nodeClass ? policy.nodeClass.toLowerCase().replace(/_/g, '-') : '';
    const hasChildren = policy.children && policy.children.length > 0;
    const childrenHtml = hasChildren
      ? `<ul>${policy.children
          .sort((a, b) => a.name.localeCompare(b.name))
          .map(c => renderNode(c, depth + 1))
          .join('')}</ul>`
      : '';

    return `<li>
      <div class="node-row">
        <div class="connector"></div>
        <div class="node ${badge}">
          <div class="node-name">${policy.name}</div>
          <div class="node-meta">
            <span class="node-badge ${badge}">${badgeLabel}</span>
            <span class="node-nc ${ncClass}">${policy.nodeClass}</span>
            <span class="node-id">ID: ${policy.id}</span>
          </div>
          ${hasChildren ? `<div class="node-children-count">${policy.children.length} child${policy.children.length > 1 ? 'ren' : ''}</div>` : ''}
        </div>
      </div>
      ${childrenHtml}
    </li>`;
  };

  const treeHtml = tree
    .sort((a, b) => a.name.localeCompare(b.name))
    .map(p => renderNode(p))
    .join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Policy Org Chart</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      padding: 2rem;
      overflow-x: auto;
    }
    h1 {
      font-size: 1.8rem;
      font-weight: 800;
      margin-bottom: 0.3rem;
    }
    .subtitle {
      color: #64748b;
      font-size: 0.9rem;
      margin-bottom: 2rem;
    }
    .controls {
      margin-bottom: 1.5rem;
      display: flex;
      gap: 0.5rem;
      flex-wrap: wrap;
    }
    .controls button {
      padding: 0.4rem 1rem;
      border-radius: 0.5rem;
      border: 1px solid #334155;
      background: #1e293b;
      color: #e2e8f0;
      cursor: pointer;
      font-size: 0.8rem;
      transition: all 0.2s;
    }
    .controls button:hover { background: #334155; }
    .controls input {
      padding: 0.4rem 0.8rem;
      border-radius: 0.5rem;
      border: 1px solid #334155;
      background: #1e293b;
      color: #e2e8f0;
      font-size: 0.8rem;
      width: 250px;
    }

    /* Horizontal left-to-right tree */
    .tree ul {
      list-style: none;
      padding-left: 30px;
      margin: 0;
      position: relative;
    }
    .tree > ul { padding-left: 0; }

    /* Vertical line: drawn dynamically via JS as .vline elements */
    .vline {
      position: absolute;
      left: 0;
      width: 0;
      border-left: 2px solid #334155;
      pointer-events: none;
    }

    .tree li {
      position: relative;
    }

    /* Top-level items */
    .tree > ul > li > .node-row > .connector { display: none; }

    .node-row {
      display: flex;
      align-items: center;
      position: relative;
      padding: 4px 0;
    }

    /* The connector draws the horizontal arm from the vertical UL line to the node */
    .connector {
      width: 30px;
      min-width: 30px;
      position: relative;
    }
    .connector::after {
      content: '';
      position: absolute;
      top: 50%;
      left: -30px;
      width: 30px;
      border-top: 2px solid #334155;
    }

    /* Node card */
    .node {
      display: inline-block;
      border: 1px solid #334155;
      border-radius: 0.75rem;
      padding: 0.5rem 0.8rem;
      background: #1e293b;
      min-width: 200px;
      max-width: 320px;
      transition: all 0.2s;
      cursor: default;
      vertical-align: middle;
    }
    .node:hover { border-color: #6366f1; transform: translateX(3px); box-shadow: 0 4px 12px rgba(99,102,241,0.2); }
    .node.parent { border-left: 4px solid #6366f1; }
    .node.child { border-left: 4px solid #22d3ee; }
    .node.child-child { border-left: 4px solid #a78bfa; }

    .node-name {
      font-weight: 600;
      font-size: 0.78rem;
      margin-bottom: 0.25rem;
      word-break: break-word;
      line-height: 1.3;
    }
    .node-meta {
      display: flex;
      gap: 0.25rem;
      flex-wrap: wrap;
      margin-bottom: 0.15rem;
    }
    .node-badge {
      display: inline-block;
      padding: 0.1rem 0.35rem;
      border-radius: 0.25rem;
      font-size: 0.6rem;
      font-weight: 600;
    }
    .node-badge.parent { background: #312e81; color: #a5b4fc; }
    .node-badge.child { background: #164e63; color: #67e8f9; }
    .node-badge.child-child { background: #2e1065; color: #c4b5fd; }

    .node-nc {
      display: inline-block;
      padding: 0.1rem 0.35rem;
      border-radius: 0.25rem;
      font-size: 0.6rem;
      font-weight: 500;
      font-family: 'SF Mono', 'Fira Code', monospace;
      background: #334155;
      color: #e2e8f0;
    }
    .node-nc.windows-workstation { background: #1e3a5f; color: #7dd3fc; }
    .node-nc.windows-server { background: #3b1764; color: #d8b4fe; }
    .node-nc.mac { background: #365314; color: #bef264; }
    .node-nc.linux-workstation, .node-nc.linux-server { background: #713f12; color: #fde047; }

    .node-id {
      font-size: 0.55rem;
      color: #64748b;
      font-family: 'SF Mono', 'Fira Code', monospace;
    }
    .node-children-count {
      font-size: 0.6rem;
      color: #94a3b8;
      margin-top: 0.1rem;
    }

    .collapsed > ul { display: none; }
    .collapsed > .node { opacity: 0.7; }
    .collapsed > .node::after {
      content: ' ▸';
      font-size: 0.7rem;
      color: #6366f1;
    }

    .highlight .node { border-color: #fbbf24 !important; box-shadow: 0 0 12px rgba(251,191,36,0.4) !important; }

    /* Spacing between root-level policy trees */
    .tree > ul > li { margin-bottom: 1.5rem; }
    .tree > ul > li:last-child { margin-bottom: 0; }
  </style>
</head>
<body>
  <h1>Policy Inheritance Org Chart</h1>
  <p class="subtitle">Visual hierarchy of all policy parent-child relationships — read left to right</p>

  <div class="controls">
    <input type="text" id="search" placeholder="Search policy..." oninput="searchNodes()">
    <button onclick="expandAll()">Expand All</button>
    <button onclick="collapseAll()">Collapse All</button>
    <button onclick="collapseToParents()">Parents Only</button>
  </div>

  <div class="tree">
    <ul>
      ${treeHtml}
    </ul>
  </div>

  <script>
    function drawLines() {
      document.querySelectorAll('.vline').forEach(el => el.remove());

      document.querySelectorAll('.tree ul').forEach(ul => {
        if (ul.parentElement.classList.contains('tree')) return;
        const children = Array.from(ul.children).filter(li => li.tagName === 'LI');
        if (children.length === 0) return;

        const firstRow = children[0].querySelector('.node-row');
        const lastRow = children[children.length - 1].querySelector('.node-row');
        if (!firstRow || !lastRow) return;

        const ulRect = ul.getBoundingClientRect();
        const firstRect = firstRow.getBoundingClientRect();
        const lastRect = lastRow.getBoundingClientRect();

        const top = firstRect.top + firstRect.height / 2 - ulRect.top;
        const bottom = lastRect.top + lastRect.height / 2 - ulRect.top;

        const vline = document.createElement('div');
        vline.className = 'vline';
        vline.style.top = top + 'px';
        vline.style.height = (bottom - top) + 'px';
        ul.appendChild(vline);
      });
    }

    document.querySelectorAll('.node').forEach(node => {
      node.addEventListener('click', () => {
        const li = node.closest('li');
        if (li.querySelector('ul')) {
          li.classList.toggle('collapsed');
          requestAnimationFrame(drawLines);
        }
      });
    });

    function expandAll() {
      document.querySelectorAll('.collapsed').forEach(el => el.classList.remove('collapsed'));
      requestAnimationFrame(drawLines);
    }

    function collapseAll() {
      document.querySelectorAll('li').forEach(li => {
        if (li.querySelector('ul')) li.classList.add('collapsed');
      });
      requestAnimationFrame(drawLines);
    }

    function collapseToParents() {
      document.querySelectorAll('li').forEach(li => {
        if (li.querySelector('ul')) li.classList.add('collapsed');
      });
      document.querySelectorAll('.tree > ul > li').forEach(li => {
        li.classList.remove('collapsed');
      });
      requestAnimationFrame(drawLines);
    }

    function searchNodes() {
      const query = document.getElementById('search').value.toLowerCase();
      document.querySelectorAll('.highlight').forEach(el => el.classList.remove('highlight'));
      if (!query) { drawLines(); return; }

      document.querySelectorAll('.collapsed').forEach(el => el.classList.remove('collapsed'));

      document.querySelectorAll('.node-name').forEach(nameEl => {
        if (nameEl.textContent.toLowerCase().includes(query)) {
          const li = nameEl.closest('li');
          li.classList.add('highlight');
          let parent = li.parentElement?.closest('li');
          while (parent) {
            parent.classList.remove('collapsed');
            parent = parent.parentElement?.closest('li');
          }
        }
      });
      requestAnimationFrame(drawLines);
    }

    drawLines();
    window.addEventListener('resize', drawLines);
  </script>
</body>
</html>`;
}

function generateHTML(tree, overrideDetails = [], childPolicyOverrides = [], policyMap = new Map()) {
  const renderRow = (policy, depth = 0) => {
    const indent = depth > 0 ? `<span class="indent">${'│  '.repeat(depth - 1)}├─ </span>` : '';
    const badge = depth === 0
      ? `<span class="badge parent">Parent</span>`
      : depth === 1
        ? `<span class="badge child">Child</span>`
        : `<span class="badge child-child">Child-Child</span>`;
    const defaultBadge = policy.nodeClassDefault
      ? `<span class="badge default">Default</span>`
      : '';
    const childCount = depth === 0 && policy.children.length > 0
      ? `<span class="child-count">${policy.children.length}</span>`
      : '';

    let rows = `
      <tr class="${depth === 0 ? 'parent-row' : 'child-row'}">
        <td class="name-cell">${indent}${policy.name} ${childCount}</td>
        <td>${policy.id}</td>
        <td>${badge} ${defaultBadge}</td>
        <td><span class="node-class ${policy.nodeClass.toLowerCase().replace(/_/g, '-')}">${policy.nodeClass}</span></td>
        <td>${new Date(policy.updated * 1000).toLocaleDateString('en-US')}</td>
      </tr>`;

    policy.children
      .sort((a, b) => a.name.localeCompare(b.name))
      .forEach(child => { rows += renderRow(child, depth + 1); });

    return rows;
  };

  const tableRows = tree
    .sort((a, b) => a.name.localeCompare(b.name))
    .map(p => renderRow(p))
    .join('');

  const totalPolicies = tree.reduce((sum, p) => sum + 1 + p.children.length, 0);
  const parentCount = tree.length;
  const childCount = totalPolicies - parentCount;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Policy Dependencies</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      padding: 2rem;
    }
    h1 {
      font-size: 1.8rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      color: #f8fafc;
    }
    .subtitle {
      color: #94a3b8;
      margin-bottom: 2rem;
      font-size: 0.9rem;
    }
    .stats {
      display: flex;
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .stat-card {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 0.75rem;
      padding: 1rem 1.5rem;
      min-width: 140px;
    }
    .stat-card .value {
      font-size: 1.8rem;
      font-weight: 700;
      color: #f8fafc;
    }
    .stat-card .label {
      font-size: 0.8rem;
      color: #94a3b8;
      margin-top: 0.25rem;
    }
    .filter-bar {
      display: flex;
      gap: 0.5rem;
      margin-bottom: 1.5rem;
      flex-wrap: wrap;
    }
    .filter-bar input {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 0.5rem;
      padding: 0.5rem 1rem;
      color: #e2e8f0;
      font-size: 0.85rem;
      width: 300px;
      outline: none;
    }
    .filter-bar input:focus { border-color: #6366f1; }
    .filter-bar select {
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 0.5rem;
      padding: 0.5rem 1rem;
      color: #e2e8f0;
      font-size: 0.85rem;
      outline: none;
      cursor: pointer;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      background: #1e293b;
      border-radius: 0.75rem;
      overflow: hidden;
      border: 1px solid #334155;
    }
    thead th {
      background: #0f172a;
      padding: 0.75rem 1rem;
      text-align: left;
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: #94a3b8;
      font-weight: 600;
      border-bottom: 1px solid #334155;
    }
    tbody td {
      padding: 0.6rem 1rem;
      font-size: 0.85rem;
      border-bottom: 1px solid #1e293b;
    }
    .parent-row { background: #1e293b; }
    .parent-row td { font-weight: 600; border-bottom: 1px solid #334155; }
    .child-row { background: #162032; }
    .child-row td { color: #cbd5e1; }
    tr:hover td { background: #253349; }
    .name-cell { white-space: nowrap; font-family: 'SF Mono', 'Fira Code', monospace; }
    .indent { color: #475569; }
    .badge {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 9999px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .badge.parent { background: #312e81; color: #a5b4fc; }
    .badge.child { background: #1e3a5f; color: #7dd3fc; }
    .badge.child-child { background: #4a1d6a; color: #e0b0ff; }
    .badge.default { background: #365314; color: #bef264; margin-left: 0.25rem; }
    .child-count {
      display: inline-block;
      background: #6366f1;
      color: #fff;
      font-size: 0.65rem;
      font-weight: 700;
      padding: 0.1rem 0.45rem;
      border-radius: 9999px;
      margin-left: 0.4rem;
      vertical-align: middle;
    }
    .node-class {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 0.375rem;
      font-size: 0.7rem;
      font-weight: 500;
      font-family: 'SF Mono', 'Fira Code', monospace;
      background: #334155;
      color: #e2e8f0;
    }
    .node-class.windows-workstation { background: #1e3a5f; color: #7dd3fc; }
    .node-class.windows-server { background: #3b1764; color: #d8b4fe; }
    .node-class.mac { background: #365314; color: #bef264; }
    .node-class.linux-workstation, .node-class.linux-server { background: #713f12; color: #fde047; }
    .node-class.nms-router, .node-class.nms-switch, .node-class.nms-other { background: #7c2d12; color: #fdba74; }

    .section-divider {
      margin: 3rem 0 2rem;
      border-top: 1px solid #334155;
      padding-top: 2rem;
    }
    h2 {
      font-size: 1.4rem;
      font-weight: 700;
      margin-bottom: 0.5rem;
      color: #f8fafc;
    }
    .breadcrumb {
      display: flex;
      align-items: center;
      gap: 0.3rem;
      flex-wrap: wrap;
    }
    .breadcrumb span {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 0.375rem;
      font-size: 0.7rem;
      font-family: 'SF Mono', 'Fira Code', monospace;
    }
    .breadcrumb .chain-item { background: #334155; color: #e2e8f0; }
    .breadcrumb .chain-current { background: #6366f1; color: #fff; font-weight: 600; }
    .breadcrumb .chain-sep { color: #475569; font-size: 0.75rem; padding: 0; }
    .override-chip {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 0.375rem;
      font-size: 0.7rem;
      font-weight: 500;
      margin: 0.1rem 0.2rem;
      background: #7c2d12;
      color: #fdba74;
    }
    .override-row td { border-bottom: 1px solid #253349; }
    .override-row:hover td { background: #253349; }
    .stat-card.warn { border-color: #b45309; }
    .stat-card.warn .value { color: #fbbf24; }
    .stat-card.info { border-color: #6366f1; }
    .stat-card.info .value { color: #a5b4fc; }
    .override-detail {
      font-size: 0.7rem;
      color: #94a3b8;
      font-family: 'SF Mono', 'Fira Code', monospace;
      margin: 0.1rem 0;
    }
    .section-group {
      margin-bottom: 0.3rem;
    }
    .section-group-title {
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 0.375rem;
      font-size: 0.7rem;
      font-weight: 600;
      background: #312e81;
      color: #a5b4fc;
      margin: 0.1rem 0.2rem;
    }
    .section-sub {
      display: inline-block;
      padding: 0.1rem 0.4rem;
      border-radius: 0.25rem;
      font-size: 0.65rem;
      background: #1e293b;
      color: #94a3b8;
      margin: 0.1rem 0.15rem;
      border: 1px solid #334155;
    }
  </style>
</head>
<body>
  <h1>Policy Dependencies</h1>
  <p class="subtitle">Parent-child relationships of all policies</p>

  <div class="stats">
    <div class="stat-card"><div class="value">${totalPolicies}</div><div class="label">Total Policies</div></div>
    <div class="stat-card"><div class="value">${parentCount}</div><div class="label">Parent Policies</div></div>
    <div class="stat-card"><div class="value">${childCount}</div><div class="label">Child Policies</div></div>
    <div class="stat-card warn"><div class="value">${overrideDetails.length}</div><div class="label">Devices with Overrides</div></div>
    <div class="stat-card info"><div class="value">${childPolicyOverrides.filter(c => c.overriddenSections.length > 0).length}</div><div class="label">Child Policies with Overrides</div></div>
  </div>

  <div class="filter-bar">
    <input type="text" id="search" placeholder="Search policy..." oninput="filterTable()">
    <select id="nodeClassFilter" onchange="filterTable()">
      <option value="">All Node Classes</option>
    </select>
    <select id="typeFilter" onchange="filterTable()">
      <option value="">All Types</option>
      <option value="parent">Parents Only</option>
      <option value="child">Children Only</option>
    </select>
  </div>

  <table>
    <thead>
      <tr>
        <th>Policy Name</th>
        <th>ID</th>
        <th>Type</th>
        <th>Node Class</th>
        <th>Updated</th>
      </tr>
    </thead>
    <tbody id="policyTable">
      ${tableRows}
    </tbody>
  </table>

  <script>
    const rows = document.querySelectorAll('#policyTable tr');
    const nodeClasses = new Set();
    rows.forEach(row => {
      const nc = row.querySelector('.node-class');
      if (nc) nodeClasses.add(nc.textContent);
    });
    const select = document.getElementById('nodeClassFilter');
    [...nodeClasses].sort().forEach(nc => {
      const opt = document.createElement('option');
      opt.value = nc;
      opt.textContent = nc;
      select.appendChild(opt);
    });

    function filterTable() {
      const search = document.getElementById('search').value.toLowerCase();
      const ncFilter = document.getElementById('nodeClassFilter').value;
      const typeFilter = document.getElementById('typeFilter').value;

      rows.forEach(row => {
        const name = row.querySelector('.name-cell')?.textContent.toLowerCase() || '';
        const nc = row.querySelector('.node-class')?.textContent || '';
        const isParent = row.classList.contains('parent-row');

        let show = true;
        if (search && !name.includes(search)) show = false;
        if (ncFilter && nc !== ncFilter) show = false;
        if (typeFilter === 'parent' && !isParent) show = false;
        if (typeFilter === 'child' && isParent) show = false;

        row.style.display = show ? '' : 'none';
      });
    }
  </script>

  <div class="section-divider">
    <h2>Policy Overrides per Device</h2>
    <p class="subtitle">Devices with overridden policy sections and their policy hierarchy</p>
  </div>

  <div class="filter-bar">
    <input type="text" id="overrideSearch" placeholder="Search device or policy..." oninput="filterOverrides()">
    <select id="overrideSectionFilter" onchange="filterOverrides()">
      <option value="">All Sections</option>
    </select>
  </div>

  <table>
    <thead>
      <tr>
        <th>Device</th>
        <th>Policy Hierarchy</th>
        <th>Node Class</th>
        <th>Overridden Sections</th>
      </tr>
    </thead>
    <tbody id="overrideTable">
      ${overrideDetails
        .sort((a, b) => a.deviceName.localeCompare(b.deviceName))
        .map(d => {
          const chainHtml = d.policyChain.length > 0
            ? '<div class="breadcrumb">' + d.policyChain.map((name, i) =>
                i < d.policyChain.length - 1
                  ? `<span class="chain-item">${name}</span><span class="chain-sep">›</span>`
                  : `<span class="chain-current">${name}</span>`
              ).join('') + '</div>'
            : '<span style="color:#64748b">No Policy</span>';
          const overrideChips = d.overrides
            .map(o => `<span class="override-chip">${o}</span>`)
            .join('');
          const ncClass = d.nodeClass ? d.nodeClass.toLowerCase().replace(/_/g, '-') : '';
          return `<tr class="override-row" data-sections="${d.overrides.join(',')}">
            <td><strong>${d.deviceName}</strong><br><span style="color:#64748b;font-size:0.75rem">ID: ${d.deviceId}</span></td>
            <td>${chainHtml}</td>
            <td><span class="node-class ${ncClass}">${d.nodeClass || 'N/A'}</span></td>
            <td>${overrideChips}</td>
          </tr>`;
        }).join('')}
    </tbody>
  </table>

  <script>
    const overrideRows = document.querySelectorAll('#overrideTable tr');
    const sections = new Set();
    overrideRows.forEach(row => {
      (row.dataset.sections || '').split(',').forEach(s => { if (s) sections.add(s); });
    });
    const sectionSelect = document.getElementById('overrideSectionFilter');
    [...sections].sort().forEach(s => {
      const opt = document.createElement('option');
      opt.value = s;
      opt.textContent = s;
      sectionSelect.appendChild(opt);
    });

    function filterOverrides() {
      const search = document.getElementById('overrideSearch').value.toLowerCase();
      const sectionFilter = document.getElementById('overrideSectionFilter').value;

      overrideRows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const rowSections = row.dataset.sections || '';

        let show = true;
        if (search && !text.includes(search)) show = false;
        if (sectionFilter && !rowSections.includes(sectionFilter)) show = false;

        row.style.display = show ? '' : 'none';
      });
    }
  </script>

  <div class="section-divider">
    <h2>Child-Policy Overrides</h2>
    <p class="subtitle">Sections overridden by child policies from their parent policies</p>
  </div>

  <div class="filter-bar">
    <input type="text" id="childOverrideSearch" placeholder="Search child policy..." oninput="filterChildOverrides()">
    <select id="childSectionFilter" onchange="filterChildOverrides()">
      <option value="">All Sections</option>
    </select>
  </div>

  <table>
    <thead>
      <tr>
        <th>Child Policy</th>
        <th>Policy Hierarchy</th>
        <th>Node Class</th>
        <th>Overridden Sections</th>
      </tr>
    </thead>
    <tbody id="childOverrideTable">
      ${childPolicyOverrides
        .filter(c => c.overriddenSections.length > 0)
        .sort((a, b) => a.policyName.localeCompare(b.policyName))
        .map(c => {
          const chain = getPolicyChain(c.policyId, policyMap);
          const chainHtml = chain.length > 0
            ? '<div class="breadcrumb">' + chain.map((p, i) =>
                i < chain.length - 1
                  ? `<span class="chain-item">${p.name}</span><span class="chain-sep">›</span>`
                  : `<span class="chain-current">${p.name}</span>`
              ).join('') + '</div>'
            : `<span class="chain-current">${c.policyName}</span>`;

          const groupedOverrides = {};
          c.overrides.forEach(o => {
            const parts = o.section.split(' › ');
            const topLevel = parts[0];
            if (!groupedOverrides[topLevel]) groupedOverrides[topLevel] = [];
            if (parts.length > 1) {
              groupedOverrides[topLevel].push(parts.slice(1).join(' › '));
            }
          });

          const sectionHtml = Object.entries(groupedOverrides)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([section, subs]) => {
              const subHtml = subs.length > 0
                ? subs.map(s => `<span class="section-sub">${s}</span>`).join('')
                : '';
              return `<div class="section-group"><span class="section-group-title">${section}</span>${subHtml}</div>`;
            }).join('');

          const ncClass = c.nodeClass ? c.nodeClass.toLowerCase().replace(/_/g, '-') : '';
          return `<tr class="override-row" data-sections="${c.overriddenSections.join(',')}">
            <td><strong>${c.policyName}</strong><br><span style="color:#64748b;font-size:0.75rem">ID: ${c.policyId}</span></td>
            <td>${chainHtml}</td>
            <td><span class="node-class ${ncClass}">${c.nodeClass || 'N/A'}</span></td>
            <td>${sectionHtml}</td>
          </tr>`;
        }).join('')}
    </tbody>
  </table>

  <script>
    const childRows = document.querySelectorAll('#childOverrideTable tr');
    const childSections = new Set();
    childRows.forEach(row => {
      (row.dataset.sections || '').split(',').forEach(s => { if (s) childSections.add(s); });
    });
    const childSectionSelect = document.getElementById('childSectionFilter');
    [...childSections].sort().forEach(s => {
      const opt = document.createElement('option');
      opt.value = s;
      opt.textContent = s;
      childSectionSelect.appendChild(opt);
    });

    function filterChildOverrides() {
      const search = document.getElementById('childOverrideSearch').value.toLowerCase();
      const sectionFilter = document.getElementById('childSectionFilter').value;

      childRows.forEach(row => {
        const text = row.textContent.toLowerCase();
        const rowSections = row.dataset.sections || '';

        let show = true;
        if (search && !text.includes(search)) show = false;
        if (sectionFilter && !rowSections.includes(sectionFilter)) show = false;

        row.style.display = show ? '' : 'none';
      });
    }
  </script>
</body>
</html>`;
}

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Report for the WYSIWYG custom field.
// NinjaOne only allows a small tag/style allowlist (no svg, img, strong, br, script, style),
// so the diagram is drawn with flex divs + borders and uses NinjaOne's card/tag/stat-card classes.
const nodeClassInfo = {
  WINDOWS_WORKSTATION: ['Windows Workstation', 'fa-solid fa-desktop'],
  WINDOWS_SERVER: ['Windows Server', 'fa-solid fa-server'],
  MAC: ['macOS', 'fa-solid fa-laptop'],
  MAC_SERVER: ['macOS Server', 'fa-solid fa-server'],
  APPLE_IOS: ['iOS', 'fa-solid fa-mobile-screen'],
  APPLE_IPADOS: ['iPadOS', 'fa-solid fa-tablet-screen-button'],
  LINUX_WORKSTATION: ['Linux Workstation', 'fa-solid fa-desktop'],
  LINUX_SERVER: ['Linux Server', 'fa-solid fa-server'],
  ANDROID: ['Android', 'fa-solid fa-mobile-screen'],
  AOSP: ['AOSP', 'fa-solid fa-mobile-screen'],
  CHROMEOS: ['ChromeOS', 'fa-solid fa-laptop'],
  HYPERV_VMM_HOST: ['Hyper-V Host', 'fa-solid fa-server'],
  HYPERV_VMM_GUEST: ['Hyper-V Guest', 'fa-solid fa-cube'],
  VMWARE_VM_HOST: ['VMware Host', 'fa-solid fa-server'],
  VMWARE_VM_GUEST: ['VMware Guest', 'fa-solid fa-cube'],
  CLOUD_MONITOR_TARGET: ['Cloud Monitor', 'fa-solid fa-cloud'],
  MANAGED_DEVICE: ['Managed Device', 'fa-solid fa-plug'],
  UNMANAGED_DEVICE: ['Unmanaged Device', 'fa-solid fa-plug-circle-xmark'],
};

// One report section per OS family, in this order; brand icons come from Font Awesome Free (fa-brands)
const osFamilies = [
  { label: 'Windows', icon: 'fa-brands fa-windows', match: nc => nc.startsWith('WINDOWS_') },
  { label: 'Apple', icon: 'fa-brands fa-apple', match: nc => nc === 'MAC' || nc.startsWith('MAC_') || nc.startsWith('APPLE_') },
  { label: 'Linux', icon: 'fa-brands fa-linux', match: nc => nc.startsWith('LINUX_') },
  { label: 'Android', icon: 'fa-brands fa-android', match: nc => nc === 'ANDROID' || nc === 'AOSP' },
  { label: 'ChromeOS', icon: 'fa-brands fa-chrome', match: nc => nc === 'CHROMEOS' },
  { label: 'Virtualization', icon: 'fa-solid fa-cubes', match: nc => nc.startsWith('HYPERV_') || nc.startsWith('VMWARE_') },
  { label: 'Network (NMS)', icon: 'fa-solid fa-network-wired', match: nc => nc.startsWith('NMS') },
  { label: 'Other', icon: 'fa-solid fa-ellipsis', match: () => true },
];

function nodeClassLabel(nodeClass) {
  if (nodeClassInfo[nodeClass]) return nodeClassInfo[nodeClass][0];
  return String(nodeClass || 'Unknown').split('_').map(w => w.charAt(0) + w.slice(1).toLowerCase()).join(' ').replace(/^Nms /, 'NMS ');
}

function nodeClassIcon(nodeClass) {
  return nodeClassInfo[nodeClass]?.[1] || (String(nodeClass).startsWith('NMS') ? 'fa-solid fa-ethernet' : 'fa-solid fa-circle-nodes');
}

function generateCustomFieldHTML(policies, tree, overrideDetails = [], childPolicyOverrides = [], policyMap = new Map()) {
  const lineColor = '#94a3b8';
  const mutedColor = '#94a3b8';
  const depthColors = ['#6366f1', '#0891b2', '#7c3aed'];
  const byName = (a, b) => a.name.localeCompare(b.name);
  const countSubtree = p => 1 + p.children.reduce((sum, c) => sum + countSubtree(c), 0);
  const depthOf = p => p.children.length === 0 ? 1 : 1 + Math.max(...p.children.map(depthOf));
  // Compact chips: NinjaOne's .tag class is too large inside the diagram cards
  const chipColors = {
    success: ['#dcfce7', '#166534'],
    danger: ['#fee2e2', '#991b1b'],
    neutral: ['#e2e8f0', '#475569'],
  };
  const chip = (text, variant = 'neutral', margin = '0 0 0 6px') => `<span style="display:inline-block;margin:${margin};padding:0 6px;border-radius:4px;font-size:10px;background-color:${chipColors[variant][0]};color:${chipColors[variant][1]};">${escapeHtml(text)}</span>`;
  const tag = (text, variant) => chip(text, variant);

  // Policy names open the policy editor in a new tab
  const policyUrl = id => `${apiUrl}/#/editor/policy/${id}`;
  const policyLink = (id, name) => `<a href="${policyUrl(id)}" target="_blank" rel="noopener noreferrer">${escapeHtml(name)}</a>`
    + `<i class="fa-solid fa-arrow-up-right-from-square" style="font-size:9px;color:${mutedColor};margin-left:4px;"></i>`;
  const sectionTags = sections => sections.map(s => chip(s, 'neutral', '2px 4px 2px 0')).join('');

  const deviceOverridesByPolicy = new Map();
  overrideDetails.forEach(d => {
    if (d.policyId != null) deviceOverridesByPolicy.set(d.policyId, (deviceOverridesByPolicy.get(d.policyId) || 0) + 1);
  });
  const childWithOverrides = childPolicyOverrides.filter(c => c.overriddenSections.length > 0);
  const childOverrideByPolicy = new Map(childWithOverrides.map(c => [c.policyId, c]));
  const failedChildLoads = childPolicyOverrides.filter(c => c.error).length;

  // Policy node: fixed single-line card so the connector (height 19px + card margin 6px) meets its vertical center
  const policyTags = (policy) => {
    const childOverride = childOverrideByPolicy.get(policy.id);
    const deviceOverrides = deviceOverridesByPolicy.get(policy.id);
    return (policy.nodeClassDefault ? tag('Default', 'success') : '')
      + (childOverride ? tag(`${childOverride.overriddenSections.length} section${childOverride.overriddenSections.length > 1 ? 's' : ''} overridden`, 'danger') : '')
      + (deviceOverrides ? tag(`${deviceOverrides} device override${deviceOverrides > 1 ? 's' : ''}`, 'neutral') : '');
  };

  // Horizontal tree (left to right) using the full width: at each level the card takes 100/remainingLevels %
  // of its container and the rest (flex-grow-1 with width 0, so long names never shrink the cards) holds the next level. The column header is built with the
  // exact same nesting, so header labels and cards always line up.
  const stubWidth = 16;
  const arrowWidth = 10;
  const line = `2px solid ${lineColor}`;
  const levelLabel = depth => `Level ${depth + 1}` + (['Parent', 'Child', 'Child-Child'][depth] ? ` · ${['Parent', 'Child', 'Child-Child'][depth]}` : '');
  const columnWidth = (depth, levels) => `${(100 / (levels - depth)).toFixed(4)}%`;

  const policyCard = (policy, width, accentColor) => `<div style="width:${width};box-sizing:border-box;padding:6px 10px;border-width:1px;border-style:solid;border-color:#cbd5e1;border-left:4px solid ${accentColor};border-radius:6px;">`
    + `<div style="font-size:13px;word-break:break-word;">${policyLink(policy.id, policy.name)}</div>`
    + `<div style="font-size:11px;color:${mutedColor};">#${policy.id}${policyTags(policy)}</div>`
    + `</div>`;

  const renderCard = (policy, depth, levels) => policyCard(policy, columnWidth(depth, levels), depthColors[Math.min(depth, 2)]);

  // Card, a stub to the right, then the children stacked in the next column
  const renderBranch = (policy, depth, levels) => {
    const children = [...policy.children].sort(byName);
    return `<div class="flex-grow-1" style="width:0;display:flex;align-items:center;padding:4px 0;">`
      + renderCard(policy, depth, levels)
      + (children.length > 0
        // margin-top shifts the centered 2px stub down 1px so it lines up with the elbow bar, which starts at 50%
        ? `<div style="width:${stubWidth}px;height:2px;margin-top:2px;background-color:${lineColor};"></div>`
          + `<div class="flex-grow-1" style="width:0;">${children.map((child, i) => renderChildRow(child, depth + 1, levels, i === 0, i === children.length - 1)).join('')}</div>`
        : '')
      + `</div>`;
  };

  // Elbow cell stretches to the row height; its halves draw the shared vertical line
  // (first child: none above, last child: none below), the 2px bar between them is the stub to the arrowhead.
  // Horizontal lines use background-color bars because NinjaOne does not render border-top/border-bottom here.
  const renderChildRow = (child, depth, levels, first, last) => `<div style="display:flex;">`
    + `<div style="width:${stubWidth}px;">`
    + `<div style="height:50%;${first ? '' : `border-left:${line};`}"></div>`
    + `<div style="height:2px;background-color:${lineColor};"></div>`
    + `<div style="height:50%;${last ? '' : `border-left:${line};`}"></div>`
    + `</div>`
    + `<div style="width:${arrowWidth}px;display:flex;align-items:center;"><i class="fa-solid fa-caret-right" style="color:${lineColor};font-size:14px;"></i></div>`
    + renderBranch(child, depth, levels)
    + `</div>`;

  const renderColumnHeader = (depth, levels) => {
    if (depth >= levels) return '';
    const label = `<div style="width:${columnWidth(depth, levels)};box-sizing:border-box;padding:0 0 0 4px;font-size:11px;color:${mutedColor};">`
      + `<span style="display:inline-block;width:8px;height:8px;background-color:${depthColors[Math.min(depth, 2)]};border-radius:2px;margin-right:4px;"></span>${levelLabel(depth)}</div>`;
    const next = depth + 1 < levels
      ? `<div style="width:${stubWidth * 2 + arrowWidth}px;text-align:center;"><i class="fa-solid fa-arrow-right" style="color:${lineColor};font-size:11px;"></i></div>`
        + `<div class="flex-grow-1" style="width:0;display:flex;">${renderColumnHeader(depth + 1, levels)}</div>`
      : '';
    return `<div class="flex-grow-1" style="width:0;display:flex;align-items:center;">${label}${next}</div>`;
  };

  const groups = new Map();
  [...tree].sort(byName).forEach(root => {
    const key = root.nodeClass || 'UNKNOWN';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(root);
  });

  const sortedGroups = [...groups.entries()]
    .map(([nodeClass, roots]) => ({ nodeClass, roots, count: roots.reduce((s, r) => s + countSubtree(r), 0) }))
    .sort((a, b) => b.count - a.count || nodeClassLabel(a.nodeClass).localeCompare(nodeClassLabel(b.nodeClass)));
  const familyOf = nodeClass => osFamilies.find(f => f.match(nodeClass || ''));
  const plural = n => `${n} ${n === 1 ? 'policy' : 'policies'}`;

  // Policies without parent or children: same card as in the trees (grey accent), laid out in a row
  const renderStandaloneRow = policies => `<div class="row g-2" style="margin-top:4px;">`
    + policies.map(p => `<div class="col-12 col-md-6 col-xl-4">${policyCard(p, '100%', '#cbd5e1')}</div>`).join('')
    + `</div>`;

  const subheader = (icon, title, meta = '') => `<div style="display:flex;align-items:center;margin:4px 0 6px;padding:6px 10px;border-radius:6px;background-color:#f1f5f9;">`
    + `<span style="display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;border-radius:6px;background-color:#e0e7ff;color:#4f46e5;font-size:13px;"><i class="${icon}"></i></span>`
    + `<span style="font-size:15px;margin-left:10px;">${title}</span>`
    + (meta ? `<span style="font-size:12px;color:${mutedColor};margin-left:8px;">${meta}</span>` : '')
    + `</div>`;

  // NinjaOne lays out sibling .card elements side by side; wrapping each one in its own
  // full-width block forces one card per row so the diagrams keep the whole width.
  const fullWidthCard = (title, body) => `<div style="display:block;width:100%;margin-bottom:16px;">`
    + `<div class="card flex-grow-1" style="width:100%;">`
    + `<div class="card-title-box"><div class="card-title">${title}</div></div>`
    + `<div class="card-body">${body}</div>`
    + `</div></div>`;

  const familySections = osFamilies.map(family => {
    const familyGroups = sortedGroups.filter(g => familyOf(g.nodeClass) === family);
    if (familyGroups.length === 0) return '';
    const total = familyGroups.reduce((s, g) => s + g.count, 0);
    const classOrder = nc => { const i = Object.keys(nodeClassInfo).indexOf(nc); return i === -1 ? Infinity : i; };

    // Every node class gets its own sub-section (e.g. macOS, iOS, iPadOS, macOS Server),
    // with its inheritance trees first and policies without inheritance as a row below.
    const classSections = [...familyGroups]
      .sort((a, b) => classOrder(a.nodeClass) - classOrder(b.nodeClass) || nodeClassLabel(a.nodeClass).localeCompare(nodeClassLabel(b.nodeClass)))
      .map(g => {
        const treeRoots = g.roots.filter(r => r.children.length > 0);
        const standalone = g.roots.filter(r => r.children.length === 0).sort(byName);
        const levels = treeRoots.length > 0 ? Math.max(...treeRoots.map(depthOf)) : 0;
        const meta = plural(g.count) + (treeRoots.length === 0 ? ' · no inheritance' : '');
        return `<div style="margin-bottom:12px;">`
          + subheader(nodeClassIcon(g.nodeClass), escapeHtml(nodeClassLabel(g.nodeClass)), meta)
          + (treeRoots.length > 0
            ? `<div style="display:flex;margin-top:8px;">${renderColumnHeader(0, levels)}</div>`
              + treeRoots.map(root => `<div style="display:flex;">${renderBranch(root, 0, levels)}</div>`).join('')
            : '')
          + (standalone.length > 0 ? renderStandaloneRow(standalone) : '')
          + `</div>`;
      }).join('');

    return fullWidthCard(`<i class="${family.icon}" style="font-size:18px;"></i>&nbsp;&nbsp;${family.label}`
      + `<span style="font-size:12px;color:${mutedColor};margin-left:8px;">${plural(total)}</span>`, classSections);
  }).join('');

  const statCard = (value, label) => `<div class="col"><div class="stat-card"><div class="stat-value">${value}</div><div class="stat-desc">${label}</div></div></div>`;
  const inheritanceChains = tree.filter(r => r.children.length > 0).length;
  const maxDepth = tree.length > 0 ? Math.max(...tree.map(depthOf)) : 0;
  const childOverrideStat = failedChildLoads > 0 && failedChildLoads === childPolicyOverrides.length ? 'n/a' : childWithOverrides.length;

  const legend = `<div style="font-size:12px;color:${mutedColor};margin:0 0 12px;">Read left to right: arrows point from a policy to the policies that inherit from it.</div>`;

  const infoCard = (variant, icon, title, description) => `<div class="info-card ${variant}" style="margin-bottom:12px;"><i class="info-icon fa-solid ${icon}"></i>`
    + `<div class="info-text"><div class="info-title">${title}</div><div class="info-description">${description}</div></div></div>`;

  const deviceTable = overrideDetails.length > 0
    ? `<table style="width:100%;border-collapse:collapse;"><thead><tr><th style="text-align:left;padding:6px 8px;">Device</th><th style="text-align:left;padding:6px 8px;">Policy</th><th style="text-align:left;padding:6px 8px;">Overridden sections</th></tr></thead><tbody>`
      + [...overrideDetails].sort((a, b) => a.deviceName.localeCompare(b.deviceName)).map(d => `<tr>`
        + `<td style="padding:6px 8px;"><div>${escapeHtml(d.deviceName)}</div><div style="font-size:11px;color:${mutedColor};">${escapeHtml(nodeClassLabel(d.nodeClass))} · #${d.deviceId}</div></td>`
        + `<td style="padding:6px 8px;font-size:12px;">${d.policyId != null && policyMap.has(d.policyId) ? getPolicyChain(d.policyId, policyMap).map(p => policyLink(p.id, p.name)).join(' › ') : 'No policy'}</td>`
        + `<td style="padding:6px 8px;">${sectionTags(d.overrides)}</td>`
        + `</tr>`).join('')
      + `</tbody></table>`
    : infoCard('success', 'fa-circle-check', 'No device overrides', 'All devices follow their assigned policy.');

  let childSection;
  if (failedChildLoads > 0) {
    childSection = infoCard('warning', 'fa-triangle-exclamation', 'Child-policy overrides incomplete',
      `Could not load ${failedChildLoads} of ${childPolicyOverrides.length} child policies. The browser session key has probably expired.`);
  } else {
    childSection = '';
  }
  if (childWithOverrides.length > 0) {
    childSection += `<table style="width:100%;border-collapse:collapse;"><thead><tr><th style="text-align:left;padding:6px 8px;">Child policy</th><th style="text-align:left;padding:6px 8px;">Inherits from</th><th style="text-align:left;padding:6px 8px;">Overridden sections</th></tr></thead><tbody>`
      + [...childWithOverrides].sort((a, b) => a.policyName.localeCompare(b.policyName)).map(c => {
        const parent = policyMap.get(c.parentPolicyId);
        const grouped = {};
        c.overrides.forEach(o => {
          const parts = o.section.split(' › ');
          if (!grouped[parts[0]]) grouped[parts[0]] = [];
          if (parts.length > 1) grouped[parts[0]].push(parts.slice(1).join(' › '));
        });
        const sections = Object.entries(grouped).sort(([a], [b]) => a.localeCompare(b)).map(([section, subs]) =>
          `<div style="margin:2px 0;">${chip(section, 'neutral', '0 6px 0 0')}`
          + `<span style="font-size:11px;color:${mutedColor};">${subs.map(escapeHtml).join(', ')}</span></div>`).join('');
        return `<tr>`
          + `<td style="padding:6px 8px;"><div>${policyLink(c.policyId, c.policyName)}</div><div style="font-size:11px;color:${mutedColor};">${escapeHtml(nodeClassLabel(c.nodeClass))} · #${c.policyId}</div></td>`
          + `<td style="padding:6px 8px;font-size:12px;">${parent ? policyLink(parent.id, parent.name) : '–'}</td>`
          + `<td style="padding:6px 8px;">${sections}</td>`
          + `</tr>`;
      }).join('')
      + `</tbody></table>`;
  } else if (failedChildLoads === 0) {
    childSection = infoCard('success', 'fa-circle-check', 'No child-policy overrides', 'All child policies fully inherit from their parents.');
  }

  return `<div>`
    + infoCard('', 'fa-sitemap', 'Policy Hierarchy', `Generated ${escapeHtml(new Date().toLocaleString('de-DE'))} via API`)
    + `<div class="row g-3" style="margin-bottom:16px;">`
    + statCard(policies.length, 'Policies')
    + statCard(inheritanceChains, 'Inheritance chains')
    + statCard(maxDepth, 'Max. depth')
    + statCard(overrideDetails.length, 'Devices with overrides')
    + statCard(childOverrideStat, 'Child policies with overrides')
    + `</div>`
    + `<h2 style="font-size:16px;margin:8px 0 4px;">Inheritance diagram</h2>`
    + legend
    + `<div style="display:block;width:100%;">${familySections}</div>`
    + `<h2 style="font-size:16px;margin:16px 0 8px;">Deviations</h2>`
    + `<div style="display:block;width:100%;">`
    + fullWidthCard(`<i class="fas fa-laptop-code"></i>&nbsp;Device overrides`, deviceTable)
    + fullWidthCard(`<i class="fas fa-code-branch"></i>&nbsp;Child-policy overrides`, childSection)
    + `</div>`
    + `</div>`;
}

const fs = await import('node:fs');

async function main() {
  try {
    const missing = ['NINJA_CLIENT_ID', 'NINJA_CLIENT_SECRET', 'NINJA_SESSION_KEY'].filter(name => !process.env[name]);
    if (missing.length > 0) {
      throw new Error(`Missing environment variables: ${missing.join(', ')}`);
    }

    const token = await fetchToken();
    console.log('Bearer Token:', token);

    console.log('Loading policies...');
    const policies = await fetchWithAuth('/v2/policies');

    const policyMap = new Map();
    policies.forEach(p => policyMap.set(p.id, p));

    const tree = buildPolicyTree(policies);

    console.log('Loading device policy overrides...');
    const overrides = await fetchWithAuth('/v2/queries/policy-overrides');

    console.log(`Loading details for ${overrides.results.length} devices...`);
    const overrideDetails = await fetchOverrideDetails(overrides, policyMap);

    const childPolicies = policies.filter(p => p.parentPolicyId);
    console.log(`Loading child-policy overrides for ${childPolicies.length} child policies...`);
    const childPolicyOverrides = await fetchChildPolicyOverrides(childPolicies);
    const withOverrides = childPolicyOverrides.filter(c => c.overriddenSections.length > 0);
    console.log(`Found ${withOverrides.length} child policies with overrides`);

    const html = generateHTML(tree, overrideDetails, childPolicyOverrides, policyMap);
    fs.writeFileSync('policies.html', html);
    console.log(`Dashboard generated: policies.html (${policies.length} policies, ${overrideDetails.length} devices with overrides, ${withOverrides.length} child policies with overrides)`);

    const orgChartHtml = generateOrgChartHTML(tree);
    fs.writeFileSync('policy-orgchart.html', orgChartHtml);
    console.log('Org chart generated: policy-orgchart.html');

    const customFieldHtml = generateCustomFieldHTML(policies, tree, overrideDetails, childPolicyOverrides, policyMap);
    console.log(`Writing report to global custom field "${customFieldName}" (${customFieldHtml.length} characters)...`);
    await updateGlobalCustomField(customFieldName, customFieldHtml);
    console.log(`Custom field "${customFieldName}" updated`);
  } catch (error) {
    console.error(error);
  }
}

main();
