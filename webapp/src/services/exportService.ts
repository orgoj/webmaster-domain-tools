import type { DomainAnalysisResult } from '../types/dns';
import type { SEOAnalysisResult } from '../types/seo';

/**
 * Export format types
 */
export type ExportFormat = 'json' | 'csv' | 'txt' | 'html';

/**
 * Combined analysis result for export
 */
export interface CombinedAnalysisResult {
  dns: DomainAnalysisResult;
  seo?: SEOAnalysisResult;
}

/**
 * Export analysis results to JSON format
 */
export function exportToJSON(result: CombinedAnalysisResult): string {
  return JSON.stringify(result, null, 2);
}

/**
 * Export analysis results to CSV format
 */
export function exportToCSV(result: CombinedAnalysisResult): string {
  const lines: string[] = [];

  // Header
  lines.push('Category,Type,Name,Value,TTL,Additional Info');

  // DNS Records
  const dnsRecords = result.dns.dnsRecords;
  Object.entries(dnsRecords).forEach(([type, records]) => {
    records.forEach((record) => {
      lines.push(
        `DNS,${type},"${escapeCSV(record.name)}","${escapeCSV(record.value)}",${record.ttl},`
      );
    });
  });

  // DNSSEC
  lines.push(
    `DNSSEC,Status,,${result.dns.dnssec.validated ? 'Validated' : 'Not Validated'},,Enabled: ${result.dns.dnssec.enabled}`
  );

  // Email Security
  if (result.dns.emailSecurity.spf.found) {
    lines.push(
      `Email Security,SPF,,"${escapeCSV(result.dns.emailSecurity.spf.record || '')}",,"Valid: ${result.dns.emailSecurity.spf.valid}"`
    );
  }

  if (result.dns.emailSecurity.dmarc.found) {
    lines.push(
      `Email Security,DMARC,,"${escapeCSV(result.dns.emailSecurity.dmarc.record || '')}",,"Policy: ${result.dns.emailSecurity.dmarc.policy}"`
    );
  }

  if (result.dns.emailSecurity.dkim.found) {
    lines.push(
      `Email Security,DKIM,,,,"Selector: ${result.dns.emailSecurity.dkim.selector || 'N/A'}"`
    );
  }

  // SEO Data
  if (result.seo) {
    // Robots.txt
    if (result.seo.robotsTxt.found) {
      lines.push(`SEO,Robots.txt,Found,Yes,,`);
      result.seo.robotsTxt.rules.sitemaps.forEach((sitemap) => {
        lines.push(`SEO,Robots.txt,Sitemap,"${escapeCSV(sitemap)}",,""`);
      });
    } else {
      lines.push(`SEO,Robots.txt,Found,No,,`);
    }

    // Sitemap
    if (result.seo.sitemap.found) {
      lines.push(`SEO,Sitemap,Found,Yes,,"URLs: ${result.seo.sitemap.urlCount}"`);
    } else {
      lines.push(`SEO,Sitemap,Found,No,,`);
    }

    // Favicons
    result.seo.favicon.locations.forEach((favicon) => {
      lines.push(
        `SEO,Favicon,"${escapeCSV(favicon.url)}",${favicon.type},,"Source: ${favicon.source}, Size: ${favicon.size || 'N/A'}"`
      );
    });
  }

  // Errors
  result.dns.errors.forEach((error) => {
    lines.push(`Error,,,"${escapeCSV(error)}",,`);
  });

  // Warnings
  result.dns.warnings.forEach((warning) => {
    lines.push(`Warning,,,"${escapeCSV(warning)}",,`);
  });

  if (result.seo) {
    result.seo.robotsTxt.errors.forEach((error) => {
      lines.push(`Error,Robots.txt,,"${escapeCSV(error)}",,`);
    });
    result.seo.robotsTxt.warnings.forEach((warning) => {
      lines.push(`Warning,Robots.txt,,"${escapeCSV(warning)}",,`);
    });
    result.seo.sitemap.errors.forEach((error) => {
      lines.push(`Error,Sitemap,,"${escapeCSV(error)}",,`);
    });
    result.seo.sitemap.warnings.forEach((warning) => {
      lines.push(`Warning,Sitemap,,"${escapeCSV(warning)}",,`);
    });
    result.seo.favicon.warnings.forEach((warning) => {
      lines.push(`Warning,Favicon,,"${escapeCSV(warning)}",,`);
    });
  }

  return lines.join('\n');
}

/**
 * Export analysis results to plain text format
 */
export function exportToTXT(result: CombinedAnalysisResult): string {
  const lines: string[] = [];

  lines.push('='.repeat(80));
  lines.push(`DOMAIN ANALYSIS REPORT: ${result.dns.domain}`);
  lines.push(`Generated: ${result.dns.timestamp.toISOString()}`);
  lines.push('='.repeat(80));
  lines.push('');

  // DNS Records
  lines.push('DNS RECORDS');
  lines.push('-'.repeat(80));
  Object.entries(result.dns.dnsRecords).forEach(([type, records]) => {
    if (records.length > 0) {
      lines.push(`\n${type} Records (${records.length}):`);
      records.forEach((record, i) => {
        lines.push(`  ${i + 1}. ${record.name}`);
        lines.push(`     Value: ${record.value}`);
        lines.push(`     TTL:   ${record.ttl}s`);
      });
    }
  });

  // DNSSEC
  lines.push('');
  lines.push('DNSSEC');
  lines.push('-'.repeat(80));
  lines.push(`Enabled:   ${result.dns.dnssec.enabled ? 'Yes' : 'No'}`);
  lines.push(`Validated: ${result.dns.dnssec.validated ? 'Yes' : 'No'}`);

  // Email Security
  lines.push('');
  lines.push('EMAIL SECURITY');
  lines.push('-'.repeat(80));

  lines.push('\nSPF:');
  if (result.dns.emailSecurity.spf.found) {
    lines.push(`  Found:  Yes`);
    lines.push(`  Valid:  ${result.dns.emailSecurity.spf.valid ? 'Yes' : 'No'}`);
    lines.push(`  Record: ${result.dns.emailSecurity.spf.record}`);
  } else {
    lines.push(`  Found:  No`);
  }

  lines.push('\nDMARC:');
  if (result.dns.emailSecurity.dmarc.found) {
    lines.push(`  Found:  Yes`);
    lines.push(`  Policy: ${result.dns.emailSecurity.dmarc.policy || 'N/A'}`);
    lines.push(`  Record: ${result.dns.emailSecurity.dmarc.record}`);
  } else {
    lines.push(`  Found:  No`);
  }

  lines.push('\nDKIM:');
  if (result.dns.emailSecurity.dkim.found) {
    lines.push(`  Found:    Yes`);
    lines.push(`  Selector: ${result.dns.emailSecurity.dkim.selector || 'N/A'}`);
  } else {
    lines.push(`  Found:    No`);
  }

  // SEO Analysis
  if (result.seo) {
    lines.push('');
    lines.push('SEO ANALYSIS');
    lines.push('-'.repeat(80));

    lines.push('\nRobots.txt:');
    if (result.seo.robotsTxt.found) {
      lines.push(`  Found:      Yes`);
      lines.push(`  User-agents: ${result.seo.robotsTxt.rules.userAgents.join(', ')}`);
      lines.push(`  Disallowed:  ${result.seo.robotsTxt.rules.disallowed.length} paths`);
      lines.push(`  Allowed:     ${result.seo.robotsTxt.rules.allowed.length} paths`);
      lines.push(`  Sitemaps:    ${result.seo.robotsTxt.rules.sitemaps.length}`);
      if (result.seo.robotsTxt.rules.sitemaps.length > 0) {
        result.seo.robotsTxt.rules.sitemaps.forEach((sitemap) => {
          lines.push(`    - ${sitemap}`);
        });
      }
    } else {
      lines.push(`  Found:      No`);
    }

    lines.push('\nSitemap.xml:');
    if (result.seo.sitemap.found) {
      lines.push(`  Found:      Yes`);
      lines.push(`  URL Count:  ${result.seo.sitemap.urlCount}`);
      if (result.seo.sitemap.lastModified) {
        lines.push(`  Last Modified: ${result.seo.sitemap.lastModified}`);
      }
    } else {
      lines.push(`  Found:      No`);
    }

    lines.push('\nFavicons:');
    if (result.seo.favicon.found) {
      lines.push(`  Found:      ${result.seo.favicon.locations.length} location(s)`);
      result.seo.favicon.locations.forEach((favicon, i) => {
        lines.push(`  ${i + 1}. ${favicon.url}`);
        lines.push(`     Type:   ${favicon.type}`);
        lines.push(`     Source: ${favicon.source}`);
        if (favicon.size) {
          lines.push(`     Size:   ${favicon.size}`);
        }
      });
    } else {
      lines.push(`  Found:      No`);
    }
  }

  // Errors and Warnings
  const allErrors = [...result.dns.errors];
  const allWarnings = [...result.dns.warnings];

  if (result.seo) {
    allErrors.push(...result.seo.robotsTxt.errors);
    allErrors.push(...result.seo.sitemap.errors);
    allErrors.push(...result.seo.favicon.errors);
    allWarnings.push(...result.seo.robotsTxt.warnings);
    allWarnings.push(...result.seo.sitemap.warnings);
    allWarnings.push(...result.seo.favicon.warnings);
  }

  if (allErrors.length > 0) {
    lines.push('');
    lines.push('ERRORS');
    lines.push('-'.repeat(80));
    allErrors.forEach((error, i) => {
      lines.push(`${i + 1}. ${error}`);
    });
  }

  if (allWarnings.length > 0) {
    lines.push('');
    lines.push('WARNINGS');
    lines.push('-'.repeat(80));
    allWarnings.forEach((warning, i) => {
      lines.push(`${i + 1}. ${warning}`);
    });
  }

  lines.push('');
  lines.push('='.repeat(80));
  lines.push('END OF REPORT');
  lines.push('='.repeat(80));

  return lines.join('\n');
}

/**
 * Export analysis results to HTML format
 */
export function exportToHTML(result: CombinedAnalysisResult): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Domain Analysis Report - ${escapeHTML(result.dns.domain)}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px;
      background: #f5f5f5;
    }
    .container {
      background: white;
      padding: 30px;
      border-radius: 8px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.1);
    }
    h1 {
      color: #2563eb;
      border-bottom: 3px solid #2563eb;
      padding-bottom: 10px;
    }
    h2 {
      color: #1e40af;
      margin-top: 30px;
      border-bottom: 1px solid #e5e7eb;
      padding-bottom: 8px;
    }
    h3 {
      color: #374151;
      margin-top: 20px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 15px 0;
    }
    th, td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid #e5e7eb;
    }
    th {
      background: #f9fafb;
      font-weight: 600;
      color: #374151;
    }
    tr:hover {
      background: #f9fafb;
    }
    .badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 4px;
      font-size: 12px;
      font-weight: 600;
    }
    .badge-success {
      background: #dcfce7;
      color: #166534;
    }
    .badge-error {
      background: #fee2e2;
      color: #991b1b;
    }
    .badge-warning {
      background: #fef3c7;
      color: #92400e;
    }
    .error-list, .warning-list {
      margin: 10px 0;
      padding-left: 20px;
    }
    .error-list li {
      color: #dc2626;
      margin: 5px 0;
    }
    .warning-list li {
      color: #f59e0b;
      margin: 5px 0;
    }
    .timestamp {
      color: #6b7280;
      font-size: 14px;
    }
    .mono {
      font-family: 'Courier New', monospace;
      background: #f3f4f6;
      padding: 2px 6px;
      border-radius: 3px;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🌐 Domain Analysis Report</h1>
    <p><strong>Domain:</strong> <span class="mono">${escapeHTML(result.dns.domain)}</span></p>
    <p class="timestamp">Generated: ${result.dns.timestamp.toISOString()}</p>

    <h2>📋 DNS Records</h2>
    ${generateDNSTable(result.dns)}

    <h2>🔒 DNSSEC</h2>
    <p>
      <span class="badge ${result.dns.dnssec.validated ? 'badge-success' : 'badge-error'}">
        ${result.dns.dnssec.validated ? '✓ Validated' : '✗ Not Validated'}
      </span>
      <span class="badge ${result.dns.dnssec.enabled ? 'badge-success' : 'badge-error'}">
        ${result.dns.dnssec.enabled ? 'Enabled' : 'Disabled'}
      </span>
    </p>

    <h2>📧 Email Security</h2>
    ${generateEmailSecurityHTML(result.dns)}

    ${result.seo ? generateSEOHTML(result.seo) : ''}

    ${result.dns.errors.length > 0 || (result.seo && (result.seo.robotsTxt.errors.length > 0 || result.seo.sitemap.errors.length > 0)) ? `
      <h2>❌ Errors</h2>
      <ul class="error-list">
        ${result.dns.errors.map((e) => `<li>${escapeHTML(e)}</li>`).join('')}
        ${result.seo ? result.seo.robotsTxt.errors.map((e) => `<li>[Robots.txt] ${escapeHTML(e)}</li>`).join('') : ''}
        ${result.seo ? result.seo.sitemap.errors.map((e) => `<li>[Sitemap] ${escapeHTML(e)}</li>`).join('') : ''}
      </ul>
    ` : ''}

    ${result.dns.warnings.length > 0 || (result.seo && (result.seo.robotsTxt.warnings.length > 0 || result.seo.sitemap.warnings.length > 0 || result.seo.favicon.warnings.length > 0)) ? `
      <h2>⚠️ Warnings</h2>
      <ul class="warning-list">
        ${result.dns.warnings.map((w) => `<li>${escapeHTML(w)}</li>`).join('')}
        ${result.seo ? result.seo.robotsTxt.warnings.map((w) => `<li>[Robots.txt] ${escapeHTML(w)}</li>`).join('') : ''}
        ${result.seo ? result.seo.sitemap.warnings.map((w) => `<li>[Sitemap] ${escapeHTML(w)}</li>`).join('') : ''}
        ${result.seo ? result.seo.favicon.warnings.map((w) => `<li>[Favicon] ${escapeHTML(w)}</li>`).join('') : ''}
      </ul>
    ` : ''}
  </div>
</body>
</html>`;
}

/**
 * Download file to user's computer
 */
export function downloadFile(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/**
 * Export and download analysis results
 */
export function exportAnalysis(
  result: CombinedAnalysisResult,
  format: ExportFormat
): void {
  const domain = result.dns.domain;
  const timestamp = new Date().toISOString().split('T')[0];

  let content: string;
  let filename: string;
  let mimeType: string;

  switch (format) {
    case 'json':
      content = exportToJSON(result);
      filename = `${domain}_analysis_${timestamp}.json`;
      mimeType = 'application/json';
      break;
    case 'csv':
      content = exportToCSV(result);
      filename = `${domain}_analysis_${timestamp}.csv`;
      mimeType = 'text/csv';
      break;
    case 'txt':
      content = exportToTXT(result);
      filename = `${domain}_analysis_${timestamp}.txt`;
      mimeType = 'text/plain';
      break;
    case 'html':
      content = exportToHTML(result);
      filename = `${domain}_analysis_${timestamp}.html`;
      mimeType = 'text/html';
      break;
  }

  downloadFile(content, filename, mimeType);
}

// Helper functions

function escapeCSV(str: string): string {
  return str.replace(/"/g, '""');
}

function escapeHTML(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function generateDNSTable(dns: DomainAnalysisResult): string {
  let html = '<table><thead><tr><th>Type</th><th>Name</th><th>Value</th><th>TTL</th></tr></thead><tbody>';

  Object.entries(dns.dnsRecords).forEach(([type, records]) => {
    records.forEach((record) => {
      html += `<tr>
        <td><strong>${type}</strong></td>
        <td><span class="mono">${escapeHTML(record.name)}</span></td>
        <td><span class="mono">${escapeHTML(record.value)}</span></td>
        <td>${record.ttl}s</td>
      </tr>`;
    });
  });

  html += '</tbody></table>';
  return html;
}

function generateEmailSecurityHTML(dns: DomainAnalysisResult): string {
  let html = '<h3>SPF</h3>';
  if (dns.emailSecurity.spf.found) {
    html += `<p>
      <span class="badge ${dns.emailSecurity.spf.valid ? 'badge-success' : 'badge-error'}">
        ${dns.emailSecurity.spf.valid ? '✓ Valid' : '✗ Invalid'}
      </span>
    </p>
    <p><span class="mono">${escapeHTML(dns.emailSecurity.spf.record || '')}</span></p>`;
  } else {
    html += '<p><span class="badge badge-error">✗ Not Found</span></p>';
  }

  html += '<h3>DMARC</h3>';
  if (dns.emailSecurity.dmarc.found) {
    html += `<p>
      <span class="badge badge-success">✓ Found</span>
      <span class="badge ${dns.emailSecurity.dmarc.policy === 'reject' || dns.emailSecurity.dmarc.policy === 'quarantine' ? 'badge-success' : 'badge-warning'}">
        Policy: ${dns.emailSecurity.dmarc.policy || 'N/A'}
      </span>
    </p>
    <p><span class="mono">${escapeHTML(dns.emailSecurity.dmarc.record || '')}</span></p>`;
  } else {
    html += '<p><span class="badge badge-error">✗ Not Found</span></p>';
  }

  html += '<h3>DKIM</h3>';
  if (dns.emailSecurity.dkim.found) {
    html += `<p><span class="badge badge-success">✓ Found</span></p>
    <p>Selector: <span class="mono">${escapeHTML(dns.emailSecurity.dkim.selector || 'N/A')}</span></p>`;
  } else {
    html += '<p><span class="badge badge-error">✗ Not Found</span></p>';
  }

  return html;
}

function generateSEOHTML(seo: SEOAnalysisResult): string {
  let html = '<h2>🎯 SEO Analysis</h2>';

  html += '<h3>Robots.txt</h3>';
  if (seo.robotsTxt.found) {
    html += `<p><span class="badge badge-success">✓ Found</span></p>
    <ul>
      <li><strong>User Agents:</strong> ${seo.robotsTxt.rules.userAgents.join(', ')}</li>
      <li><strong>Disallowed Paths:</strong> ${seo.robotsTxt.rules.disallowed.length}</li>
      <li><strong>Allowed Paths:</strong> ${seo.robotsTxt.rules.allowed.length}</li>
      <li><strong>Sitemaps:</strong> ${seo.robotsTxt.rules.sitemaps.length}</li>
    </ul>`;
  } else {
    html += '<p><span class="badge badge-error">✗ Not Found</span></p>';
  }

  html += '<h3>Sitemap.xml</h3>';
  if (seo.sitemap.found) {
    html += `<p>
      <span class="badge badge-success">✓ Found</span>
      <span class="badge badge-success">${seo.sitemap.urlCount} URLs</span>
    </p>`;
  } else {
    html += '<p><span class="badge badge-error">✗ Not Found</span></p>';
  }

  html += '<h3>Favicons</h3>';
  if (seo.favicon.found) {
    html += `<p><span class="badge badge-success">✓ Found ${seo.favicon.locations.length} location(s)</span></p>`;
    html += '<table><thead><tr><th>URL</th><th>Type</th><th>Source</th><th>Size</th></tr></thead><tbody>';
    seo.favicon.locations.forEach((fav) => {
      html += `<tr>
        <td><span class="mono">${escapeHTML(fav.url)}</span></td>
        <td>${fav.type}</td>
        <td>${fav.source}</td>
        <td>${fav.size || 'N/A'}</td>
      </tr>`;
    });
    html += '</tbody></table>';
  } else {
    html += '<p><span class="badge badge-error">✗ Not Found</span></p>';
  }

  return html;
}
