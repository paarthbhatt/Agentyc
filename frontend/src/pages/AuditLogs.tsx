import type { AuditLog } from '../lib/api';

export default function AuditLogs({ auditLogs }: { auditLogs: AuditLog[] }) {
  return (
    <div className="fade-in">
      <div className="page-header">
        <div className="page-header-left">
          <div className="page-eyebrow">Administration</div>
          <div className="page-title">Audit Logs</div>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
        {auditLogs.length === 0 && (
          <div className="glass-card">
            <div className="card-body">
              <div className="empty-state">
                <div className="empty-icon">✓</div>
                No audit logs found
              </div>
            </div>
          </div>
        )}
        
        {auditLogs.map((log) => (
          <div key={log.id} className="glass-card fade-in" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                <span className="badge" style={{ backgroundColor: 'rgba(0, 212, 255, 0.1)', color: 'var(--cyan)' }}>
                  {log.action}
                </span>
                <span style={{ fontWeight: 600, color: 'var(--text-bright)' }}>
                  {log.resource_type}: {log.resource_id}
                </span>
              </div>
              <span style={{ fontSize: 10, color: 'var(--text-dim)', fontFamily: "'JetBrains Mono', monospace" }}>
                {new Date(log.created_at).toLocaleString()}
              </span>
            </div>
            
            <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
              <strong>User ID:</strong> {log.user_id || 'System'}
            </div>
            
            {Object.keys(log.details || {}).length > 0 && (
              <pre style={{ 
                fontSize: 11, 
                color: 'var(--text-muted)', 
                fontFamily: "'JetBrains Mono', monospace", 
                background: 'rgba(0,0,0,0.4)', 
                padding: 10, 
                borderRadius: 6, 
                overflow: 'auto',
                marginTop: '4px'
              }}>
                {JSON.stringify(log.details, null, 2)}
              </pre>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
