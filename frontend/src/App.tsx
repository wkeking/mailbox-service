import { type FormEvent, type JSX, useEffect, useMemo, useState } from "react";
import {
  BookOpen,
  CheckCircle2,
  CircleAlert,
  CircleOff,
  Copy,
  KeyRound,
  LogOut,
  Network,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  RefreshCw,
  ServerCog,
  Settings2,
  ShieldCheck,
  Trash2,
  Upload,
  X,
} from "lucide-react";

type ProxyStatus = "healthy" | "cooldown" | "unknown";
type ProxyProtocol = "http_connect" | "socks5";
type NavigationSection = "dashboard" | "mailboxes" | "leases" | "egress-proxies" | "client-keys";

const ADMIN_TOKEN_STORAGE_KEY = "mailbox-service.admin-token";

function readStoredAdminToken(): string {
  try {
    return sessionStorage.getItem(ADMIN_TOKEN_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

function writeStoredAdminToken(token: string): void {
  try {
    if (token) {
      sessionStorage.setItem(ADMIN_TOKEN_STORAGE_KEY, token);
    } else {
      sessionStorage.removeItem(ADMIN_TOKEN_STORAGE_KEY);
    }
  } catch {
    // Ignore storage failures (private mode / disabled storage); login still works in-memory.
  }
}

const CLIENT_KEY_SCOPE_OPTIONS = [
  { id: "leases:acquire", label: "领取租约", description: "leases:acquire" },
  { id: "leases:release", label: "释放租约", description: "leases:release" },
  { id: "tokens:access:read", label: "读取 Access Token", description: "tokens:access:read" },
  { id: "tokens:refresh:read", label: "读取 Refresh Token", description: "tokens:refresh:read" },
  { id: "tokens:refresh:write", label: "回写 Refresh Token", description: "tokens:refresh:write" },
] as const;

type ClientKeyScope = (typeof CLIENT_KEY_SCOPE_OPTIONS)[number]["id"];

interface ClientKeyListItem {
  id: string;
  name: string;
  scopes: string[];
  enabled: boolean;
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
}

interface ClientKeyCreatedResponse {
  id: string;
  name: string;
  api_key: string;
  scopes: string[];
  enabled: boolean;
  expires_at: string | null;
  created_at: string;
}

interface EgressProxy {
  id: string;
  name: string;
  protocol: ProxyProtocol;
  host_preview: string;
  port: number;
  enabled: boolean;
  priority: number;
  status: ProxyStatus;
  has_credentials: boolean;
  consecutive_failure_count: number;
  cooldown_until: string | null;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_error_summary: string | null;
  bound_mailbox_count: number;
}

interface ProxyPolicy {
  enabled: boolean;
  required: boolean;
  allowed_protocols: ProxyProtocol[];
  connect_timeout_seconds: number;
  read_timeout_seconds: number;
  health_check_interval_seconds: number;
  failure_threshold: number;
  cooldown_seconds: number;
  switch_minimum_interval_seconds: number;
  allow_direct_development: boolean;
}

interface ConnectivityResult {
  successful: boolean;
  error_code?: string;
  error_summary?: string;
}

interface DashboardSummary {
  total_mailbox_count: number;
  active_mailbox_count: number;
  usable_mailbox_count: number;
  invalid_mailbox_count: number;
  disabled_mailbox_count: number;
  cooldown_mailbox_count: number;
  imap_capable_mailbox_count: number;
  graph_capable_mailbox_count: number;
  unusable_mailbox_count: number;
  unprobed_capability_mailbox_count: number;
  active_lease_count: number;
  expired_lease_count: number;
  total_proxy_count: number;
  healthy_proxy_count: number;
  cooldown_proxy_count: number;
  bound_mailbox_count: number;
  recent_audit_count: number;
}

type MailboxStatus = "active" | "disabled" | "invalid" | "cooldown";

interface MailboxListItem {
  id: string;
  primary_email: string;
  status: MailboxStatus;
  client_id: string | null;
  token_version: number;
  egress_proxy_id: string | null;
  egress_proxy_name: string | null;
  proxy_bound_at: string | null;
  proxy_last_switch_at: string | null;
  has_access_token: boolean;
  access_token_expires_at: string | null;
  access_token_refreshed_at: string | null;
  scope: string | null;
  capability: "imap" | "graph" | "unusable" | "unknown" | null;
  capability_probed_at: string | null;
  capability_probe_error: string | null;
  active_lease_count: number;
  created_at: string;
  updated_at: string;
}

interface MailboxListResponse {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  items: MailboxListItem[];
}

type MailboxImportConflictStrategy = "skip" | "replace_token" | "error";

interface MailboxImportLineError {
  line_number: number;
  message: string;
}

interface MailboxImportResult {
  created: number;
  updated: number;
  skipped: number;
  failed: number;
  errors: MailboxImportLineError[];
}

interface MailboxAccessTokenRefreshItem {
  mailbox_id: string;
  primary_email: string | null;
  successful: boolean;
  refreshed: boolean;
  refresh_token_rotated: boolean;
  access_token_expires_at: string | null;
  error_summary: string | null;
}

interface MailboxAccessTokenRefreshResult {
  successful: number;
  failed: number;
  results: MailboxAccessTokenRefreshItem[];
}

type LeaseMode = "refresh_token" | "access_token" | "mail_read";
type LeaseStatus = "active" | "released" | "expired";

interface LeaseListItem {
  id: string;
  mailbox_id: string;
  primary_email: string;
  client_key_id: string | null;
  client_tag: string | null;
  purpose: string | null;
  mode: LeaseMode;
  status: LeaseStatus;
  expires_at: string;
  released_at: string | null;
  created_at: string;
}

interface LeaseListResponse {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  items: LeaseListItem[];
}

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000";

function formatTime(value: string | null): string {
  if (!value) {
    return "-";
  }
  return new Intl.DateTimeFormat("zh-CN", {
    dateStyle: "short",
    timeStyle: "short",
  }).format(new Date(value));
}

const TRUNCATED_FIELD_VISIBLE_CHARACTER_COUNT = 5;

function formatPrefixWithEllipsis(value: string, visibleCharacterCount = TRUNCATED_FIELD_VISIBLE_CHARACTER_COUNT): string {
  if (value.length <= visibleCharacterCount) {
    return value;
  }
  return `${value.slice(0, visibleCharacterCount)}...`;
}

function splitScopePermissions(scope: string): string[] {
  return scope
    .split(/\s+/)
    .map((permissionToken) => permissionToken.trim())
    .filter(Boolean);
}

function getErrorMessage(payload: unknown): string {
  if (typeof payload === "object" && payload !== null && "detail" in payload) {
    const detail = payload.detail;
    if (typeof detail === "object" && detail !== null && "message" in detail) {
      return String(detail.message);
    }
    if (typeof detail === "string") {
      return detail;
    }
  }
  return "请求失败，请检查服务状态和管理员凭证。";
}

async function requestApi<ResponsePayload>(
  adminToken: string,
  path: string,
  options: RequestInit = {},
): Promise<ResponsePayload> {
  const headers = new Headers(options.headers);
  headers.set("X-Admin-Token", adminToken);
  if (options.body) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${apiBaseUrl}${path}`, { ...options, headers });
  if (response.status === 204) {
    return undefined as ResponsePayload;
  }
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(getErrorMessage(payload));
  }
  return payload as ResponsePayload;
}

function StatusBadge({ proxy }: { proxy: EgressProxy }): JSX.Element {
  const label = !proxy.enabled ? "已停用" : proxy.status === "healthy" ? "健康" : proxy.status === "cooldown" ? "冷却中" : "待验证";
  const className = !proxy.enabled ? "badge-disabled" : `badge-${proxy.status}`;
  return <span className={`badge ${className}`}>{label}</span>;
}

function MailboxStatusBadge({ status }: { status: MailboxStatus }): JSX.Element {
  const statusLabel = {
    active: "可用",
    disabled: "已停用",
    invalid: "失效",
    cooldown: "冷却中",
  }[status];
  return <span className={`badge badge-mailbox-${status}`}>{statusLabel}</span>;
}

function MailboxCapabilityBadge({
  capability,
  probeError,
}: {
  capability: MailboxListItem["capability"];
  probeError: string | null;
}): JSX.Element {
  if (!capability) {
    return <span className="muted-copy">未探测</span>;
  }
  const capabilityLabel = {
    imap: "IMAP",
    graph: "Graph",
    unusable: "不可用",
    unknown: "未知",
  }[capability];
  return (
    <span className={`badge badge-capability-${capability}`} title={probeError ?? undefined}>
      {capabilityLabel}
    </span>
  );
}

function TruncatedHoverField({
  value,
  emptyLabel,
  tooltipLines,
  className,
}: {
  value: string | null;
  emptyLabel: string;
  tooltipLines?: string[] | null;
  className?: string;
}): JSX.Element {
  if (!value) {
    return <span className="muted-copy">{emptyLabel}</span>;
  }

  const displayLabel = formatPrefixWithEllipsis(value);
  const resolvedTooltipLines =
    tooltipLines && tooltipLines.length > 0 ? tooltipLines : [value];
  const isMultilineTooltip = resolvedTooltipLines.length > 1;

  return (
    <span className={`truncated-hover-field ${className ?? ""}`.trim()}>
      <span className="truncated-hover-label">{displayLabel}</span>
      <span
        className={`truncated-hover-tooltip${isMultilineTooltip ? " truncated-hover-tooltip-multiline" : ""}`}
        role="tooltip"
      >
        {resolvedTooltipLines.map((tooltipLine, tooltipLineIndex) => (
          <span key={`${tooltipLineIndex}-${tooltipLine}`} className="truncated-hover-tooltip-line">
            {tooltipLine}
          </span>
        ))}
      </span>
    </span>
  );
}

function MailboxClientIdSummary({ clientId }: { clientId: string | null }): JSX.Element {
  return (
    <TruncatedHoverField
      value={clientId}
      emptyLabel="-"
      className="client-id-summary"
    />
  );
}

function MailboxScopeSummary({ scope }: { scope: string | null }): JSX.Element {
  return (
    <TruncatedHoverField
      value={scope}
      emptyLabel="未识别"
      tooltipLines={scope ? splitScopePermissions(scope) : null}
      className="scope-summary"
    />
  );
}

function LeaseStatusBadge({ status }: { status: LeaseStatus }): JSX.Element {
  const statusLabel = {
    active: "进行中",
    released: "已释放",
    expired: "已过期",
  }[status];
  return <span className={`badge badge-lease-${status}`}>{statusLabel}</span>;
}

function ClientKeyStatusBadge({ enabled }: { enabled: boolean }): JSX.Element {
  return (
    <span className={`badge ${enabled ? "badge-enabled" : "badge-disabled"}`}>
      {enabled ? "启用中" : "已停用"}
    </span>
  );
}

function formatClientKeyScopeLabel(scope: string): string {
  return CLIENT_KEY_SCOPE_OPTIONS.find((option) => option.id === scope)?.label ?? scope;
}

function DashboardPage({ summary }: { summary: DashboardSummary | null }): JSX.Element {
  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">概览</h1>
          <p className="page-subtitle">查看邮箱健康度、租约使用情况与近期保活结果。</p>
        </div>
      </header>
      <section className="metric-grid" aria-label="概览指标">
        <MetricCard label="全部邮箱" value={summary?.total_mailbox_count ?? 0} />
        <MetricCard label="可用邮箱" value={summary?.usable_mailbox_count ?? 0} />
        <MetricCard label="活跃租约" value={summary?.active_lease_count ?? 0} />
        <MetricCard label="健康代理" value={summary?.healthy_proxy_count ?? 0} />
      </section>
      <section className="two-column-grid">
        <div className="panel">
          <div className="section-header"><h2 className="section-title">邮箱健康</h2></div>
          <div className="stacked-list">
            <SummaryRow label="IMAP 可用" value={summary?.imap_capable_mailbox_count ?? 0} />
            <SummaryRow label="Graph 可用" value={summary?.graph_capable_mailbox_count ?? 0} />
            <SummaryRow label="能力不可用" value={summary?.unusable_mailbox_count ?? 0} />
            <SummaryRow label="未探测能力" value={summary?.unprobed_capability_mailbox_count ?? 0} />
            <SummaryRow label="凭证失效" value={summary?.invalid_mailbox_count ?? 0} />
            <SummaryRow label="停用邮箱" value={summary?.disabled_mailbox_count ?? 0} />
            <SummaryRow label="冷却邮箱" value={summary?.cooldown_mailbox_count ?? 0} />
          </div>
        </div>
        <div className="panel">
          <div className="section-header"><h2 className="section-title">运行状态</h2></div>
          <div className="stacked-list">
            <SummaryRow label="已过期未释放租约" value={summary?.expired_lease_count ?? 0} />
            <SummaryRow label="全部代理" value={summary?.total_proxy_count ?? 0} />
            <SummaryRow label="冷却代理" value={summary?.cooldown_proxy_count ?? 0} />
            <SummaryRow label="审计事件" value={summary?.recent_audit_count ?? 0} />
          </div>
        </div>
      </section>
    </>
  );
}

function MailboxesPage({
  mailboxes,
  page,
  pageSize,
  total,
  totalPages,
  selectedMailboxIds,
  isRefreshingAccessTokens,
  onPageChange,
  onOpenImport,
  onRefreshAllAccessTokens,
  onRefreshSelectedAccessTokens,
  onToggleAllMailboxSelection,
  onToggleMailboxSelection,
}: {
  mailboxes: MailboxListItem[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  selectedMailboxIds: Set<string>;
  isRefreshingAccessTokens: boolean;
  onPageChange: (page: number) => void;
  onOpenImport: () => void;
  onRefreshAllAccessTokens: () => void;
  onRefreshSelectedAccessTokens: () => void;
  onToggleAllMailboxSelection: (isSelected: boolean) => void;
  onToggleMailboxSelection: (mailboxId: string, isSelected: boolean) => void;
}): JSX.Element {
  const selectedMailboxCount = selectedMailboxIds.size;
  const areAllMailboxesSelected = mailboxes.length > 0 && mailboxes.every((mailbox) => selectedMailboxIds.has(mailbox.id));
  const normalizedTotalPages = Math.max(totalPages, 1);

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">邮箱管理</h1>
          <p className="page-subtitle">集中维护邮箱凭证、状态、Token 版本与出口代理绑定。</p>
        </div>
        <button className="button button-primary" type="button" onClick={onOpenImport}>
          <Upload size={15} /> 导入邮箱
        </button>
      </header>
      <section className="panel">
        <div className="toolbar mailbox-toolbar">
          <div>
            <h2 className="section-title">邮箱列表</h2>
            <span className="muted-copy">共 {total} 个，每页 {pageSize} 个，当前页已选 {selectedMailboxCount} 个</span>
          </div>
          <div className="toolbar-actions">
            <button
              className="button"
              type="button"
              onClick={onRefreshSelectedAccessTokens}
              disabled={isRefreshingAccessTokens || selectedMailboxCount === 0}
            >
              <RefreshCw size={14} /> 刷新选中 RT/AT
            </button>
            <button
              className="button"
              type="button"
              onClick={onRefreshAllAccessTokens}
              disabled={isRefreshingAccessTokens || mailboxes.length === 0}
            >
              <RefreshCw size={14} /> 刷新全部 RT/AT
            </button>
            <div className="pagination-actions" aria-label="邮箱分页">
              <button className="button" type="button" onClick={() => onPageChange(page - 1)} disabled={page <= 1}>上一页</button>
              <span className="muted-copy">第 {page} / {normalizedTotalPages} 页</span>
              <button className="button" type="button" onClick={() => onPageChange(page + 1)} disabled={page >= normalizedTotalPages}>下一页</button>
            </div>
          </div>
        </div>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th aria-label="选择邮箱">
                  <input
                    type="checkbox"
                    checked={areAllMailboxesSelected}
                    onChange={(event) => onToggleAllMailboxSelection(event.target.checked)}
                  />
                </th>
                <th>邮箱</th>
                <th>状态</th>
                <th>Client ID</th>
                <th>Scope</th>
                <th>能力</th>
                <th>Token 版本</th>
                <th>AT 过期时间</th>
                <th>AT 刷新时间</th>
                <th>出口代理</th>
                <th>活跃租约</th>
                <th>更新时间</th>
              </tr>
            </thead>
            <tbody>
              {mailboxes.map((mailbox) => (
                <tr key={mailbox.id}>
                  <td>
                    <input
                      type="checkbox"
                      checked={selectedMailboxIds.has(mailbox.id)}
                      aria-label={`选择 ${mailbox.primary_email}`}
                      onChange={(event) => onToggleMailboxSelection(mailbox.id, event.target.checked)}
                    />
                  </td>
                  <td><strong>{mailbox.primary_email}</strong><div className="muted-copy">{mailbox.id}</div></td>
                  <td><MailboxStatusBadge status={mailbox.status} /></td>
                  <td className="client-id-cell">
                    <MailboxClientIdSummary clientId={mailbox.client_id} />
                  </td>
                  <td className="scope-cell">
                    <MailboxScopeSummary scope={mailbox.scope} />
                  </td>
                  <td>
                    <MailboxCapabilityBadge
                      capability={mailbox.capability}
                      probeError={mailbox.capability_probe_error}
                    />
                    <div className="muted-copy">{formatTime(mailbox.capability_probed_at)}</div>
                  </td>
                  <td>{mailbox.token_version}</td>
                  <td>{mailbox.has_access_token ? formatTime(mailbox.access_token_expires_at) : "未缓存"}</td>
                  <td>{formatTime(mailbox.access_token_refreshed_at)}</td>
                  <td>{mailbox.egress_proxy_name ?? "直连 / 未绑定"}<div className="muted-copy">{formatTime(mailbox.proxy_last_switch_at)}</div></td>
                  <td>{mailbox.active_lease_count}</td>
                  <td>{formatTime(mailbox.updated_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {mailboxes.length === 0 && <div className="empty-state"><CircleOff size={16} style={{ verticalAlign: "middle", marginRight: 6 }} />暂无邮箱。后续可通过导入接口添加邮箱凭证。</div>}
      </section>
    </>
  );
}

function MailboxImportDialog({
  importResult,
  isImporting,
  onClose,
  onSubmit,
}: {
  importResult: MailboxImportResult | null;
  isImporting: boolean;
  onClose: () => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}): JSX.Element {
  return (
    <div className="dialog-backdrop" role="presentation">
      <form className="dialog dialog-wide" role="dialog" aria-modal="true" aria-labelledby="mailbox-import-title" onSubmit={onSubmit}>
        <div className="section-header">
          <div>
            <h2 className="section-title" id="mailbox-import-title">导入邮箱</h2>
            <p className="page-subtitle">每行 1 个邮箱，使用四段文本格式批量写入加密凭证。</p>
          </div>
        </div>
        <div className="form-grid">
          <label className="form-field full-width">
            导入内容
            <textarea
              className="textarea import-textarea"
              name="content"
              placeholder="user@outlook.com----mail-password----client-id----refresh-token"
              required
            />
          </label>
          <label className="form-field full-width">
            已存在邮箱处理方式
            <select className="select" name="on_conflict" defaultValue="replace_token">
              <option value="replace_token">替换密码与 Refresh Token，并递增 Token 版本</option>
              <option value="skip">跳过已存在邮箱</option>
              <option value="error">遇到已存在邮箱时报错</option>
            </select>
          </label>
          <div className="import-format-help full-width">
            <strong>格式说明：</strong>
            <span>邮箱----邮箱密码----Client ID----Refresh Token</span>
            <span>空行会自动忽略；密码和 Token 只会加密写入，不会在列表或错误信息中回显。</span>
          </div>
        </div>

        {importResult && (
          <div className="import-result" aria-live="polite">
            <div className="import-result-grid">
              <ImportResultCard label="新增" value={importResult.created} />
              <ImportResultCard label="更新" value={importResult.updated} />
              <ImportResultCard label="跳过" value={importResult.skipped} />
              <ImportResultCard label="失败" value={importResult.failed} />
            </div>
            {importResult.errors.length > 0 && (
              <div className="import-error-list">
                {importResult.errors.map((lineError) => (
                  <div key={`${lineError.line_number}-${lineError.message}`} className="import-error-item">
                    第 {lineError.line_number} 行：{lineError.message}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        <div className="dialog-actions">
          <button className="button" type="button" onClick={onClose} disabled={isImporting}>关闭</button>
          <button className="button button-primary" type="submit" disabled={isImporting}>
            {isImporting ? "导入中" : "开始导入"}
          </button>
        </div>
      </form>
    </div>
  );
}

function ImportResultCard({ label, value }: { label: string; value: number }): JSX.Element {
  return (
    <div className="import-result-card">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function LeasesPage({
  leases,
  page,
  pageSize,
  total,
  totalPages,
  onPageChange,
}: {
  leases: LeaseListItem[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  onPageChange: (page: number) => void;
}): JSX.Element {
  const normalizedTotalPages = Math.max(totalPages, 1);

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">租约管理</h1>
          <p className="page-subtitle">查看当前领取记录、到期时间与调用方使用情况。</p>
        </div>
      </header>
      <section className="panel">
        <div className="toolbar">
          <div>
            <h2 className="section-title">最近租约</h2>
            <span className="muted-copy">共 {total} 条，每页 {pageSize} 条</span>
          </div>
          <div className="pagination-actions" aria-label="租约分页">
            <button className="button" type="button" onClick={() => onPageChange(page - 1)} disabled={page <= 1}>上一页</button>
            <span className="muted-copy">第 {page} / {normalizedTotalPages} 页</span>
            <button className="button" type="button" onClick={() => onPageChange(page + 1)} disabled={page >= normalizedTotalPages}>下一页</button>
          </div>
        </div>
        <div className="table-wrapper">
          <table>
            <thead><tr><th>邮箱</th><th>模式</th><th>状态</th><th>调用方</th><th>用途</th><th>到期时间</th><th>创建时间</th></tr></thead>
            <tbody>
              {leases.map((lease) => (
                <tr key={lease.id}>
                  <td><strong>{lease.primary_email}</strong><div className="muted-copy">{lease.id}</div></td>
                  <td>{lease.mode}</td>
                  <td><LeaseStatusBadge status={lease.status} /></td>
                  <td>{lease.client_tag ?? lease.client_key_id ?? "-"}</td>
                  <td>{lease.purpose ?? "-"}</td>
                  <td>{formatTime(lease.expires_at)}</td>
                  <td>{formatTime(lease.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {leases.length === 0 && <div className="empty-state"><CircleOff size={16} style={{ verticalAlign: "middle", marginRight: 6 }} />暂无租约。调用方领取邮箱后会显示在这里。</div>}
      </section>
    </>
  );
}

function SummaryRow({ label, value }: { label: string; value: number }): JSX.Element {
  return <div className="summary-row"><span>{label}</span><strong>{value}</strong></div>;
}

function ClientKeysPage({
  clientKeys,
  createdApiKey,
  filterText,
  isCreating,
  isCreateDialogOpen,
  onCloseCreateDialog,
  onCopyApiKey,
  onCreate,
  onDisable,
  onFilterTextChange,
  onOpenCreateDialog,
  onDismissCreatedApiKey,
}: {
  clientKeys: ClientKeyListItem[];
  createdApiKey: string | null;
  filterText: string;
  isCreating: boolean;
  isCreateDialogOpen: boolean;
  onCloseCreateDialog: () => void;
  onCopyApiKey: () => void;
  onCreate: (event: FormEvent<HTMLFormElement>) => void;
  onDisable: (clientKey: ClientKeyListItem) => void;
  onFilterTextChange: (value: string) => void;
  onOpenCreateDialog: () => void;
  onDismissCreatedApiKey: () => void;
}): JSX.Element {
  const visibleClientKeys = useMemo(
    () =>
      clientKeys.filter((clientKey) =>
        clientKey.name.toLowerCase().includes(filterText.trim().toLowerCase()),
      ),
    [clientKeys, filterText],
  );
  const enabledClientKeyCount = clientKeys.filter((clientKey) => clientKey.enabled).length;

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">Client Key 管理</h1>
          <p className="page-subtitle">
            创建外部调用方 API Key。明文只在创建时显示一次，列表不会回显密钥。
          </p>
        </div>
        <button className="button button-primary" type="button" onClick={onOpenCreateDialog}>
          <Plus size={15} /> 创建 Client Key
        </button>
      </header>

      <section className="metric-grid" aria-label="Client Key 指标">
        <MetricCard label="全部 Key" value={clientKeys.length} />
        <MetricCard label="启用中" value={enabledClientKeyCount} />
        <MetricCard label="已停用" value={clientKeys.length - enabledClientKeyCount} />
        <MetricCard
          label="近期使用"
          value={clientKeys.filter((clientKey) => clientKey.last_used_at).length}
        />
      </section>

      {createdApiKey && (
        <section className="panel created-key-panel" aria-label="新建 Client Key 明文">
          <div className="section-header">
            <div>
              <h2 className="section-title">请立即保存 API Key</h2>
              <p className="page-subtitle">
                该明文只会显示一次。关闭后将无法再次查看完整密钥，请复制到安全位置。
              </p>
            </div>
            <button className="button" type="button" onClick={onDismissCreatedApiKey}>
              我已保存
            </button>
          </div>
          <div className="created-key-box">
            <code className="created-key-value">{createdApiKey}</code>
            <button className="button" type="button" onClick={onCopyApiKey}>
              <Copy size={14} /> 复制
            </button>
          </div>
        </section>
      )}

      <section className="panel">
        <div className="toolbar">
          <div>
            <h2 className="section-title">Client Key 列表</h2>
            <span className="muted-copy">共 {clientKeys.length} 个</span>
          </div>
          <input
            className="input"
            style={{ maxWidth: 260 }}
            value={filterText}
            onChange={(event) => onFilterTextChange(event.target.value)}
            placeholder="按名称筛选"
          />
        </div>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>名称</th>
                <th>权限</th>
                <th>状态</th>
                <th>最近使用</th>
                <th>过期时间</th>
                <th>创建时间</th>
                <th aria-label="操作" />
              </tr>
            </thead>
            <tbody>
              {visibleClientKeys.map((clientKey) => (
                <tr key={clientKey.id}>
                  <td>
                    <strong>{clientKey.name}</strong>
                    <div className="muted-copy">{clientKey.id}</div>
                  </td>
                  <td>
                    <div className="scope-chip-list">
                      {clientKey.scopes.map((scope) => (
                        <span key={`${clientKey.id}-${scope}`} className="scope-chip" title={scope}>
                          {formatClientKeyScopeLabel(scope)}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td>
                    <ClientKeyStatusBadge enabled={clientKey.enabled} />
                  </td>
                  <td>{formatTime(clientKey.last_used_at)}</td>
                  <td>{formatTime(clientKey.expires_at)}</td>
                  <td>{formatTime(clientKey.created_at)}</td>
                  <td>
                    <div className="cell-actions">
                      <button
                        className="button button-danger"
                        type="button"
                        disabled={!clientKey.enabled}
                        onClick={() => onDisable(clientKey)}
                      >
                        停用
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {visibleClientKeys.length === 0 && (
          <div className="empty-state">
            <CircleOff size={16} style={{ verticalAlign: "middle", marginRight: 6 }} />
            暂无 Client Key。创建后可用于外部租约与 Token 接口鉴权。
          </div>
        )}
      </section>

      {isCreateDialogOpen && (
        <div className="dialog-backdrop" role="presentation">
          <form
            className="dialog dialog-wide"
            role="dialog"
            aria-modal="true"
            aria-labelledby="client-key-create-title"
            onSubmit={onCreate}
          >
            <div className="section-header">
              <div>
                <h2 className="section-title" id="client-key-create-title">
                  创建 Client Key
                </h2>
                <p className="page-subtitle">
                  按最小权限勾选 scopes。创建成功后仅展示一次明文 API Key。
                </p>
              </div>
            </div>
            <div className="form-grid">
              <label className="form-field full-width">
                名称
                <input className="input" name="name" required maxLength={100} placeholder="registration-worker" />
              </label>
              <label className="form-field full-width">
                过期时间（可选）
                <input className="input" name="expires_at" type="datetime-local" />
              </label>
              <fieldset className="form-field full-width scope-fieldset">
                <legend>权限 scopes</legend>
                <div className="scope-option-list">
                  {CLIENT_KEY_SCOPE_OPTIONS.map((scopeOption) => (
                    <label key={scopeOption.id} className="checkbox-label scope-option">
                      <input
                        type="checkbox"
                        name="scopes"
                        value={scopeOption.id}
                        defaultChecked={
                          scopeOption.id === "leases:acquire" ||
                          scopeOption.id === "leases:release" ||
                          scopeOption.id === "tokens:access:read"
                        }
                      />
                      <span>
                        <strong>{scopeOption.label}</strong>
                        <div className="muted-copy">{scopeOption.description}</div>
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>
            </div>
            <div className="dialog-actions">
              <button className="button" type="button" onClick={onCloseCreateDialog} disabled={isCreating}>
                取消
              </button>
              <button className="button button-primary" type="submit" disabled={isCreating}>
                {isCreating ? "创建中" : "创建并显示密钥"}
              </button>
            </div>
          </form>
        </div>
      )}
    </>
  );
}

function LoginPage({
  adminToken,
  errorMessage,
  isLoading,
  onAdminTokenChange,
  onSubmit,
}: {
  adminToken: string;
  errorMessage: string | null;
  isLoading: boolean;
  onAdminTokenChange: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
}): JSX.Element {
  return (
    <main className="login-page">
      <section className="login-brand-panel" aria-label="产品说明">
        <div>
          <div className="brand">Mailbox Service</div>
          <h1 className="login-title">统一维护邮箱凭证、租约与出口代理。</h1>
          <p className="login-description">
            登录后可查看邮箱健康、租约占用、审计概览，并管理 OAuth 与 IMAP 的出口代理策略。
          </p>
        </div>
      </section>
      <section className="login-form-panel" aria-label="管理员登录">
        <form className="login-card" onSubmit={onSubmit}>
          <div>
            <h2 className="section-title">管理员登录</h2>
            <p className="page-subtitle">
              输入部署环境中的 Admin Token。登录后会保存在当前浏览器标签页的会话存储中，刷新页面无需重新输入；关闭标签页后清除。
            </p>
          </div>
          <label className="form-field full-width">
            Admin Token
            <input
              className="input"
              type="password"
              value={adminToken}
              onChange={(event) => onAdminTokenChange(event.target.value)}
              placeholder="输入 X-Admin-Token"
              aria-label="管理员 Token"
              autoFocus
            />
          </label>
          {errorMessage && <div className="notice error">{errorMessage}</div>}
          <button className="button button-primary login-submit" type="submit" disabled={isLoading || !adminToken.trim()}>
            {isLoading ? "登录中" : "登录并进入概览"}
          </button>
        </form>
      </section>
    </main>
  );
}

function App(): JSX.Element {
  const [adminToken, setAdminToken] = useState(() => readStoredAdminToken());
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isRestoringSession, setIsRestoringSession] = useState(() => Boolean(readStoredAdminToken()));
  const [isSidebarVisible, setIsSidebarVisible] = useState(true);
  const [activeNavigationSection, setActiveNavigationSection] = useState<NavigationSection>("dashboard");
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null);
  const [mailboxes, setMailboxes] = useState<MailboxListItem[]>([]);
  const [mailboxPagination, setMailboxPagination] = useState({ total: 0, page: 1, pageSize: 20, totalPages: 1 });
  const [leases, setLeases] = useState<LeaseListItem[]>([]);
  const [leasePagination, setLeasePagination] = useState({ total: 0, page: 1, pageSize: 20, totalPages: 1 });
  const [proxies, setProxies] = useState<EgressProxy[]>([]);
  const [policy, setPolicy] = useState<ProxyPolicy | null>(null);
  const [clientKeys, setClientKeys] = useState<ClientKeyListItem[]>([]);
  const [clientKeyFilterText, setClientKeyFilterText] = useState("");
  const [isClientKeyCreateDialogOpen, setIsClientKeyCreateDialogOpen] = useState(false);
  const [isCreatingClientKey, setIsCreatingClientKey] = useState(false);
  const [createdClientApiKey, setCreatedClientApiKey] = useState<string | null>(null);
  const [filterText, setFilterText] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isCreateDialogOpen, setIsCreateDialogOpen] = useState(false);
  const [isImportDialogOpen, setIsImportDialogOpen] = useState(false);
  const [isImportingMailboxes, setIsImportingMailboxes] = useState(false);
  const [mailboxImportResult, setMailboxImportResult] = useState<MailboxImportResult | null>(null);
  const [selectedMailboxIds, setSelectedMailboxIds] = useState<Set<string>>(() => new Set());
  const [isRefreshingAccessTokens, setIsRefreshingAccessTokens] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const visibleProxies = useMemo(
    () => proxies.filter((proxy) => proxy.name.toLowerCase().includes(filterText.toLowerCase())),
    [filterText, proxies],
  );

  const healthyProxyCount = proxies.filter((proxy) => proxy.enabled && proxy.status === "healthy").length;
  const cooldownProxyCount = proxies.filter((proxy) => proxy.status === "cooldown").length;
  const boundMailboxCount = proxies.reduce((total, proxy) => total + proxy.bound_mailbox_count, 0);

  function resolveAdminToken(tokenOverride?: string): string {
    return (tokenOverride ?? adminToken).trim();
  }

  async function loadDashboard(tokenOverride?: string): Promise<boolean> {
    const tokenForRequest = resolveAdminToken(tokenOverride);
    if (!tokenForRequest) {
      setErrorMessage("输入管理员 Token 后才能读取管理台数据。");
      return false;
    }
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const dashboard = await requestApi<DashboardSummary>(tokenForRequest, "/api/v1/admin/dashboard");
      setDashboardSummary(dashboard);
      return true;
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法加载概览数据。");
      return false;
    } finally {
      setIsLoading(false);
    }
  }

  async function loadMailboxes(
    requestedMailboxPage = mailboxPagination.page,
    tokenOverride?: string,
  ): Promise<boolean> {
    const tokenForRequest = resolveAdminToken(tokenOverride);
    if (!tokenForRequest) {
      setErrorMessage("输入管理员 Token 后才能读取管理台数据。");
      return false;
    }
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const mailboxList = await requestApi<MailboxListResponse>(
        tokenForRequest,
        `/api/v1/admin/mailboxes?page=${requestedMailboxPage}&page_size=${mailboxPagination.pageSize}`,
      );
      setMailboxes(mailboxList.items);
      setMailboxPagination({
        total: mailboxList.total,
        page: mailboxList.page,
        pageSize: mailboxList.page_size,
        totalPages: mailboxList.total_pages,
      });
      setSelectedMailboxIds((currentSelectedMailboxIds) => {
        const existingMailboxIds = new Set(mailboxList.items.map((mailbox) => mailbox.id));
        return new Set([...currentSelectedMailboxIds].filter((mailboxId) => existingMailboxIds.has(mailboxId)));
      });
      return true;
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法加载邮箱列表。");
      return false;
    } finally {
      setIsLoading(false);
    }
  }

  async function loadLeases(
    requestedLeasePage = leasePagination.page,
    tokenOverride?: string,
  ): Promise<boolean> {
    const tokenForRequest = resolveAdminToken(tokenOverride);
    if (!tokenForRequest) {
      setErrorMessage("输入管理员 Token 后才能读取管理台数据。");
      return false;
    }
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const leaseList = await requestApi<LeaseListResponse>(
        tokenForRequest,
        `/api/v1/admin/leases?page=${requestedLeasePage}&page_size=${leasePagination.pageSize}`,
      );
      setLeases(leaseList.items);
      setLeasePagination({
        total: leaseList.total,
        page: leaseList.page,
        pageSize: leaseList.page_size,
        totalPages: leaseList.total_pages,
      });
      return true;
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法加载租约列表。");
      return false;
    } finally {
      setIsLoading(false);
    }
  }

  async function loadEgressProxies(tokenOverride?: string): Promise<boolean> {
    const tokenForRequest = resolveAdminToken(tokenOverride);
    if (!tokenForRequest) {
      setErrorMessage("输入管理员 Token 后才能读取管理台数据。");
      return false;
    }
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [proxyList, proxyPolicy] = await Promise.all([
        requestApi<EgressProxy[]>(tokenForRequest, "/api/v1/admin/egress-proxies"),
        requestApi<ProxyPolicy>(tokenForRequest, "/api/v1/admin/egress-proxy-policy"),
      ]);
      setProxies(proxyList);
      setPolicy(proxyPolicy);
      return true;
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法加载出口代理配置。");
      return false;
    } finally {
      setIsLoading(false);
    }
  }

  async function loadClientKeys(tokenOverride?: string): Promise<boolean> {
    const tokenForRequest = resolveAdminToken(tokenOverride);
    if (!tokenForRequest) {
      setErrorMessage("输入管理员 Token 后才能读取管理台数据。");
      return false;
    }
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const clientKeyList = await requestApi<ClientKeyListItem[]>(
        tokenForRequest,
        "/api/v1/admin/client-keys",
      );
      setClientKeys(clientKeyList);
      return true;
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法加载 Client Key 列表。");
      return false;
    } finally {
      setIsLoading(false);
    }
  }

  async function loadSectionData(
    section: NavigationSection,
    tokenOverride?: string,
  ): Promise<boolean> {
    switch (section) {
      case "dashboard":
        return loadDashboard(tokenOverride);
      case "mailboxes":
        return loadMailboxes(mailboxPagination.page, tokenOverride);
      case "leases":
        return loadLeases(leasePagination.page, tokenOverride);
      case "egress-proxies":
        return loadEgressProxies(tokenOverride);
      case "client-keys":
        return loadClientKeys(tokenOverride);
      default: {
        const exhaustiveCheck: never = section;
        return exhaustiveCheck;
      }
    }
  }

  function navigateToSection(section: NavigationSection): void {
    setActiveNavigationSection(section);
    void loadSectionData(section);
  }

  useEffect(() => {
    const storedToken = readStoredAdminToken().trim();
    if (!storedToken) {
      setIsRestoringSession(false);
      return;
    }

    let cancelled = false;
    void (async () => {
      // Session restore lands on dashboard; only fetch overview data.
      const isLoaded = await loadDashboard(storedToken);
      if (cancelled) {
        return;
      }
      if (isLoaded) {
        setAdminToken(storedToken);
        setIsAuthenticated(true);
        setActiveNavigationSection("dashboard");
        setNotice(null);
      } else {
        writeStoredAdminToken("");
        setAdminToken("");
        setIsAuthenticated(false);
      }
      setIsRestoringSession(false);
    })();

    return () => {
      cancelled = true;
    };
    // Restore once on mount from sessionStorage.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function handleLogin(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const tokenForLogin = adminToken.trim();
    if (!tokenForLogin) {
      setErrorMessage("请输入管理员 Token。");
      return;
    }
    // Login lands on dashboard; only fetch overview data.
    const isLoaded = await loadDashboard(tokenForLogin);
    if (isLoaded) {
      writeStoredAdminToken(tokenForLogin);
      setAdminToken(tokenForLogin);
      setIsAuthenticated(true);
      setActiveNavigationSection("dashboard");
      setNotice(null);
    }
  }

  function handleLogout(): void {
    writeStoredAdminToken("");
    setIsAuthenticated(false);
    setIsRestoringSession(false);
    setIsSidebarVisible(true);
    setAdminToken("");
    setNotice(null);
    setErrorMessage(null);
    setDashboardSummary(null);
    setMailboxes([]);
    setMailboxPagination({ total: 0, page: 1, pageSize: 20, totalPages: 1 });
    setLeases([]);
    setLeasePagination({ total: 0, page: 1, pageSize: 20, totalPages: 1 });
    setProxies([]);
    setPolicy(null);
    setClientKeys([]);
    setClientKeyFilterText("");
    setIsClientKeyCreateDialogOpen(false);
    setCreatedClientApiKey(null);
    setIsCreateDialogOpen(false);
    setIsImportDialogOpen(false);
    setMailboxImportResult(null);
    setSelectedMailboxIds(new Set());
  }

  function toggleMailboxSelection(mailboxId: string, isSelected: boolean): void {
    setSelectedMailboxIds((currentSelectedMailboxIds) => {
      const nextSelectedMailboxIds = new Set(currentSelectedMailboxIds);
      if (isSelected) {
        nextSelectedMailboxIds.add(mailboxId);
      } else {
        nextSelectedMailboxIds.delete(mailboxId);
      }
      return nextSelectedMailboxIds;
    });
  }

  function toggleAllMailboxSelection(isSelected: boolean): void {
    setSelectedMailboxIds(isSelected ? new Set(mailboxes.map((mailbox) => mailbox.id)) : new Set());
  }

  async function refreshAccessTokens(mailboxIds: string[] | null): Promise<void> {
    setIsRefreshingAccessTokens(true);
    setErrorMessage(null);
    try {
      const result = await requestApi<MailboxAccessTokenRefreshResult>(
        adminToken,
        "/api/v1/admin/mailboxes/access-tokens/refresh",
        {
          method: "POST",
          body: JSON.stringify({ mailbox_ids: mailboxIds }),
        },
      );
      setNotice(`AT 刷新完成：成功 ${result.successful}，失败 ${result.failed}。`);
      if (result.failed > 0) {
        const failedSummaries = result.results
          .filter((item) => !item.successful)
          .slice(0, 3)
          .map((item) => `${item.primary_email ?? item.mailbox_id}：${item.error_summary ?? "刷新失败"}`);
        setErrorMessage(`部分邮箱刷新失败：${failedSummaries.join("；")}`);
      }
      await loadMailboxes();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法刷新邮箱 AT。");
    } finally {
      setIsRefreshingAccessTokens(false);
    }
  }

  async function refreshSelectedAccessTokens(): Promise<void> {
    const mailboxIds = [...selectedMailboxIds];
    if (mailboxIds.length === 0) {
      setErrorMessage("请先选择需要刷新 AT 的邮箱。");
      return;
    }
    await refreshAccessTokens(mailboxIds);
  }

  async function refreshAllAccessTokens(): Promise<void> {
    await refreshAccessTokens(null);
  }

  async function changeMailboxPage(nextPage: number): Promise<void> {
    const boundedNextPage = Math.min(Math.max(nextPage, 1), Math.max(mailboxPagination.totalPages, 1));
    if (boundedNextPage === mailboxPagination.page) {
      return;
    }
    setSelectedMailboxIds(new Set());
    await loadMailboxes(boundedNextPage);
  }

  async function changeLeasePage(nextPage: number): Promise<void> {
    const boundedNextPage = Math.min(Math.max(nextPage, 1), Math.max(leasePagination.totalPages, 1));
    if (boundedNextPage === leasePagination.page) {
      return;
    }
    await loadLeases(boundedNextPage);
  }

  function openMailboxImportDialog(): void {
    setErrorMessage(null);
    setMailboxImportResult(null);
    setIsImportDialogOpen(true);
  }

  function closeMailboxImportDialog(): void {
    setIsImportDialogOpen(false);
    setMailboxImportResult(null);
  }

  async function importMailboxes(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const content = String(formData.get("content") ?? "").trim();
    const onConflict = String(formData.get("on_conflict") ?? "replace_token") as MailboxImportConflictStrategy;
    if (!content) {
      setErrorMessage("请粘贴需要导入的邮箱内容。");
      return;
    }

    setIsImportingMailboxes(true);
    setErrorMessage(null);
    setMailboxImportResult(null);
    try {
      const result = await requestApi<MailboxImportResult>(adminToken, "/api/v1/admin/mailboxes/import", {
        method: "POST",
        body: JSON.stringify({ content, on_conflict: onConflict }),
      });
      setMailboxImportResult(result);
      setNotice(`邮箱导入完成：新增 ${result.created}，更新 ${result.updated}，跳过 ${result.skipped}，失败 ${result.failed}。`);
      await loadMailboxes();
      if (result.failed === 0) {
        closeMailboxImportDialog();
      }
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "邮箱导入失败。");
    } finally {
      setIsImportingMailboxes(false);
    }
  }

  async function updatePolicy(changes: Partial<ProxyPolicy>): Promise<void> {
    if (!policy) {
      return;
    }
    try {
      const updatedPolicy = await requestApi<ProxyPolicy>(adminToken, "/api/v1/admin/egress-proxy-policy", {
        method: "PATCH",
        body: JSON.stringify(changes),
      });
      setPolicy(updatedPolicy);
      setNotice("全局代理策略已更新。");
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法更新代理策略。");
    }
  }

  async function createProxy(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const username = String(formData.get("username") ?? "").trim();
    const password = String(formData.get("password") ?? "");
    const payload = {
      name: String(formData.get("name") ?? "").trim(),
      protocol: String(formData.get("protocol") ?? "socks5") as ProxyProtocol,
      host: String(formData.get("host") ?? "").trim(),
      port: Number(formData.get("port")),
      priority: Number(formData.get("priority")),
      username: username || undefined,
      password: password || undefined,
      enabled: formData.get("enabled") === "on",
    };

    try {
      await requestApi<EgressProxy>(adminToken, "/api/v1/admin/egress-proxies", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setIsCreateDialogOpen(false);
      setNotice("出口代理已创建。认证信息不会再次显示。");
      await loadEgressProxies();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法创建出口代理。");
    }
  }

  function replaceProxyInList(updatedProxy: EgressProxy): void {
    setProxies((currentProxies) =>
      currentProxies.map((currentProxy) =>
        currentProxy.id === updatedProxy.id
          ? {
              ...currentProxy,
              ...updatedProxy,
              bound_mailbox_count:
                updatedProxy.bound_mailbox_count > 0
                  ? updatedProxy.bound_mailbox_count
                  : currentProxy.bound_mailbox_count,
            }
          : currentProxy,
      ),
    );
  }

  async function toggleProxy(proxy: EgressProxy): Promise<void> {
    const action = proxy.enabled ? "disable" : "enable";
    try {
      const updatedProxy = await requestApi<EgressProxy>(
        adminToken,
        `/api/v1/admin/egress-proxies/${proxy.id}/${action}`,
        {
          method: "POST",
        },
      );
      replaceProxyInList(updatedProxy);
      setNotice(proxy.enabled ? "出口代理已停用，绑定邮箱会在下次外联时重新选择。" : "出口代理已启用。");
      // Background refresh keeps proxy list metrics in sync without blocking the list badge update.
      void loadEgressProxies();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法更新出口代理。");
    }
  }

  async function testProxy(proxy: EgressProxy): Promise<void> {
    try {
      const result = await requestApi<ConnectivityResult>(
        adminToken,
        `/api/v1/admin/egress-proxies/${proxy.id}/test`,
        { method: "POST" },
      );
      if (result.successful) {
        setNotice(`代理 ${proxy.name} 连接测试成功。`);
      } else {
        setErrorMessage(result.error_summary ?? "代理连接测试失败。");
      }
      await loadEgressProxies();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "代理连接测试失败。");
    }
  }

  async function recoverProxy(proxy: EgressProxy): Promise<void> {
    try {
      const updatedProxy = await requestApi<EgressProxy>(
        adminToken,
        `/api/v1/admin/egress-proxies/${proxy.id}/recover`,
        {
          method: "POST",
        },
      );
      replaceProxyInList(updatedProxy);
      setNotice(`代理 ${proxy.name} 已恢复为待验证状态。`);
      void loadEgressProxies();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法恢复出口代理。");
    }
  }

  async function deleteProxy(proxy: EgressProxy): Promise<void> {
    const shouldDelete = window.confirm(
      `删除出口代理“${proxy.name}”？将先解除 ${proxy.bound_mailbox_count} 个邮箱的绑定。`,
    );
    if (!shouldDelete) {
      return;
    }
    try {
      await requestApi<void>(adminToken, `/api/v1/admin/egress-proxies/${proxy.id}?force=true`, {
        method: "DELETE",
      });
      setNotice(`出口代理 ${proxy.name} 已删除。`);
      await loadEgressProxies();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法删除出口代理。");
    }
  }

  async function createClientKey(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const name = String(formData.get("name") ?? "").trim();
    const scopes = formData
      .getAll("scopes")
      .map((scopeValue) => String(scopeValue))
      .filter((scopeValue): scopeValue is ClientKeyScope =>
        CLIENT_KEY_SCOPE_OPTIONS.some((option) => option.id === scopeValue),
      );
    const expiresAtRaw = String(formData.get("expires_at") ?? "").trim();
    if (!name) {
      setErrorMessage("Client Key 名称不能为空。");
      return;
    }
    if (scopes.length === 0) {
      setErrorMessage("请至少选择一个权限 scope。");
      return;
    }

    setIsCreatingClientKey(true);
    setErrorMessage(null);
    try {
      const createdClientKey = await requestApi<ClientKeyCreatedResponse>(
        adminToken,
        "/api/v1/admin/client-keys",
        {
          method: "POST",
          body: JSON.stringify({
            name,
            scopes,
            expires_at: expiresAtRaw ? new Date(expiresAtRaw).toISOString() : null,
          }),
        },
      );
      setClientKeys((currentClientKeys) => [
        {
          id: createdClientKey.id,
          name: createdClientKey.name,
          scopes: createdClientKey.scopes,
          enabled: createdClientKey.enabled,
          expires_at: createdClientKey.expires_at,
          last_used_at: null,
          created_at: createdClientKey.created_at,
          updated_at: createdClientKey.created_at,
        },
        ...currentClientKeys,
      ]);
      setCreatedClientApiKey(createdClientKey.api_key);
      setIsClientKeyCreateDialogOpen(false);
      setNotice(`Client Key「${createdClientKey.name}」已创建，请立即保存明文 API Key。`);
      void loadClientKeys();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法创建 Client Key。");
    } finally {
      setIsCreatingClientKey(false);
    }
  }

  async function disableClientKey(clientKey: ClientKeyListItem): Promise<void> {
    if (!clientKey.enabled) {
      return;
    }
    const shouldDisable = window.confirm(
      `停用 Client Key「${clientKey.name}」？停用后外部请求将立即拒绝该密钥。`,
    );
    if (!shouldDisable) {
      return;
    }
    try {
      const updatedClientKey = await requestApi<ClientKeyListItem>(
        adminToken,
        `/api/v1/admin/client-keys/${clientKey.id}/disable`,
        { method: "POST" },
      );
      setClientKeys((currentClientKeys) =>
        currentClientKeys.map((currentClientKey) =>
          currentClientKey.id === updatedClientKey.id ? updatedClientKey : currentClientKey,
        ),
      );
      setNotice(`Client Key「${clientKey.name}」已停用。`);
      void loadClientKeys();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法停用 Client Key。");
    }
  }

  async function copyCreatedClientApiKey(): Promise<void> {
    if (!createdClientApiKey) {
      return;
    }
    try {
      await navigator.clipboard.writeText(createdClientApiKey);
      setNotice("API Key 已复制到剪贴板。");
    } catch {
      setErrorMessage("复制失败，请手动选中密钥文本复制。");
    }
  }

  if (isRestoringSession) {
    return (
      <main className="login-page">
        <section className="login-form-panel" aria-label="会话恢复">
          <div className="login-card">
            <h2 className="section-title">正在恢复登录</h2>
            <p className="page-subtitle">已检测到本标签页的管理员会话，正在校验并加载数据…</p>
          </div>
        </section>
      </main>
    );
  }

  if (!isAuthenticated) {
    return (
      <LoginPage
        adminToken={adminToken}
        errorMessage={errorMessage}
        isLoading={isLoading}
        onAdminTokenChange={(value) => {
          setAdminToken(value);
          setErrorMessage(null);
        }}
        onSubmit={(event) => void handleLogin(event)}
      />
    );
  }

  return (
    <main className={`application-shell ${isSidebarVisible ? "" : "sidebar-hidden"}`}>
      {isSidebarVisible && (
      <aside className="sidebar">
        <div className="sidebar-header">
          <div>
            <div className="brand">Mailbox Service</div>
            <div className="brand-subtitle">凭证与邮箱运维控制台</div>
          </div>
          <button
            className="button icon-button sidebar-toggle"
            type="button"
            aria-label="隐藏导航栏"
            title="隐藏导航栏"
            onClick={() => setIsSidebarVisible(false)}
          >
            <PanelLeftClose size={16} />
          </button>
        </div>
        <nav className="navigation-group" aria-label="系统导航">
          <button className={`navigation-item ${activeNavigationSection === "dashboard" ? "active" : ""}`} type="button" onClick={() => navigateToSection("dashboard")} aria-current={activeNavigationSection === "dashboard" ? "page" : undefined}><ServerCog size={16} /> 概览</button>
          <button className={`navigation-item ${activeNavigationSection === "mailboxes" ? "active" : ""}`} type="button" onClick={() => navigateToSection("mailboxes")} aria-current={activeNavigationSection === "mailboxes" ? "page" : undefined}><ShieldCheck size={16} /> 邮箱管理</button>
          <button className={`navigation-item ${activeNavigationSection === "leases" ? "active" : ""}`} type="button" onClick={() => navigateToSection("leases")} aria-current={activeNavigationSection === "leases" ? "page" : undefined}><Network size={16} /> 租约管理</button>
          <button className={`navigation-item ${activeNavigationSection === "egress-proxies" ? "active" : ""}`} type="button" onClick={() => navigateToSection("egress-proxies")} aria-current={activeNavigationSection === "egress-proxies" ? "page" : undefined}><Settings2 size={16} /> 出口代理</button>
          <button className={`navigation-item ${activeNavigationSection === "client-keys" ? "active" : ""}`} type="button" onClick={() => navigateToSection("client-keys")} aria-current={activeNavigationSection === "client-keys" ? "page" : undefined}><KeyRound size={16} /> Client Key</button>
          <a className="navigation-item" href={`${apiBaseUrl}/redoc`} target="_blank" rel="noreferrer">
            <BookOpen size={16} /> API 文档
          </a>
        </nav>
        <div className="sidebar-footer">
          <div className="sidebar-actions">
            <button className="navigation-item" type="button" onClick={handleLogout}>
              <LogOut size={16} /> 退出登录
            </button>
          </div>
        </div>
      </aside>
      )}

      {!isSidebarVisible && (
        <button
          className="button icon-button sidebar-show-button"
          type="button"
          aria-label="展开导航栏"
          title="展开导航栏"
          onClick={() => setIsSidebarVisible(true)}
        >
          <PanelLeftOpen size={16} />
        </button>
      )}

      <section className="content">
        {notice && (
          <div className="notice" role="status">
            <span className="notice-content">
              <CheckCircle2 size={14} aria-hidden="true" />
              <span>{notice}</span>
            </span>
            <button
              className="notice-close"
              type="button"
              aria-label="关闭成功提示"
              onClick={() => setNotice(null)}
            >
              <X size={14} aria-hidden="true" />
            </button>
          </div>
        )}
        {errorMessage && (
          <div className="notice error" role="alert">
            <span className="notice-content">
              <CircleAlert size={14} aria-hidden="true" />
              <span>{errorMessage}</span>
            </span>
            <button
              className="notice-close"
              type="button"
              aria-label="关闭错误提示"
              onClick={() => setErrorMessage(null)}
            >
              <X size={14} aria-hidden="true" />
            </button>
          </div>
        )}
        {activeNavigationSection === "dashboard" ? (
          <DashboardPage summary={dashboardSummary} />
        ) : activeNavigationSection === "mailboxes" ? (
          <MailboxesPage
            mailboxes={mailboxes}
            page={mailboxPagination.page}
            pageSize={mailboxPagination.pageSize}
            total={mailboxPagination.total}
            totalPages={mailboxPagination.totalPages}
            selectedMailboxIds={selectedMailboxIds}
            isRefreshingAccessTokens={isRefreshingAccessTokens}
            onPageChange={(nextPage) => void changeMailboxPage(nextPage)}
            onOpenImport={openMailboxImportDialog}
            onRefreshAllAccessTokens={() => void refreshAllAccessTokens()}
            onRefreshSelectedAccessTokens={() => void refreshSelectedAccessTokens()}
            onToggleAllMailboxSelection={toggleAllMailboxSelection}
            onToggleMailboxSelection={toggleMailboxSelection}
          />
        ) : activeNavigationSection === "leases" ? (
          <LeasesPage
            leases={leases}
            page={leasePagination.page}
            pageSize={leasePagination.pageSize}
            total={leasePagination.total}
            totalPages={leasePagination.totalPages}
            onPageChange={(nextPage) => void changeLeasePage(nextPage)}
          />
        ) : activeNavigationSection === "client-keys" ? (
          <ClientKeysPage
            clientKeys={clientKeys}
            createdApiKey={createdClientApiKey}
            filterText={clientKeyFilterText}
            isCreating={isCreatingClientKey}
            isCreateDialogOpen={isClientKeyCreateDialogOpen}
            onCloseCreateDialog={() => setIsClientKeyCreateDialogOpen(false)}
            onCopyApiKey={() => void copyCreatedClientApiKey()}
            onCreate={(event) => void createClientKey(event)}
            onDisable={(clientKey) => void disableClientKey(clientKey)}
            onFilterTextChange={setClientKeyFilterText}
            onOpenCreateDialog={() => {
              setErrorMessage(null);
              setIsClientKeyCreateDialogOpen(true);
            }}
            onDismissCreatedApiKey={() => setCreatedClientApiKey(null)}
          />
        ) : (
          <>
        <header className="page-header">
          <div>
            <h1 className="page-title">出口代理</h1>
            <p className="page-subtitle">按邮箱粘性路由 Microsoft OAuth 与 XOAUTH2 IMAP 流量。</p>
          </div>
          <button className="button button-primary" type="button" onClick={() => setIsCreateDialogOpen(true)} disabled={!adminToken}>
            <Plus size={15} /> 添加代理
          </button>
        </header>

        <section className="metric-grid" aria-label="代理指标">
          <MetricCard label="全部代理" value={proxies.length} />
          <MetricCard label="健康代理" value={healthyProxyCount} />
          <MetricCard label="冷却代理" value={cooldownProxyCount} />
          <MetricCard label="绑定邮箱" value={boundMailboxCount} />
        </section>

        {policy && (
          <section className="panel" style={{ marginBottom: 24 }}>
            <div className="section-header">
              <div>
                <h2 className="section-title">全局代理策略</h2>
                <p className="page-subtitle">强制代理时，代理池为空或不可用会拒绝请求，不回退直连。</p>
              </div>
            </div>
            <div className="form-grid" style={{ marginBottom: 0 }}>
              <label className="checkbox-label">
                <input type="checkbox" checked={policy.enabled} onChange={(event) => void updatePolicy({ enabled: event.target.checked })} />
                启用代理池
              </label>
              <label className="checkbox-label">
                <input type="checkbox" checked={policy.required} onChange={(event) => void updatePolicy({ required: event.target.checked })} />
                强制代理，不允许直连
              </label>
              <label className="form-field">
                连接超时（秒）
                <input className="input" type="number" min="1" defaultValue={policy.connect_timeout_seconds} onBlur={(event) => void updatePolicy({ connect_timeout_seconds: Number(event.target.value) })} />
              </label>
              <label className="form-field">
                失败阈值
                <input className="input" type="number" min="1" defaultValue={policy.failure_threshold} onBlur={(event) => void updatePolicy({ failure_threshold: Number(event.target.value) })} />
              </label>
            </div>
          </section>
        )}

        <section className="panel">
          <div className="toolbar">
            <h2 className="section-title">代理池</h2>
            <input className="input" style={{ maxWidth: 260 }} value={filterText} onChange={(event) => setFilterText(event.target.value)} placeholder="按名称筛选" />
          </div>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>名称</th>
                  <th>协议 / 地址</th>
                  <th>状态</th>
                  <th>优先级</th>
                  <th>绑定邮箱</th>
                  <th>最近成功</th>
                  <th aria-label="操作" />
                </tr>
              </thead>
              <tbody>
                {visibleProxies.map((proxy) => (
                  <tr key={proxy.id}>
                    <td>
                      <strong>{proxy.name}</strong>
                      <div className="muted-copy">{proxy.has_credentials ? "已配置认证" : "无认证"}</div>
                    </td>
                    <td>{proxy.protocol === "socks5" ? "SOCKS5" : "HTTP CONNECT"}<div className="muted-copy">{proxy.host_preview}:{proxy.port}</div></td>
                    <td><StatusBadge proxy={proxy} /></td>
                    <td>{proxy.priority}</td>
                    <td>{proxy.bound_mailbox_count}</td>
                    <td>{formatTime(proxy.last_success_at)}</td>
                    <td>
                      <div className="cell-actions">
                        <button className="button" type="button" onClick={() => void testProxy(proxy)}>测试</button>
                        {proxy.status === "cooldown" && <button className="button" type="button" onClick={() => void recoverProxy(proxy)}>恢复</button>}
                        <button className="button" type="button" onClick={() => void toggleProxy(proxy)}>{proxy.enabled ? "停用" : "启用"}</button>
                        <button className="button button-danger icon-button" type="button" aria-label={`删除 ${proxy.name}`} onClick={() => void deleteProxy(proxy)}><Trash2 size={14} /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!isLoading && visibleProxies.length === 0 && <div className="empty-state"><CircleOff size={16} style={{ verticalAlign: "middle", marginRight: 6 }} />暂无出口代理。添加后，邮箱会在首次 OAuth 或 IMAP 请求时粘性绑定。</div>}
        </section>
          </>
        )}
      </section>

      {activeNavigationSection === "egress-proxies" && isCreateDialogOpen && (
        <div className="dialog-backdrop" role="presentation">
          <form className="dialog" onSubmit={(event) => void createProxy(event)}>
            <div className="section-header">
              <div>
                <h2 className="section-title">添加出口代理</h2>
                <p className="page-subtitle">认证凭证仅会加密写入，无法从列表读取。</p>
              </div>
            </div>
            <div className="form-grid">
              <label className="form-field">名称<input className="input" name="name" required placeholder="hk-socks-01" /></label>
              <label className="form-field">协议<select className="select" name="protocol" defaultValue="socks5"><option value="socks5">SOCKS5</option><option value="http_connect">HTTP CONNECT</option></select></label>
              <label className="form-field">主机<input className="input" name="host" required placeholder="proxy.example.com" /></label>
              <label className="form-field">端口<input className="input" name="port" type="number" min="1" max="65535" defaultValue="1080" required /></label>
              <label className="form-field">用户名（可选）<input className="input" name="username" autoComplete="off" /></label>
              <label className="form-field">密码（可选）<input className="input" name="password" type="password" autoComplete="new-password" /></label>
              <label className="form-field">优先级<input className="input" name="priority" type="number" min="0" defaultValue="100" required /></label>
              <label className="checkbox-label" style={{ alignSelf: "end", minHeight: 34 }}><input type="checkbox" name="enabled" defaultChecked /> 创建后立即启用</label>
            </div>
            <div className="dialog-actions">
              <button className="button" type="button" onClick={() => setIsCreateDialogOpen(false)}>取消</button>
              <button className="button button-primary" type="submit">安全保存</button>
            </div>
          </form>
        </div>
      )}
      {activeNavigationSection === "mailboxes" && isImportDialogOpen && (
        <MailboxImportDialog
          importResult={mailboxImportResult}
          isImporting={isImportingMailboxes}
          onClose={closeMailboxImportDialog}
          onSubmit={(event) => void importMailboxes(event)}
        />
      )}
    </main>
  );
}

function MetricCard({ label, value }: { label: string; value: number }): JSX.Element {
  return <div className="metric-card"><div className="metric-label">{label}</div><div className="metric-value">{value}</div></div>;
}

export default App;
