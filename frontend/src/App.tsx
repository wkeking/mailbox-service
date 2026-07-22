import { type FormEvent, type JSX, useEffect, useMemo, useState } from "react";
import {
  BookOpen,
  CheckCircle2,
  CircleAlert,
  CircleOff,
  Copy,
  Download,
  KeyRound,
  ListFilter,
  LogOut,
  Globe2,
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
type NavigationSection =
  | "dashboard"
  | "mailboxes"
  | "leases"
  | "usage-sites"
  | "email-site-usages"
  | "egress-proxies"
  | "providers"
  | "operator-console"
  | "client-keys";

interface ProviderHealthItem {
  provider_type: string;
  provider_instance_id: string;
  enabled: boolean;
  status: string;
  latency_ms: number | null;
  checked_at: string | null;
  domains_preview: string[];
  error_summary: string | null;
  detail: Record<string, unknown>;
  display_name: string | null;
  supply_mode: string | null;
}

interface OperatorSession {
  lease_id: string;
  provider_type: string;
  provider_instance_id: string;
  provider_resource_id: string;
  address: string;
  purpose: string;
  expires_at: string;
  created_at: string;
  released_at: string | null;
  last_verification_code: string | null;
  last_code_checked_at: string | null;
}

interface OperatorMessageItem {
  id: string | null;
  from_address: string | null;
  subject: string | null;
  intro: string;
  text: string;
  created_at: string | null;
  code: string | null;
}

const LEGACY_ADMIN_TOKEN_STORAGE_KEY = "mailbox-service.admin-token";

/** Admin Token is memory-only (SEC-14). Best-effort purge of any legacy sessionStorage copy. */
function clearLegacyAdminTokenStorage(): void {
  try {
    sessionStorage.removeItem(LEGACY_ADMIN_TOKEN_STORAGE_KEY);
  } catch {
    // Ignore storage failures.
  }
}

const CLIENT_KEY_SCOPE_OPTIONS = [
  { id: "leases:acquire", label: "领取租约", description: "leases:acquire" },
  { id: "leases:release", label: "释放租约", description: "leases:release" },
  { id: "tokens:access:read", label: "读取 Access Token", description: "tokens:access:read" },
  { id: "tokens:refresh:read", label: "读取 Refresh Token", description: "tokens:refresh:read" },
  { id: "tokens:refresh:write", label: "回写 Refresh Token", description: "tokens:refresh:write" },
  { id: "mailboxes:acquire", label: "领取可用邮箱", description: "mailboxes:acquire" },
  {
    id: "mailboxes:reacquire",
    label: "按历史地址重新领取",
    description: "mailboxes:reacquire",
  },
  {
    id: "mail:verification-code:read",
    label: "读取收件箱验证码",
    description: "mail:verification-code:read",
  },
  {
    id: "providers:smsbower_gmail:acquire",
    label: "领取 SMSBower Gmail",
    description: "providers:smsbower_gmail:acquire",
  },
  {
    id: "providers:cloudflare_temp_email:acquire",
    label: "领取 Cloudflare Temp Email",
    description: "providers:cloudflare_temp_email:acquire",
  },
  {
    id: "providers:ddg_mail:acquire",
    label: "领取 DDG Mail",
    description: "providers:ddg_mail:acquire",
  },
  {
    id: "providers:cloudmail_gen:acquire",
    label: "领取 CloudMail Gen",
    description: "providers:cloudmail_gen:acquire",
  },
  {
    id: "providers:tempmail_lol:acquire",
    label: "领取 TempMail.lol",
    description: "providers:tempmail_lol:acquire",
  },
  {
    id: "providers:duckmail:acquire",
    label: "领取 DuckMail",
    description: "providers:duckmail:acquire",
  },
  {
    id: "providers:gptmail:acquire",
    label: "领取 GPTMail",
    description: "providers:gptmail:acquire",
  },
  {
    id: "providers:moemail:acquire",
    label: "领取 MoeMail",
    description: "providers:moemail:acquire",
  },
  {
    id: "providers:inbucket:acquire",
    label: "领取 Inbucket",
    description: "providers:inbucket:acquire",
  },
  {
    id: "providers:yyds_mail:acquire",
    label: "领取 YYDS Mail",
    description: "providers:yyds_mail:acquire",
  },
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
  host: string;
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

interface ProxyDialogDraft {
  sourceProxyId: string | null;
  name: string;
  protocol: ProxyProtocol;
  host: string;
  port: number;
  priority: number;
  enabled: boolean;
  hasSourceCredentials: boolean;
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

interface ProviderFieldSchema {
  key: string;
  label: string;
  field_type: string;
  required?: boolean;
  secret?: boolean;
  description?: string;
  default?: unknown;
  placeholder?: string;
}

interface ProviderCatalogItem {
  provider_type: string;
  display_name: string;
  supply_mode: string;
  supported_modes: string[];
  configurable_in_ui: boolean;
  enabled?: boolean | null;
  has_api_key?: boolean | null;
  instance_id?: string | null;
  source?: string | null;
  notes?: string | null;
  fields?: ProviderFieldSchema[] | null;
}

interface ProviderInstanceSettings {
  provider_type: string;
  instance_id: string;
  enabled: boolean;
  source: string;
  has_any_secret: boolean;
  secret_flags: Record<string, boolean>;
  values: Record<string, unknown>;
  request_timeout_seconds?: number | null;
  updated_at: string | null;
  fields?: ProviderFieldSchema[] | null;
}

interface SmsbowerSettings {
  provider_type: string;
  instance_id: string;
  enabled: boolean;
  api_base: string;
  service: string;
  domain: string;
  max_price: number | null;
  request_timeout_seconds: number;
  has_api_key: boolean;
  source: string;
  env_enabled_default: boolean;
  updated_at: string | null;
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
  refresh_token_updated_at: string | null;
  refresh_token_expires_at: string | null;
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

interface MailboxBatchDeleteResult {
  deleted: number;
  deleted_mailbox_ids: string[];
  missing_mailbox_ids: string[];
}

interface MailboxDeleteInvalidResult {
  deleted: number;
  deleted_mailbox_ids: string[];
  deleted_primary_emails: string[];
}

interface MailboxUnprobedRefreshResult {
  candidate_total: number;
  processed: number;
  successful: number;
  failed: number;
  remaining_candidates: number;
  batch_size: number;
  worker_count: number;
  results: MailboxAccessTokenRefreshItem[];
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

interface UsageSiteItem {
  code: string;
  display_name: string;
  enabled: boolean;
  created_at: string | null;
  active_usage_count?: number | null;
}

interface UsageSiteListResponse {
  items: UsageSiteItem[];
}

interface EmailSiteUsageItem {
  id: string;
  allocated_email: string;
  usage_site: string;
  mailbox_id: string | null;
  lease_id: string | null;
  client_key_id: string | null;
  created_at: string;
  revoked_at: string | null;
  updated_at: string;
}

interface EmailSiteUsageListResponse {
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
  items: EmailSiteUsageItem[];
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

type UnauthorizedHandler = (() => void) | null;
let adminUnauthorizedHandler: UnauthorizedHandler = null;

function registerAdminUnauthorizedHandler(handler: UnauthorizedHandler): void {
  adminUnauthorizedHandler = handler;
}

function handlePossiblyUnauthorized(statusCode: number): void {
  if (statusCode === 401 && adminUnauthorizedHandler) {
    adminUnauthorizedHandler();
  }
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
  if (response.status === 401) {
    handlePossiblyUnauthorized(401);
    throw new Error("管理员认证失败，请重新登录。");
  }
  if (response.status === 204) {
    return undefined as ResponsePayload;
  }
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(getErrorMessage(payload));
  }
  return payload as ResponsePayload;
}

async function requestApiText(
  adminToken: string,
  path: string,
  options: RequestInit = {},
): Promise<string> {
  const headers = new Headers(options.headers);
  headers.set("X-Admin-Token", adminToken);
  if (options.body) {
    headers.set("Content-Type", "application/json");
  }

  const response = await fetch(`${apiBaseUrl}${path}`, { ...options, headers });
  if (response.status === 401) {
    handlePossiblyUnauthorized(401);
    throw new Error("管理员认证失败，请重新登录。");
  }
  if (!response.ok) {
    const payload: unknown = await response.json().catch(() => null);
    throw new Error(getErrorMessage(payload));
  }
  return response.text();
}

function downloadTextFile(filename: string, content: string): void {
  const textBlob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const objectUrl = URL.createObjectURL(textBlob);
  const downloadAnchor = document.createElement("a");
  downloadAnchor.href = objectUrl;
  downloadAnchor.download = filename;
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  document.body.removeChild(downloadAnchor);
  URL.revokeObjectURL(objectUrl);
}

function buildMailboxExportFilename(): string {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  return `mailboxes-export-${timestamp}.txt`;
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
  isProbingUnprobedMailboxes,
  isExportingSelectedMailboxes,
  isDeletingSelectedMailboxes,
  isDeletingInvalidMailboxes,
  onPageChange,
  onOpenImport,
  onRefreshAllAccessTokens,
  onRefreshSelectedAccessTokens,
  onProbeUnprobedMailboxes,
  onExportSelectedMailboxes,
  onDeleteSelectedMailboxes,
  onDeleteInvalidMailboxes,
  onToggleAllMailboxSelection,
  onToggleMailboxSelection,
  onOpenSiteUsages,
}: {
  mailboxes: MailboxListItem[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  selectedMailboxIds: Set<string>;
  isRefreshingAccessTokens: boolean;
  isProbingUnprobedMailboxes: boolean;
  isExportingSelectedMailboxes: boolean;
  isDeletingSelectedMailboxes: boolean;
  isDeletingInvalidMailboxes: boolean;
  onPageChange: (page: number) => void;
  onOpenImport: () => void;
  onRefreshAllAccessTokens: () => void;
  onRefreshSelectedAccessTokens: () => void;
  onProbeUnprobedMailboxes: () => void;
  onExportSelectedMailboxes: () => void;
  onDeleteSelectedMailboxes: () => void;
  onDeleteInvalidMailboxes: () => void;
  onToggleAllMailboxSelection: (isSelected: boolean) => void;
  onToggleMailboxSelection: (mailboxId: string, isSelected: boolean) => void;
  onOpenSiteUsages: (primaryEmail: string) => void;
}): JSX.Element {
  const selectedMailboxCount = selectedMailboxIds.size;
  const areAllMailboxesSelected = mailboxes.length > 0 && mailboxes.every((mailbox) => selectedMailboxIds.has(mailbox.id));
  const normalizedTotalPages = Math.max(totalPages, 1);
  const isSelectionBusy =
    isRefreshingAccessTokens ||
    isProbingUnprobedMailboxes ||
    isExportingSelectedMailboxes ||
    isDeletingSelectedMailboxes ||
    isDeletingInvalidMailboxes;

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">邮箱管理</h1>
          <p className="page-subtitle">集中维护邮箱凭证、状态、Token 版本与出口代理绑定。</p>
        </div>
        <div className="page-header-actions">
          <button
            className="button"
            type="button"
            onClick={onRefreshAllAccessTokens}
            disabled={isSelectionBusy || total === 0}
            title="强制刷新全部 active 邮箱的 RT/AT"
          >
            <RefreshCw size={14} /> {isRefreshingAccessTokens ? "刷新中" : "刷新全部 RT/AT"}
          </button>
          <button className="button button-primary" type="button" onClick={onOpenImport}>
            <Upload size={15} /> 导入邮箱
          </button>
        </div>
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
              onClick={onProbeUnprobedMailboxes}
              disabled={isSelectionBusy}
              title="对未探测 / 能力未知的邮箱分批强制刷新 RT/AT，识别可用与失效"
            >
              <RefreshCw size={14} /> {isProbingUnprobedMailboxes ? "识别中" : "识别未探测"}
            </button>
            <button
              className="button button-danger"
              type="button"
              onClick={onDeleteInvalidMailboxes}
              disabled={isSelectionBusy}
              title="删除全部 status=invalid 的失效邮箱"
            >
              <Trash2 size={14} /> {isDeletingInvalidMailboxes ? "清理中" : "删除失效邮箱"}
            </button>
            <button
              className="button"
              type="button"
              onClick={onExportSelectedMailboxes}
              disabled={isSelectionBusy || selectedMailboxCount === 0}
            >
              <Download size={14} /> {isExportingSelectedMailboxes ? "导出中" : "导出选中"}
            </button>
            <button
              className="button button-danger"
              type="button"
              onClick={onDeleteSelectedMailboxes}
              disabled={isSelectionBusy || selectedMailboxCount === 0}
            >
              <Trash2 size={14} /> {isDeletingSelectedMailboxes ? "删除中" : "删除选中"}
            </button>
            <button
              className="button"
              type="button"
              onClick={onRefreshSelectedAccessTokens}
              disabled={isSelectionBusy || selectedMailboxCount === 0}
            >
              <RefreshCw size={14} /> 刷新选中 RT/AT
            </button>
            <div className="pagination-actions" aria-label="邮箱分页">
              <button className="button" type="button" onClick={() => onPageChange(page - 1)} disabled={page <= 1}>上一页</button>
              <span className="muted-copy">第 {page} / {normalizedTotalPages} 页</span>
              <button className="button" type="button" onClick={() => onPageChange(page + 1)} disabled={page >= normalizedTotalPages}>下一页</button>
            </div>
          </div>
        </div>
        <div className="table-wrapper">
          <table className="mailbox-table">
            <colgroup>
              <col className="mailbox-col-select" />
              <col className="mailbox-col-email" />
              <col className="mailbox-col-status" />
              <col className="mailbox-col-scope" />
              <col className="mailbox-col-capability" />
              <col className="mailbox-col-token-version" />
              <col className="mailbox-col-datetime" />
              <col className="mailbox-col-datetime" />
              <col className="mailbox-col-proxy" />
              <col className="mailbox-col-lease" />
              <col className="mailbox-col-datetime" />
              <col className="mailbox-col-actions" />
            </colgroup>
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
                <th>Scope</th>
                <th>能力</th>
                <th>Token 版本</th>
                <th>AT 过期时间</th>
                <th>RT 过期时间</th>
                <th>出口代理</th>
                <th>活跃租约</th>
                <th>更新时间</th>
                <th aria-label="操作" />
              </tr>
            </thead>
            <tbody>
              {mailboxes.map((mailbox) => (
                <tr key={mailbox.id}>
                  <td className="cell-center">
                    <input
                      type="checkbox"
                      checked={selectedMailboxIds.has(mailbox.id)}
                      aria-label={`选择 ${mailbox.primary_email}`}
                      onChange={(event) => onToggleMailboxSelection(mailbox.id, event.target.checked)}
                    />
                  </td>
                  <td className="mailbox-email-cell cell-start">
                    <strong>{mailbox.primary_email}</strong>
                    <div className="muted-copy">{mailbox.id}</div>
                  </td>
                  <td className="cell-center"><MailboxStatusBadge status={mailbox.status} /></td>
                  <td className="scope-cell cell-start">
                    <MailboxScopeSummary scope={mailbox.scope} />
                  </td>
                  <td className="cell-center">
                    <MailboxCapabilityBadge
                      capability={mailbox.capability}
                      probeError={mailbox.capability_probe_error}
                    />
                  </td>
                  <td className="mailbox-token-version-cell cell-center">{mailbox.token_version}</td>
                  <td className="mailbox-datetime-cell cell-center">
                    {mailbox.has_access_token ? formatTime(mailbox.access_token_expires_at) : "未缓存"}
                  </td>
                  <td className="mailbox-datetime-cell cell-center">{formatTime(mailbox.refresh_token_expires_at)}</td>
                  <td className="mailbox-proxy-cell cell-start">
                    {mailbox.egress_proxy_name ?? "直连 / 未绑定"}
                    <div className="muted-copy">{formatTime(mailbox.proxy_last_switch_at)}</div>
                  </td>
                  <td className="mailbox-lease-cell cell-center">{mailbox.active_lease_count}</td>
                  <td className="mailbox-datetime-cell cell-center">{formatTime(mailbox.updated_at)}</td>
                  <td className="cell-center">
                    <div className="cell-actions">
                      <button
                        className="button"
                        type="button"
                        title="查看该主邮箱相关的站点占用（含 plus 别名需另行筛选）"
                        onClick={() => onOpenSiteUsages(mailbox.primary_email)}
                      >
                        <ListFilter size={14} /> 站点占用
                      </button>
                    </div>
                  </td>
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
          <table className="lease-table">
            <thead><tr><th>邮箱</th><th>模式</th><th>状态</th><th>调用方</th><th>用途</th><th>到期时间</th><th>创建时间</th></tr></thead>
            <tbody>
              {leases.map((lease) => (
                <tr key={lease.id}>
                  <td className="cell-center"><strong>{lease.primary_email}</strong><div className="muted-copy">{lease.id}</div></td>
                  <td className="cell-center">{lease.mode}</td>
                  <td className="cell-center"><LeaseStatusBadge status={lease.status} /></td>
                  <td className="cell-start">{lease.client_tag ?? lease.client_key_id ?? "-"}</td>
                  <td className="cell-center">{lease.purpose ?? "-"}</td>
                  <td className="cell-center">{formatTime(lease.expires_at)}</td>
                  <td className="cell-center">{formatTime(lease.created_at)}</td>
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


function UsageSitesPage({
  sites,
  isCreateDialogOpen,
  isSaving,
  deletingCode,
  onOpenCreateDialog,
  onCloseCreateDialog,
  onCreate,
  onToggleEnabled,
  onDelete,
  onRefresh,
}: {
  sites: UsageSiteItem[];
  isCreateDialogOpen: boolean;
  isSaving: boolean;
  deletingCode: string | null;
  onOpenCreateDialog: () => void;
  onCloseCreateDialog: () => void;
  onCreate: (event: FormEvent<HTMLFormElement>) => void;
  onToggleEnabled: (site: UsageSiteItem) => void;
  onDelete: (site: UsageSiteItem) => void;
  onRefresh: () => void;
}): JSX.Element {
  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">注册站点</h1>
          <p className="page-subtitle">配置 mail_read 领取时可选的 usage_site 白名单；禁用后禁止新声明，历史占用仍参与排除。</p>
        </div>
        <div className="cell-actions">
          <button className="button" type="button" onClick={onRefresh}><RefreshCw size={15} /> 刷新</button>
          <button className="button button-primary" type="button" onClick={onOpenCreateDialog}><Plus size={15} /> 新增站点</button>
        </div>
      </header>
      <section className="panel">
        <div className="toolbar">
          <div>
            <h2 className="section-title">站点白名单</h2>
            <span className="muted-copy">共 {sites.length} 个站点</span>
          </div>
        </div>
        <div className="table-wrapper">
          <table className="usage-sites-table">
            <thead>
              <tr>
                <th>code</th>
                <th>展示名</th>
                <th>状态</th>
                <th>未撤销占用</th>
                <th>创建时间</th>
                <th aria-label="操作" />
              </tr>
            </thead>
            <tbody>
              {sites.map((site) => {
                const activeUsageCount = site.active_usage_count ?? 0;
                const canDelete = activeUsageCount === 0;
                return (
                <tr key={site.code}>
                  <td className="cell-center"><strong>{site.code}</strong></td>
                  <td className="cell-center">{site.display_name}</td>
                  <td className="cell-center">
                    <span className={`badge ${site.enabled ? "badge-enabled" : "badge-disabled"}`}>
                      {site.enabled ? "启用中" : "已禁用"}
                    </span>
                  </td>
                  <td className="cell-center">{activeUsageCount}</td>
                  <td className="cell-center">{formatTime(site.created_at)}</td>
                  <td className="cell-center">
                    <div className="cell-actions">
                      <button className="button" type="button" onClick={() => onToggleEnabled(site)}>
                        {site.enabled ? "禁用" : "启用"}
                      </button>
                      <button
                        className="button button-danger"
                        type="button"
                        disabled={!canDelete || deletingCode === site.code}
                        title={canDelete ? "删除站点" : "仍有未撤销占用，无法删除"}
                        onClick={() => onDelete(site)}
                      >
                        <Trash2 size={14} /> {deletingCode === site.code ? "删除中" : "删除"}
                      </button>
                    </div>
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {sites.length === 0 && (
          <div className="empty-state">
            <CircleOff size={16} style={{ verticalAlign: "middle", marginRight: 6 }} />
            暂无站点。请新增 openai / grok 等注册目标站。
          </div>
        )}
      </section>
      {isCreateDialogOpen && (
        <div className="dialog-backdrop" role="presentation">
          <form className="dialog" onSubmit={onCreate}>
            <div className="section-header">
              <div>
                <h2 className="section-title">新增注册站点</h2>
                <p className="page-subtitle">code 创建后不可修改，仅允许小写字母、数字、点、下划线与连字符。</p>
              </div>
            </div>
            <div className="form-grid">
              <label className="form-field">
                code
                <input className="input" name="code" required minLength={2} maxLength={64} placeholder="openai" pattern="[a-z0-9._-]+" />
              </label>
              <label className="form-field">
                展示名
                <input className="input" name="display_name" required maxLength={100} placeholder="OpenAI" />
              </label>
              <label className="checkbox-label" style={{ alignSelf: "end", minHeight: 34 }}>
                <input type="checkbox" name="enabled" defaultChecked /> 创建后立即启用
              </label>
            </div>
            <div className="dialog-actions">
              <button className="button" type="button" onClick={onCloseCreateDialog} disabled={isSaving}>取消</button>
              <button className="button button-primary" type="submit" disabled={isSaving}>
                {isSaving ? "保存中…" : "创建"}
              </button>
            </div>
          </form>
        </div>
      )}
    </>
  );
}

function EmailSiteUsagesPage({
  usages,
  page,
  pageSize,
  total,
  totalPages,
  allocatedEmailFilter,
  usageSiteFilter,
  includeRevoked,
  siteOptions,
  isRevokingId,
  onAllocatedEmailFilterChange,
  onUsageSiteFilterChange,
  onIncludeRevokedChange,
  onSearch,
  onPageChange,
  onRevoke,
}: {
  usages: EmailSiteUsageItem[];
  page: number;
  pageSize: number;
  total: number;
  totalPages: number;
  allocatedEmailFilter: string;
  usageSiteFilter: string;
  includeRevoked: boolean;
  siteOptions: UsageSiteItem[];
  isRevokingId: string | null;
  onAllocatedEmailFilterChange: (value: string) => void;
  onUsageSiteFilterChange: (value: string) => void;
  onIncludeRevokedChange: (value: boolean) => void;
  onSearch: () => void;
  onPageChange: (page: number) => void;
  onRevoke: (usage: EmailSiteUsageItem) => void;
}): JSX.Element {
  const normalizedTotalPages = Math.max(totalPages, 1);
  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">邮箱站点占用</h1>
          <p className="page-subtitle">查看某业务地址已在哪些站登记；撤销后同一地址可再次用于该站。</p>
        </div>
      </header>
      <section className="panel">
        <div className="toolbar" style={{ flexWrap: "wrap", gap: 12 }}>
          <div>
            <h2 className="section-title">占用记录</h2>
            <span className="muted-copy">共 {total} 条，每页 {pageSize} 条</span>
          </div>
          <div className="cell-actions" style={{ flexWrap: "wrap" }}>
            <input
              className="input"
              style={{ minWidth: 220 }}
              value={allocatedEmailFilter}
              onChange={(event) => onAllocatedEmailFilterChange(event.target.value)}
              placeholder="业务邮箱（完整地址）"
            />
            <select
              className="select"
              style={{ minWidth: 140 }}
              value={usageSiteFilter}
              onChange={(event) => onUsageSiteFilterChange(event.target.value)}
            >
              <option value="">全部站点</option>
              {siteOptions.map((site) => (
                <option key={site.code} value={site.code}>{site.code}</option>
              ))}
            </select>
            <label className="checkbox-label" style={{ minHeight: 34 }}>
              <input
                type="checkbox"
                checked={includeRevoked}
                onChange={(event) => onIncludeRevokedChange(event.target.checked)}
              />
              含已撤销
            </label>
            <button className="button button-primary" type="button" onClick={onSearch}>
              <ListFilter size={15} /> 查询
            </button>
          </div>
        </div>
        <div className="table-wrapper">
          <table className="email-site-usages-table">
            <thead>
              <tr>
                <th>业务地址</th>
                <th>站点</th>
                <th>状态</th>
                <th>Client Key</th>
                <th>登记时间</th>
                <th>更新时间</th>
                <th aria-label="操作" />
              </tr>
            </thead>
            <tbody>
              {usages.map((usage) => {
                const isActive = usage.revoked_at === null;
                return (
                  <tr key={usage.id}>
                    <td className="cell-center">
                      <strong>{usage.allocated_email}</strong>
                      <div className="muted-copy">{usage.id}</div>
                    </td>
                    <td className="cell-center">{usage.usage_site}</td>
                    <td className="cell-center">
                      <span className={`badge ${isActive ? "badge-enabled" : "badge-disabled"}`}>
                        {isActive ? "占用中" : "已撤销"}
                      </span>
                    </td>
                    <td className="cell-center">{usage.client_key_id ?? "-"}</td>
                    <td className="cell-center">{formatTime(usage.created_at)}</td>
                    <td className="cell-center">{formatTime(usage.updated_at)}</td>
                    <td className="cell-center">
                      {isActive ? (
                        <button
                          className="button"
                          type="button"
                          disabled={isRevokingId === usage.id}
                          onClick={() => onRevoke(usage)}
                        >
                          {isRevokingId === usage.id ? "撤销中…" : "撤销占用"}
                        </button>
                      ) : (
                        <span className="muted-copy">撤销于 {formatTime(usage.revoked_at)}</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {usages.length === 0 && (
          <div className="empty-state">
            <CircleOff size={16} style={{ verticalAlign: "middle", marginRight: 6 }} />
            暂无匹配的占用记录。
          </div>
        )}
        <div className="pagination-actions" aria-label="占用分页" style={{ marginTop: 16 }}>
          <button className="button" type="button" onClick={() => onPageChange(page - 1)} disabled={page <= 1}>上一页</button>
          <span className="muted-copy">第 {page} / {normalizedTotalPages} 页</span>
          <button className="button" type="button" onClick={() => onPageChange(page + 1)} disabled={page >= normalizedTotalPages}>下一页</button>
        </div>
      </section>
    </>
  );
}

function SummaryRow({ label, value }: { label: string; value: number }): JSX.Element {
  return <div className="summary-row"><span>{label}</span><strong>{value}</strong></div>;
}


function providerStatusBadge(item: ProviderCatalogItem): { className: string; label: string } {
  if (!item.configurable_in_ui) {
    return { className: "badge badge-unknown", label: "导入维护" };
  }
  if (!item.enabled) {
    return { className: "badge badge-disabled", label: "未启用" };
  }
  if (item.has_api_key) {
    return { className: "badge badge-enabled", label: "已启用 · 密钥已配置" };
  }
  return { className: "badge badge-cooldown", label: "已启用 · 缺密钥" };
}

function supplyModeLabel(supplyMode: string): string {
  if (supplyMode === "inventory_import") {
    return "库存导入";
  }
  if (supplyMode === "inventory_replenish") {
    return "库存补货";
  }
  if (supplyMode === "on_demand") {
    return "即时开箱";
  }
  return supplyMode;
}

function OperatorConsolePage({
  catalog,
  adminToken,
  onError,
  onNotice,
}: {
  catalog: ProviderCatalogItem[];
  adminToken: string;
  onError: (message: string) => void;
  onNotice: (message: string) => void;
}): JSX.Element {
  const onDemandProviders = useMemo(
    () => catalog.filter((item) => item.supply_mode === "on_demand" && item.enabled),
    [catalog],
  );
  const [providerType, setProviderType] = useState("");
  const [localPart, setLocalPart] = useState("");
  const [label, setLabel] = useState("");
  const [sessions, setSessions] = useState<OperatorSession[]>([]);
  const [currentSession, setCurrentSession] = useState<OperatorSession | null>(null);
  const [messages, setMessages] = useState<OperatorMessageItem[]>([]);
  const [codes, setCodes] = useState<string[]>([]);
  const [selectedMessageId, setSelectedMessageId] = useState<number | null>(null);
  const [isBusy, setIsBusy] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(false);

  useEffect(() => {
    if (!providerType && onDemandProviders.length > 0) {
      setProviderType(onDemandProviders[0].provider_type);
    }
  }, [onDemandProviders, providerType]);

  async function refreshSessions(): Promise<void> {
    try {
      const response = await requestApi<{ items: OperatorSession[] }>(
        adminToken,
        "/api/v1/admin/operator/sessions",
      );
      setSessions(response.items);
    } catch (error) {
      onError(error instanceof Error ? error.message : "无法加载联调会话。");
    }
  }

  useEffect(() => {
    void refreshSessions();
  }, [adminToken]);

  async function createSession(): Promise<void> {
    if (!providerType) {
      onError("请选择已启用的 on-demand Provider。");
      return;
    }
    setIsBusy(true);
    try {
      const created = await requestApi<OperatorSession>(adminToken, "/api/v1/admin/operator/sessions", {
        method: "POST",
        body: JSON.stringify({
          provider_type: providerType,
          local_part: localPart.trim() || null,
          label: label.trim() || null,
        }),
      });
      setCurrentSession(created);
      setMessages([]);
      setCodes([]);
      setSelectedMessageId(null);
      onNotice(`已创建联调邮箱：${created.address}`);
      await refreshSessions();
      await refreshMessages(created.lease_id);
    } catch (error) {
      onError(error instanceof Error ? error.message : "创建联调会话失败。");
    } finally {
      setIsBusy(false);
    }
  }

  async function refreshMessages(leaseId?: string): Promise<void> {
    const targetLeaseId = leaseId || currentSession?.lease_id;
    if (!targetLeaseId) {
      return;
    }
    setIsBusy(true);
    try {
      const response = await requestApi<{
        session: OperatorSession;
        total: number;
        codes: string[];
        messages: OperatorMessageItem[];
      }>(adminToken, `/api/v1/admin/operator/sessions/${targetLeaseId}/messages`);
      setCurrentSession(response.session);
      setMessages(response.messages);
      setCodes(response.codes);
      if (response.messages.length > 0 && selectedMessageId == null) {
        setSelectedMessageId(0);
      }
    } catch (error) {
      onError(error instanceof Error ? error.message : "刷新收件失败。");
    } finally {
      setIsBusy(false);
    }
  }

  async function releaseSession(leaseId: string): Promise<void> {
    setIsBusy(true);
    try {
      await requestApi<OperatorSession>(adminToken, `/api/v1/admin/operator/sessions/${leaseId}`, {
        method: "DELETE",
      });
      if (currentSession?.lease_id === leaseId) {
        setCurrentSession(null);
        setMessages([]);
        setCodes([]);
        setSelectedMessageId(null);
      }
      onNotice("联调会话已释放。");
      await refreshSessions();
    } catch (error) {
      onError(error instanceof Error ? error.message : "释放会话失败。");
    } finally {
      setIsBusy(false);
    }
  }

  useEffect(() => {
    if (!autoRefresh || !currentSession?.lease_id) {
      return;
    }
    const timer = window.setInterval(() => {
      void refreshMessages(currentSession.lease_id);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [autoRefresh, currentSession?.lease_id]);

  async function copyText(text: string, successMessage: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      onNotice(successMessage);
    } catch {
      onError("复制失败，请手动选择文本。");
    }
  }

  const selectedMessage =
    selectedMessageId != null && selectedMessageId >= 0 && selectedMessageId < messages.length
      ? messages[selectedMessageId]
      : null;
  const latestCode = currentSession?.last_verification_code || codes[0] || "";

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">联调工作台</h1>
          <p className="page-subtitle">
            选择已启用的 on-demand Provider，即时开箱、刷新收件并提取验证码。不写入邮箱库存表。
          </p>
        </div>
        <div className="page-header-actions">
          <label className="muted-copy" style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(event) => setAutoRefresh(event.target.checked)}
            />
            5s 自动刷新
          </label>
          <button className="button" type="button" onClick={() => void refreshSessions()} disabled={isBusy}>
            刷新会话列表
          </button>
        </div>
      </header>

      <section className="two-column-grid">
        <div className="panel">
          <div className="section-header">
            <h2 className="section-title">创建临时邮箱</h2>
          </div>
          <div className="form-grid">
            <label className="form-field">
              Provider
              <select
                className="select"
                value={providerType}
                onChange={(event) => setProviderType(event.target.value)}
              >
                {onDemandProviders.length === 0 && <option value="">无已启用 on-demand</option>}
                {onDemandProviders.map((item) => (
                  <option key={item.provider_type} value={item.provider_type}>
                    {item.display_name} ({item.provider_type})
                  </option>
                ))}
              </select>
            </label>
            <label className="form-field">
              自定义前缀（可空）
              <input className="input" value={localPart} onChange={(event) => setLocalPart(event.target.value)} placeholder="例如 debug01" />
            </label>
            <label className="form-field">
              备注（可空）
              <input className="input" value={label} onChange={(event) => setLabel(event.target.value)} placeholder="手动联调" />
            </label>
          </div>
          <div className="page-header-actions" style={{ marginTop: 12 }}>
            <button className="button button-primary" type="button" onClick={() => void createSession()} disabled={isBusy || !providerType}>
              创建临时邮箱
            </button>
            <button
              className="button"
              type="button"
              onClick={() => currentSession && void copyText(currentSession.address, "邮箱地址已复制。")}
              disabled={!currentSession}
            >
              复制当前邮箱
            </button>
            <button
              className="button"
              type="button"
              onClick={() => latestCode && void copyText(latestCode, "验证码已复制。")}
              disabled={!latestCode}
            >
              复制验证码
            </button>
            <button
              className="button"
              type="button"
              onClick={() => void refreshMessages()}
              disabled={!currentSession || isBusy}
            >
              刷新收件
            </button>
            <button
              className="button button-danger"
              type="button"
              onClick={() => currentSession && void releaseSession(currentSession.lease_id)}
              disabled={!currentSession || isBusy}
            >
              释放当前
            </button>
          </div>
          <div className="muted-copy" style={{ marginTop: 12 }}>
            当前邮箱：<strong>{currentSession?.address ?? "未选择"}</strong>
            <br />
            Provider：{currentSession?.provider_type ?? "—"}
            <br />
            最近验证码：<strong>{latestCode || "—"}</strong>
          </div>
          <div style={{ marginTop: 16 }}>
            <h3 className="section-title">活跃会话</h3>
            <div className="table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>地址</th>
                    <th>Provider</th>
                    <th>最近验证码</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((session) => (
                    <tr key={session.lease_id}>
                      <td className="cell-start">
                        <button
                          className="button button-ghost"
                          type="button"
                          onClick={() => {
                            setCurrentSession(session);
                            void refreshMessages(session.lease_id);
                          }}
                        >
                          {session.address}
                        </button>
                      </td>
                      <td className="cell-center">{session.provider_type}</td>
                      <td className="cell-center">{session.last_verification_code || "—"}</td>
                      <td className="cell-center">
                        <button className="button" type="button" onClick={() => void releaseSession(session.lease_id)}>
                          释放
                        </button>
                      </td>
                    </tr>
                  ))}
                  {sessions.length === 0 && (
                    <tr>
                      <td colSpan={4}>
                        <div className="empty-state">暂无活跃联调会话。</div>
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        <div className="panel">
          <div className="section-header">
            <h2 className="section-title">收件 / 验证码</h2>
            <span className="muted-copy">共 {messages.length} 封</span>
          </div>
          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>发件人</th>
                  <th>主题</th>
                  <th>验证码</th>
                </tr>
              </thead>
              <tbody>
                {messages.map((message, index) => (
                  <tr
                    key={`${message.subject ?? "msg"}-${index}`}
                    className={selectedMessageId === index ? "provider-row-selected" : undefined}
                    style={{ cursor: "pointer" }}
                    onClick={() => setSelectedMessageId(index)}
                  >
                    <td className="cell-start">{message.from_address || "—"}</td>
                    <td className="cell-start">{message.subject || "(no subject)"}</td>
                    <td className="cell-center">{message.code || "—"}</td>
                  </tr>
                ))}
                {messages.length === 0 && (
                  <tr>
                    <td colSpan={3}>
                      <div className="empty-state">暂无邮件，创建会话后点击刷新收件。</div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
          <div style={{ marginTop: 12 }}>
            <label className="form-field">
              邮件正文
              <textarea
                className="textarea"
                readOnly
                rows={12}
                value={
                  selectedMessage
                    ? `${selectedMessage.subject || ""}\nFrom: ${selectedMessage.from_address || ""}\nCode: ${selectedMessage.code || "—"}\n\n${selectedMessage.text || selectedMessage.intro || ""}`
                    : "选择一封邮件查看内容 / 验证码"
                }
              />
            </label>
          </div>
        </div>
      </section>
    </>
  );
}

function ProvidersPage({
  catalog,
  smsbower,
  apiKeyDraft,
  isSaving,
  isReplenishing,
  adminToken,
  onApiKeyDraftChange,
  onRefresh,
  onToggleEnabled,
  onSaveBasics,
  onSaveApiKey,
  onClearApiKey,
  onReplenish,
  onError,
  onNotice,
}: {
  catalog: ProviderCatalogItem[];
  smsbower: SmsbowerSettings | null;
  apiKeyDraft: string;
  isSaving: boolean;
  isReplenishing: boolean;
  adminToken: string;
  onApiKeyDraftChange: (value: string) => void;
  onRefresh: () => void;
  onToggleEnabled: (enabled: boolean) => void;
  onSaveBasics: (fields: {
    api_base?: string;
    service?: string;
    domain?: string;
    max_price?: number | null;
    clear_max_price?: boolean;
    request_timeout_seconds?: number;
  }) => void;
  onSaveApiKey: () => void;
  onClearApiKey: () => void;
  onReplenish: () => void;
  onError: (message: string) => void;
  onNotice: (message: string) => void;
}): JSX.Element {
  const [apiBaseDraft, setApiBaseDraft] = useState(smsbower?.api_base ?? "");
  const [serviceDraft, setServiceDraft] = useState(smsbower?.service ?? "openai");
  const [domainDraft, setDomainDraft] = useState(smsbower?.domain ?? "gmail.com");
  const [maxPriceDraft, setMaxPriceDraft] = useState(
    smsbower?.max_price != null ? String(smsbower.max_price) : "",
  );
  const [timeoutDraft, setTimeoutDraft] = useState(
    String(smsbower?.request_timeout_seconds ?? 30),
  );
  const [selectedProviderType, setSelectedProviderType] = useState<string>("smsbower_gmail");
  const [instanceSettings, setInstanceSettings] = useState<ProviderInstanceSettings | null>(null);
  const [valueDrafts, setValueDrafts] = useState<Record<string, string>>({});
  const [secretDrafts, setSecretDrafts] = useState<Record<string, string>>({});
  const [isSavingGeneric, setIsSavingGeneric] = useState(false);
  const [isLoadingInstance, setIsLoadingInstance] = useState(false);
  const [enabledDraft, setEnabledDraft] = useState(false);
  const [healthItems, setHealthItems] = useState<ProviderHealthItem[]>([]);
  const [isCheckingHealth, setIsCheckingHealth] = useState(false);
  const [domainsPreview, setDomainsPreview] = useState<string[]>([]);

  const configurableProviders = useMemo(
    () => catalog.filter((item) => item.configurable_in_ui),
    [catalog],
  );
  const selectedCatalogItem = catalog.find((item) => item.provider_type === selectedProviderType) ?? null;
  const isSmsbowerSelected = selectedProviderType === "smsbower_gmail";

  const enabledCount = catalog.filter((item) => item.enabled).length;
  const missingKeyCount = catalog.filter(
    (item) => item.configurable_in_ui && item.enabled && !item.has_api_key,
  ).length;
  const onDemandCount = catalog.filter((item) => item.supply_mode === "on_demand").length;

  async function checkAllProviderHealth(): Promise<void> {
    setIsCheckingHealth(true);
    try {
      const response = await requestApi<{ items: ProviderHealthItem[] }>(
        adminToken,
        "/api/v1/admin/providers/health?check=true",
      );
      setHealthItems(response.items);
      onNotice("Provider 健康检查完成。");
    } catch (error) {
      onError(error instanceof Error ? error.message : "健康检查失败。");
    } finally {
      setIsCheckingHealth(false);
    }
  }

  async function probeSelectedDomains(): Promise<void> {
    if (!selectedProviderType) {
      return;
    }
    const catalogItem = catalog.find((item) => item.provider_type === selectedProviderType);
    const instanceId = catalogItem?.instance_id || "default";
    try {
      const response = await requestApi<{ domains: string[] }>(
        adminToken,
        `/api/v1/admin/providers/${selectedProviderType}/instances/${instanceId}/domains`,
      );
      setDomainsPreview(response.domains);
      onNotice(`已获取 ${response.domains.length} 个域名。`);
    } catch (error) {
      setDomainsPreview([]);
      onError(error instanceof Error ? error.message : "域名探测失败。");
    }
  }

  useEffect(() => {
    if (!smsbower) {
      return;
    }
    setApiBaseDraft(smsbower.api_base);
    setServiceDraft(smsbower.service);
    setDomainDraft(smsbower.domain);
    setMaxPriceDraft(smsbower.max_price != null ? String(smsbower.max_price) : "");
    setTimeoutDraft(String(smsbower.request_timeout_seconds));
  }, [smsbower]);

  useEffect(() => {
    if (selectedProviderType) {
      return;
    }
    if (configurableProviders.length > 0) {
      setSelectedProviderType(configurableProviders[0].provider_type);
    }
  }, [configurableProviders, selectedProviderType]);

  useEffect(() => {
    if (!selectedProviderType || !adminToken || isSmsbowerSelected) {
      setInstanceSettings(null);
      return;
    }
    const catalogItem = catalog.find((item) => item.provider_type === selectedProviderType);
    const instanceId = catalogItem?.instance_id || "default";
    let cancelled = false;
    setIsLoadingInstance(true);
    void (async () => {
      try {
        const view = await requestApi<ProviderInstanceSettings>(
          adminToken,
          `/api/v1/admin/providers/${selectedProviderType}/instances/${instanceId}`,
        );
        if (cancelled) {
          return;
        }
        setInstanceSettings(view);
        setEnabledDraft(view.enabled);
        const nextValues: Record<string, string> = {};
        for (const [key, value] of Object.entries(view.values || {})) {
          if (Array.isArray(value)) {
            nextValues[key] = value.join("\n");
          } else if (value == null) {
            nextValues[key] = "";
          } else if (typeof value === "boolean") {
            nextValues[key] = value ? "true" : "false";
          } else {
            nextValues[key] = String(value);
          }
        }
        setValueDrafts(nextValues);
        setSecretDrafts({});
      } catch (error) {
        if (!cancelled) {
          onError(error instanceof Error ? error.message : "无法加载 Provider 实例配置。");
        }
      } finally {
        if (!cancelled) {
          setIsLoadingInstance(false);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [adminToken, catalog, isSmsbowerSelected, onError, selectedProviderType]);

  async function saveGenericProvider(): Promise<void> {
    if (!selectedProviderType || !instanceSettings || isSmsbowerSelected) {
      return;
    }
    const fields =
      instanceSettings.fields ||
      catalog.find((item) => item.provider_type === selectedProviderType)?.fields ||
      [];
    const values: Record<string, unknown> = {};
    const secrets: Record<string, string> = {};
    for (const field of fields) {
      if (field.secret) {
        const draft = (secretDrafts[field.key] || "").trim();
        if (draft) {
          secrets[field.key] = draft;
        }
        continue;
      }
      if (!(field.key in valueDrafts)) {
        continue;
      }
      const raw = valueDrafts[field.key];
      if (field.field_type === "string_list") {
        values[field.key] = raw
          .split(/[\n,]/)
          .map((part) => part.trim())
          .filter(Boolean);
      } else if (field.field_type === "boolean") {
        values[field.key] = raw === "true" || raw === "1" || raw === "on";
      } else if (field.field_type === "number") {
        values[field.key] = raw.trim() === "" ? null : Number(raw);
      } else {
        values[field.key] = raw;
      }
    }
    try {
      setIsSavingGeneric(true);
      const updated = await requestApi<ProviderInstanceSettings>(
        adminToken,
        `/api/v1/admin/providers/${selectedProviderType}/instances/${instanceSettings.instance_id}`,
        {
          method: "PUT",
          body: JSON.stringify({
            enabled: enabledDraft,
            values,
            secrets: Object.keys(secrets).length > 0 ? secrets : undefined,
          }),
        },
      );
      setInstanceSettings(updated);
      setSecretDrafts({});
      onNotice(`${selectedCatalogItem?.display_name ?? selectedProviderType} 配置已保存。`);
      onRefresh();
    } catch (error) {
      onError(error instanceof Error ? error.message : "保存 Provider 配置失败。");
    } finally {
      setIsSavingGeneric(false);
    }
  }

  function renderGenericField(field: ProviderFieldSchema): JSX.Element {
    if (field.secret) {
      const hasSecret = Boolean(instanceSettings?.secret_flags?.[field.key]);
      return (
        <label key={field.key} className="form-field">
          <span>
            {field.label}
            {field.required ? " *" : ""}
            <span className="muted-copy"> · {hasSecret ? "已配置，填写则覆盖" : "未配置"}</span>
          </span>
          <input
            className="input"
            type="password"
            autoComplete="off"
            placeholder={hasSecret ? "••••••••" : field.placeholder || ""}
            value={secretDrafts[field.key] || ""}
            onChange={(event) =>
              setSecretDrafts((previous) => ({
                ...previous,
                [field.key]: event.target.value,
              }))
            }
          />
        </label>
      );
    }
    if (field.field_type === "string_list" || field.field_type === "textarea") {
      return (
        <label key={field.key} className="form-field full-width">
          <span>
            {field.label}
            {field.required ? " *" : ""}
          </span>
          <textarea
            className="textarea"
            rows={3}
            value={valueDrafts[field.key] || ""}
            placeholder={field.description || field.placeholder || "每行一个，也可用逗号分隔"}
            onChange={(event) =>
              setValueDrafts((previous) => ({
                ...previous,
                [field.key]: event.target.value,
              }))
            }
          />
        </label>
      );
    }
    if (field.field_type === "boolean") {
      const checked = (valueDrafts[field.key] || String(field.default ?? false)) === "true";
      return (
        <label key={field.key} className="form-field checkbox-label">
          <input
            type="checkbox"
            checked={checked}
            onChange={(event) =>
              setValueDrafts((previous) => ({
                ...previous,
                [field.key]: event.target.checked ? "true" : "false",
              }))
            }
          />
          {field.label}
        </label>
      );
    }
    return (
      <label key={field.key} className="form-field">
        <span>
          {field.label}
          {field.required ? " *" : ""}
        </span>
        <input
          className="input"
          type={field.field_type === "number" ? "number" : "text"}
          value={valueDrafts[field.key] ?? ""}
          placeholder={field.placeholder || ""}
          onChange={(event) =>
            setValueDrafts((previous) => ({
              ...previous,
              [field.key]: event.target.value,
            }))
          }
        />
      </label>
    );
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">邮箱 Provider</h1>
          <p className="page-subtitle">
            维护邮箱来源启停与实例参数。Microsoft 通过邮箱导入；其余类型在此配置密钥后，外部调用需显式传 provider 与对应 scope。
          </p>
        </div>
        <div className="page-header-actions">
          <button className="button" type="button" onClick={() => void checkAllProviderHealth()} disabled={isCheckingHealth}>
            <RefreshCw size={14} /> {isCheckingHealth ? "检测中…" : "检测全部服务"}
          </button>
          <button className="button" type="button" onClick={() => void probeSelectedDomains()} disabled={!selectedProviderType}>
            探测当前域名
          </button>
          <button className="button" type="button" onClick={onRefresh}>
            <RefreshCw size={14} /> 刷新
          </button>
        </div>
      </header>

      <section className="metric-grid" aria-label="Provider 指标">
        <MetricCard label="全部类型" value={catalog.length} />
        <MetricCard label="已启用" value={enabledCount} />
        <MetricCard label="缺密钥" value={missingKeyCount} />
        <MetricCard label="即时开箱" value={onDemandCount} />
      </section>

      {healthItems.length > 0 && (
        <section className="panel">
          <div className="section-header">
            <div>
              <h2 className="section-title">服务连接状态</h2>
              <p className="page-subtitle">实时探测结果：ok / degraded / down / skipped。</p>
            </div>
          </div>
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Provider</th>
                  <th>状态</th>
                  <th>延迟</th>
                  <th>域名预览</th>
                  <th>错误</th>
                </tr>
              </thead>
              <tbody>
                {healthItems.map((item) => (
                  <tr key={`${item.provider_type}:${item.provider_instance_id}`}>
                    <td className="cell-center">
                      <strong>{item.display_name || item.provider_type}</strong>
                      <div className="muted-copy">{item.provider_type}</div>
                    </td>
                    <td className="cell-center">
                      <span className={item.status === "ok" ? "badge badge-healthy" : item.status === "down" ? "badge badge-danger" : "badge badge-unknown"}>
                        {item.status}
                      </span>
                    </td>
                    <td className="cell-center">{item.latency_ms != null ? `${item.latency_ms} ms` : "—"}</td>
                    <td className="muted-copy cell-center">{item.domains_preview.slice(0, 3).join(", ") || "—"}</td>
                    <td className="muted-copy cell-start">{item.error_summary || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {domainsPreview.length > 0 && (
            <p className="muted-copy" style={{ marginTop: 12 }}>
              当前 Provider 域名：{domainsPreview.join(", ")}
            </p>
          )}
        </section>
      )}

      <section className="panel">
        <div className="section-header">
          <div>
            <h2 className="section-title">Provider 目录</h2>
            <p className="page-subtitle">点击可配置行进入下方编辑区；Microsoft 仅展示状态，凭证走邮箱导入。</p>
          </div>
        </div>
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>类型</th>
                <th>名称</th>
                <th>供给</th>
                <th>模式</th>
                <th>状态</th>
                <th>说明</th>
              </tr>
            </thead>
            <tbody>
              {catalog.map((item) => {
                const status = providerStatusBadge(item);
                const isSelected = item.provider_type === selectedProviderType;
                const isSelectable = item.configurable_in_ui;
                return (
                  <tr
                    key={item.provider_type}
                    className={isSelected ? "provider-row-selected" : undefined}
                    onClick={() => {
                      if (isSelectable) {
                        setSelectedProviderType(item.provider_type);
                      }
                    }}
                    style={isSelectable ? { cursor: "pointer" } : undefined}
                  >
                    <td className="cell-center">
                      <code className="provider-type-code">{item.provider_type}</code>
                    </td>
                    <td className="cell-center">
                      <strong>{item.display_name}</strong>
                    </td>
                    <td className="cell-center">
                      <span className="badge badge-unknown">{supplyModeLabel(item.supply_mode)}</span>
                    </td>
                    <td className="cell-center">
                      <span className="muted-copy">{item.supported_modes.join(" · ")}</span>
                    </td>
                    <td className="cell-center">
                      <span className={status.className}>{status.label}</span>
                    </td>
                    <td className="cell-start">
                      <span className="muted-copy">{item.notes ?? "—"}</span>
                    </td>
                  </tr>
                );
              })}
              {catalog.length === 0 && (
                <tr>
                  <td colSpan={6}>
                    <div className="empty-state">暂无 Provider 数据，请点击右上角刷新。</div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <section className="panel">
        <div className="section-header">
          <div>
            <h2 className="section-title">实例配置</h2>
            <p className="page-subtitle">
              密钥加密保存，页面只显示是否已配置，不回显明文。外部领取需 Client Key 具备{" "}
              <code>providers:&#123;type&#125;:acquire</code>。
            </p>
          </div>
        </div>

        <div className="form-grid">
          <label className="form-field">
            选择 Provider
            <select
              className="select"
              value={selectedProviderType}
              onChange={(event) => setSelectedProviderType(event.target.value)}
            >
              {configurableProviders.map((item) => (
                <option key={item.provider_type} value={item.provider_type}>
                  {item.display_name} ({item.provider_type})
                </option>
              ))}
            </select>
          </label>
          <div className="form-field">
            <span>当前实例</span>
            <div className="provider-instance-meta">
              <code>{selectedCatalogItem?.instance_id || (isSmsbowerSelected ? smsbower?.instance_id : "default") || "default"}</code>
              <span className="muted-copy">
                {isSmsbowerSelected
                  ? smsbower
                    ? `来源：${smsbower.source === "database" ? "数据库" : "环境变量"}`
                    : "加载中…"
                  : instanceSettings
                    ? `来源：${instanceSettings.source === "database" ? "数据库" : "默认"}`
                    : isLoadingInstance
                      ? "加载中…"
                      : "—"}
              </span>
            </div>
          </div>
        </div>

        {isSmsbowerSelected ? (
          !smsbower ? (
            <div className="empty-state">正在加载 SMSBower 配置…</div>
          ) : (
            <>
              <div className="form-grid">
                <label className="form-field checkbox-label">
                  <input
                    type="checkbox"
                    checked={smsbower.enabled}
                    disabled={isSaving}
                    onChange={(event) => onToggleEnabled(event.target.checked)}
                  />
                  启用 SMSBower（补货与显式领取）
                </label>
                <label className="form-field">
                  Instance ID
                  <input className="input" value={smsbower.instance_id} readOnly />
                </label>
                <label className="form-field">
                  API Base
                  <input
                    className="input"
                    value={apiBaseDraft}
                    onChange={(event) => setApiBaseDraft(event.target.value)}
                    onBlur={() => {
                      if (apiBaseDraft.trim() && apiBaseDraft.trim() !== smsbower.api_base) {
                        onSaveBasics({ api_base: apiBaseDraft.trim() });
                      }
                    }}
                  />
                </label>
                <label className="form-field">
                  Service（如 openai）
                  <input
                    className="input"
                    value={serviceDraft}
                    onChange={(event) => setServiceDraft(event.target.value)}
                    onBlur={() => {
                      if (serviceDraft.trim() && serviceDraft.trim() !== smsbower.service) {
                        onSaveBasics({ service: serviceDraft.trim() });
                      }
                    }}
                  />
                </label>
                <label className="form-field">
                  Domain
                  <input
                    className="input"
                    value={domainDraft}
                    onChange={(event) => setDomainDraft(event.target.value)}
                    onBlur={() => {
                      if (domainDraft.trim() && domainDraft.trim() !== smsbower.domain) {
                        onSaveBasics({ domain: domainDraft.trim() });
                      }
                    }}
                  />
                </label>
                <label className="form-field">
                  最高价格（空=不限）
                  <input
                    className="input"
                    value={maxPriceDraft}
                    onChange={(event) => setMaxPriceDraft(event.target.value)}
                    onBlur={() => {
                      const raw = maxPriceDraft.trim();
                      if (!raw) {
                        if (smsbower.max_price != null) {
                          onSaveBasics({ clear_max_price: true });
                        }
                        return;
                      }
                      const parsed = Number(raw);
                      if (!Number.isFinite(parsed)) {
                        return;
                      }
                      if (parsed !== smsbower.max_price) {
                        onSaveBasics({ max_price: parsed });
                      }
                    }}
                  />
                </label>
                <label className="form-field">
                  请求超时（秒）
                  <input
                    className="input"
                    type="number"
                    min={1}
                    max={120}
                    value={timeoutDraft}
                    onChange={(event) => setTimeoutDraft(event.target.value)}
                    onBlur={() => {
                      const parsed = Number(timeoutDraft);
                      if (!Number.isFinite(parsed) || parsed <= 0) {
                        return;
                      }
                      if (parsed !== smsbower.request_timeout_seconds) {
                        onSaveBasics({ request_timeout_seconds: parsed });
                      }
                    }}
                  />
                </label>
                <label className="form-field">
                  <span>
                    API Key
                    <span className="muted-copy">
                      {" "}
                      · {smsbower.has_api_key ? "已配置，填写则覆盖" : "未配置"}
                    </span>
                  </span>
                  <input
                    className="input"
                    type="password"
                    autoComplete="off"
                    placeholder={smsbower.has_api_key ? "••••••••（留空表示不修改）" : "粘贴 SMSBower API Key"}
                    value={apiKeyDraft}
                    onChange={(event) => onApiKeyDraftChange(event.target.value)}
                  />
                </label>
              </div>
              <div className="dialog-actions provider-config-actions">
                <button className="button" type="button" disabled={isSaving} onClick={onSaveApiKey}>
                  保存 API Key
                </button>
                <button
                  className="button"
                  type="button"
                  disabled={isSaving || !smsbower.has_api_key}
                  onClick={onClearApiKey}
                >
                  清除密钥
                </button>
                <button
                  className="button button-primary"
                  type="button"
                  disabled={isReplenishing || !smsbower.enabled || !smsbower.has_api_key}
                  onClick={onReplenish}
                >
                  <Plus size={14} /> {isReplenishing ? "补货中…" : "立即补货 1 个"}
                </button>
              </div>
              <div className="import-format-help">
                <strong>调用说明</strong>
                <span>
                  Client Key 需同时具备 <code>mailboxes:acquire</code> 与{" "}
                  <code>providers:smsbower_gmail:acquire</code>，并在 acquire 时传{" "}
                  <code>provider=smsbower_gmail</code>。
                </span>
              </div>
            </>
          )
        ) : isLoadingInstance ? (
          <div className="empty-state">正在加载实例配置…</div>
        ) : !instanceSettings ? (
          <div className="empty-state">请选择可配置的 Provider。</div>
        ) : (
          <>
            <div className="form-grid">
              <label className="form-field checkbox-label">
                <input
                  type="checkbox"
                  checked={enabledDraft}
                  disabled={isSavingGeneric}
                  onChange={(event) => setEnabledDraft(event.target.checked)}
                />
                启用该 Provider
              </label>
              {(instanceSettings.fields || []).map((field) => renderGenericField(field))}
            </div>
            <div className="dialog-actions provider-config-actions">
              <button
                className="button button-primary"
                type="button"
                disabled={isSavingGeneric}
                onClick={() => void saveGenericProvider()}
              >
                {isSavingGeneric ? "保存中…" : "保存配置"}
              </button>
            </div>
            {selectedCatalogItem?.notes ? (
              <div className="import-format-help">
                <strong>说明</strong>
                <span>{selectedCatalogItem.notes}</span>
              </div>
            ) : null}
          </>
        )}
      </section>
    </>
  );
}

function ClientKeysPage({
  clientKeys,
  createdApiKey,
  filterText,
  isCreating,
  isCreateDialogOpen,
  isUpdating,
  editingClientKey,
  onCloseCreateDialog,
  onCloseEditDialog,
  onCopyApiKey,
  onCreate,
  onUpdate,
  onDisable,
  onFilterTextChange,
  onOpenCreateDialog,
  onOpenEditDialog,
  onDismissCreatedApiKey,
}: {
  clientKeys: ClientKeyListItem[];
  createdApiKey: string | null;
  filterText: string;
  isCreating: boolean;
  isCreateDialogOpen: boolean;
  isUpdating: boolean;
  editingClientKey: ClientKeyListItem | null;
  onCloseCreateDialog: () => void;
  onCloseEditDialog: () => void;
  onCopyApiKey: () => void;
  onCreate: (event: FormEvent<HTMLFormElement>) => void;
  onUpdate: (event: FormEvent<HTMLFormElement>) => void;
  onDisable: (clientKey: ClientKeyListItem) => void;
  onFilterTextChange: (value: string) => void;
  onOpenCreateDialog: () => void;
  onOpenEditDialog: (clientKey: ClientKeyListItem) => void;
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
  const editingScopeSet = useMemo(
    () => new Set(editingClientKey?.scopes ?? []),
    [editingClientKey],
  );

  return (
    <>
      <header className="page-header">
        <div>
          <h1 className="page-title">Client Key 管理</h1>
          <p className="page-subtitle">
            创建外部调用方 API Key。明文只在创建时显示一次；已有 Key 可修改名称与权限，密钥明文不可再次查看。
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
                  <td className="cell-start">
                    <strong>{clientKey.name}</strong>
                    <div className="muted-copy">{clientKey.id}</div>
                  </td>
                  <td className="cell-center">
                    <div className="scope-chip-list">
                      {clientKey.scopes.map((scope) => (
                        <span key={`${clientKey.id}-${scope}`} className="scope-chip" title={scope}>
                          {formatClientKeyScopeLabel(scope)}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="cell-center">
                    <ClientKeyStatusBadge enabled={clientKey.enabled} />
                  </td>
                  <td className="cell-center">{formatTime(clientKey.last_used_at)}</td>
                  <td className="cell-center">{formatTime(clientKey.expires_at)}</td>
                  <td className="cell-center">{formatTime(clientKey.created_at)}</td>
                  <td className="cell-center">
                    <div className="cell-actions">
                      <button
                        className="button"
                        type="button"
                        onClick={() => onOpenEditDialog(clientKey)}
                      >
                        编辑
                      </button>
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
            className="dialog dialog-wide dialog-scrollable"
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
            <div className="dialog-body">
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

      {editingClientKey && (
        <div className="dialog-backdrop" role="presentation">
          <form
            className="dialog dialog-wide dialog-scrollable"
            role="dialog"
            aria-modal="true"
            aria-labelledby="client-key-edit-title"
            key={editingClientKey.id}
            onSubmit={onUpdate}
          >
            <div className="section-header">
              <div>
                <h2 className="section-title" id="client-key-edit-title">
                  编辑 Client Key
                </h2>
                <p className="page-subtitle">
                  可修改显示名称与权限。不会轮换 API Key 明文；已停用的 Key 修改后仍保持停用。
                </p>
              </div>
            </div>
            <div className="dialog-body">
              <div className="form-grid">
                <label className="form-field full-width">
                  名称
                  <input
                    className="input"
                    name="name"
                    required
                    maxLength={100}
                    defaultValue={editingClientKey.name}
                  />
                </label>
                <div className="form-field full-width">
                  <span className="muted-copy">Key ID：{editingClientKey.id}</span>
                </div>
                <fieldset className="form-field full-width scope-fieldset">
                  <legend>权限 scopes</legend>
                  <div className="scope-option-list">
                    {CLIENT_KEY_SCOPE_OPTIONS.map((scopeOption) => (
                      <label key={scopeOption.id} className="checkbox-label scope-option">
                        <input
                          type="checkbox"
                          name="scopes"
                          value={scopeOption.id}
                          defaultChecked={editingScopeSet.has(scopeOption.id)}
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
            </div>
            <div className="dialog-actions">
              <button className="button" type="button" onClick={onCloseEditDialog} disabled={isUpdating}>
                取消
              </button>
              <button className="button button-primary" type="submit" disabled={isUpdating}>
                {isUpdating ? "保存中" : "保存修改"}
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
              输入部署环境中的 Admin Token。Token 仅保存在当前页面内存中，刷新或关闭标签页后需重新输入；不会写入 sessionStorage 或 localStorage。
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
  const [adminToken, setAdminToken] = useState("");
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isRestoringSession, setIsRestoringSession] = useState(false);
  const [isSidebarVisible, setIsSidebarVisible] = useState(true);
  const [activeNavigationSection, setActiveNavigationSection] = useState<NavigationSection>("dashboard");
  const [dashboardSummary, setDashboardSummary] = useState<DashboardSummary | null>(null);
  const [mailboxes, setMailboxes] = useState<MailboxListItem[]>([]);
  const [mailboxPagination, setMailboxPagination] = useState({ total: 0, page: 1, pageSize: 20, totalPages: 1 });
  const [leases, setLeases] = useState<LeaseListItem[]>([]);
  const [leasePagination, setLeasePagination] = useState({ total: 0, page: 1, pageSize: 20, totalPages: 1 });
  const [usageSites, setUsageSites] = useState<UsageSiteItem[]>([]);
  const [isUsageSiteCreateDialogOpen, setIsUsageSiteCreateDialogOpen] = useState(false);
  const [isSavingUsageSite, setIsSavingUsageSite] = useState(false);
  const [deletingUsageSiteCode, setDeletingUsageSiteCode] = useState<string | null>(null);
  const [emailSiteUsages, setEmailSiteUsages] = useState<EmailSiteUsageItem[]>([]);
  const [emailSiteUsagePagination, setEmailSiteUsagePagination] = useState({
    total: 0,
    page: 1,
    pageSize: 20,
    totalPages: 1,
  });
  const [emailSiteUsageEmailFilter, setEmailSiteUsageEmailFilter] = useState("");
  const [emailSiteUsageSiteFilter, setEmailSiteUsageSiteFilter] = useState("");
  const [emailSiteUsageIncludeRevoked, setEmailSiteUsageIncludeRevoked] = useState(true);
  const [isRevokingUsageId, setIsRevokingUsageId] = useState<string | null>(null);
  const [proxies, setProxies] = useState<EgressProxy[]>([]);
  const [policy, setPolicy] = useState<ProxyPolicy | null>(null);
  const [providerCatalog, setProviderCatalog] = useState<ProviderCatalogItem[]>([]);
  const [smsbowerSettings, setSmsbowerSettings] = useState<SmsbowerSettings | null>(null);
  const [smsbowerApiKeyDraft, setSmsbowerApiKeyDraft] = useState("");
  const [isSavingSmsbower, setIsSavingSmsbower] = useState(false);
  const [isReplenishingSmsbower, setIsReplenishingSmsbower] = useState(false);
  const [clientKeys, setClientKeys] = useState<ClientKeyListItem[]>([]);
  const [clientKeyFilterText, setClientKeyFilterText] = useState("");
  const [isClientKeyCreateDialogOpen, setIsClientKeyCreateDialogOpen] = useState(false);
  const [isCreatingClientKey, setIsCreatingClientKey] = useState(false);
  const [editingClientKey, setEditingClientKey] = useState<ClientKeyListItem | null>(null);
  const [isUpdatingClientKey, setIsUpdatingClientKey] = useState(false);
  const [createdClientApiKey, setCreatedClientApiKey] = useState<string | null>(null);
  const [filterText, setFilterText] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isProxyDialogOpen, setIsProxyDialogOpen] = useState(false);
  const [proxyDialogDraft, setProxyDialogDraft] = useState<ProxyDialogDraft | null>(null);
  const [isImportDialogOpen, setIsImportDialogOpen] = useState(false);
  const [isImportingMailboxes, setIsImportingMailboxes] = useState(false);
  const [mailboxImportResult, setMailboxImportResult] = useState<MailboxImportResult | null>(null);
  const [selectedMailboxIds, setSelectedMailboxIds] = useState<Set<string>>(() => new Set());
  const [isRefreshingAccessTokens, setIsRefreshingAccessTokens] = useState(false);
  const [isProbingUnprobedMailboxes, setIsProbingUnprobedMailboxes] = useState(false);
  const [isExportingSelectedMailboxes, setIsExportingSelectedMailboxes] = useState(false);
  const [isDeletingSelectedMailboxes, setIsDeletingSelectedMailboxes] = useState(false);
  const [isDeletingInvalidMailboxes, setIsDeletingInvalidMailboxes] = useState(false);
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


  async function loadProviders(tokenOverride?: string): Promise<boolean> {
    const tokenForRequest = resolveAdminToken(tokenOverride);
    if (!tokenForRequest) {
      setErrorMessage("输入管理员 Token 后才能读取管理台数据。");
      return false;
    }
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [catalog, settings] = await Promise.all([
        requestApi<{ items: ProviderCatalogItem[] }>(tokenForRequest, "/api/v1/admin/providers"),
        requestApi<SmsbowerSettings>(
          tokenForRequest,
          "/api/v1/admin/providers/smsbower_gmail/settings",
        ),
      ]);
      setProviderCatalog(catalog.items);
      setSmsbowerSettings(settings);
      return true;
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法加载 Provider 配置。");
      return false;
    } finally {
      setIsLoading(false);
    }
  }

  async function updateSmsbowerSettings(
    changes: Partial<{
      enabled: boolean;
      api_base: string;
      service: string;
      domain: string;
      max_price: number | null;
      clear_max_price: boolean;
      request_timeout_seconds: number;
      api_key: string;
      clear_api_key: boolean;
    }>,
  ): Promise<void> {
    try {
      setIsSavingSmsbower(true);
      setErrorMessage(null);
      const updated = await requestApi<SmsbowerSettings>(
        adminToken,
        "/api/v1/admin/providers/smsbower_gmail/settings",
        {
          method: "PATCH",
          body: JSON.stringify(changes),
        },
      );
      setSmsbowerSettings(updated);
      if (changes.api_key !== undefined || changes.clear_api_key) {
        setSmsbowerApiKeyDraft("");
      }
      setNotice("SMSBower 配置已更新。");
      void loadProviders();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法更新 SMSBower 配置。");
    } finally {
      setIsSavingSmsbower(false);
    }
  }

  async function replenishSmsbower(): Promise<void> {
    try {
      setIsReplenishingSmsbower(true);
      setErrorMessage(null);
      const result = await requestApi<{
        operation_id: string;
        status: string;
        mailbox_id: string | null;
        primary_email: string | null;
        error_class: string | null;
      }>(adminToken, "/api/v1/admin/providers/smsbower_gmail/replenish", {
        method: "POST",
        body: JSON.stringify({}),
      });
      if (result.status === "succeeded") {
        setNotice(`补货成功：${result.primary_email ?? result.mailbox_id ?? result.operation_id}`);
      } else {
        setErrorMessage(
          `补货未成功：status=${result.status}${result.error_class ? ` (${result.error_class})` : ""}`,
        );
      }
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "补货失败。");
    } finally {
      setIsReplenishingSmsbower(false);
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


  async function loadUsageSites(tokenOverride?: string): Promise<boolean> {
    const tokenForRequest = resolveAdminToken(tokenOverride);
    if (!tokenForRequest) {
      setErrorMessage("输入管理员 Token 后才能读取管理台数据。");
      return false;
    }
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const response = await requestApi<UsageSiteListResponse>(
        tokenForRequest,
        "/api/v1/admin/usage-sites?include_disabled=true",
      );
      setUsageSites(response.items);
      return true;
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法加载注册站点列表。");
      return false;
    } finally {
      setIsLoading(false);
    }
  }

  async function loadEmailSiteUsages(
    requestedPage = emailSiteUsagePagination.page,
    tokenOverride?: string,
    filterOverrides?: {
      allocatedEmail?: string;
      usageSite?: string;
      includeRevoked?: boolean;
    },
  ): Promise<boolean> {
    const tokenForRequest = resolveAdminToken(tokenOverride);
    if (!tokenForRequest) {
      setErrorMessage("输入管理员 Token 后才能读取管理台数据。");
      return false;
    }
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const resolvedEmail = (filterOverrides?.allocatedEmail ?? emailSiteUsageEmailFilter).trim();
      const resolvedSite = (filterOverrides?.usageSite ?? emailSiteUsageSiteFilter).trim();
      const resolvedIncludeRevoked = filterOverrides?.includeRevoked ?? emailSiteUsageIncludeRevoked;
      const query = new URLSearchParams({
        page: String(requestedPage),
        page_size: String(emailSiteUsagePagination.pageSize),
        include_revoked: String(resolvedIncludeRevoked),
      });
      const normalizedEmail = resolvedEmail;
      const normalizedSite = resolvedSite;
      if (normalizedEmail) {
        query.set("allocated_email", normalizedEmail);
      }
      if (normalizedSite) {
        query.set("usage_site", normalizedSite);
      }
      const response = await requestApi<EmailSiteUsageListResponse>(
        tokenForRequest,
        `/api/v1/admin/email-site-usages?${query.toString()}`,
      );
      setEmailSiteUsages(response.items);
      setEmailSiteUsagePagination({
        total: response.total,
        page: response.page,
        pageSize: response.page_size,
        totalPages: response.total_pages,
      });
      return true;
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法加载邮箱站点占用。");
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
      case "usage-sites":
        return loadUsageSites(tokenOverride);
      case "email-site-usages":
        // Keep site options available for the occupancy filter dropdown.
        void loadUsageSites(tokenOverride);
        return loadEmailSiteUsages(emailSiteUsagePagination.page, tokenOverride);
      case "egress-proxies":
        return loadEgressProxies(tokenOverride);
      case "providers":
        return loadProviders(tokenOverride);
      case "operator-console":
        return loadProviders(tokenOverride);
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
    clearLegacyAdminTokenStorage();
    registerAdminUnauthorizedHandler(() => {
      clearLegacyAdminTokenStorage();
      setIsAuthenticated(false);
      setAdminToken("");
      setErrorMessage("管理员认证已失效，请重新登录。");
    });
    return () => {
      registerAdminUnauthorizedHandler(null);
    };
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
      clearLegacyAdminTokenStorage();
      setAdminToken(tokenForLogin);
      setIsAuthenticated(true);
      setActiveNavigationSection("dashboard");
      setNotice(null);
    }
  }

  function handleLogout(): void {
    clearLegacyAdminTokenStorage();
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
    setEditingClientKey(null);
    setIsUpdatingClientKey(false);
    setCreatedClientApiKey(null);
    setIsProxyDialogOpen(false);
    setProxyDialogDraft(null);
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

  async function probeUnprobedMailboxes(): Promise<void> {
    const shouldStart = window.confirm(
      "开始识别未探测 / 能力未知邮箱？\n\n" +
        "将分批强制刷新 RT/AT（默认每批最多 1000 个），并发 worker 数按当前可用出口代理数计算。\n" +
        "成功则写入能力，invalid_grant 会标记为失效。若剩余较多，可多次点击继续下一批。",
    );
    if (!shouldStart) {
      return;
    }

    setIsProbingUnprobedMailboxes(true);
    setErrorMessage(null);
    try {
      const result = await requestApi<MailboxUnprobedRefreshResult>(
        adminToken,
        "/api/v1/admin/mailboxes/access-tokens/refresh-unprobed",
        {
          method: "POST",
          body: JSON.stringify({ batch_size: 1000 }),
        },
      );
      if (result.processed === 0) {
        setNotice("当前没有待识别的未探测 / 未知能力邮箱。");
      } else {
        setNotice(
          `未探测识别完成：候选 ${result.candidate_total}，本批处理 ${result.processed}，并发 ${result.worker_count}，成功 ${result.successful}，失败 ${result.failed}，剩余 ${result.remaining_candidates}。`,
        );
        if (result.failed > 0) {
          const failureReasonCounts = new Map<string, number>();
          for (const item of result.results) {
            if (item.successful) {
              continue;
            }
            const reason = (item.error_summary ?? "").trim() || "识别失败（无 error_summary）";
            failureReasonCounts.set(reason, (failureReasonCounts.get(reason) ?? 0) + 1);
          }
          const topFailureReasons = [...failureReasonCounts.entries()]
            .sort((left, right) => right[1] - left[1])
            .slice(0, 5)
            .map(([reason, count]) => `${reason} ×${count}`);
          const sampleFailures = result.results
            .filter((item) => !item.successful)
            .slice(0, 3)
            .map((item) => `${item.primary_email ?? item.mailbox_id}：${item.error_summary ?? "识别失败"}`);
          setErrorMessage(
            `部分邮箱识别失败（按原因汇总）：${topFailureReasons.join("；")}。示例：${sampleFailures.join("；")}`,
          );
        }
      }
      await loadMailboxes();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "识别未探测邮箱失败。");
    } finally {
      setIsProbingUnprobedMailboxes(false);
    }
  }

  async function deleteInvalidMailboxes(): Promise<void> {
    const shouldDelete = window.confirm(
      "确认删除全部失效邮箱（status=invalid）？\n\n关联租约会一并删除，且操作不可恢复。",
    );
    if (!shouldDelete) {
      return;
    }

    setIsDeletingInvalidMailboxes(true);
    setErrorMessage(null);
    try {
      const result = await requestApi<MailboxDeleteInvalidResult>(
        adminToken,
        "/api/v1/admin/mailboxes/delete-invalid",
        { method: "POST" },
      );
      setNotice(
        result.deleted > 0
          ? `已删除 ${result.deleted} 个失效邮箱。`
          : "当前没有可删除的失效邮箱。",
      );
      setSelectedMailboxIds(new Set());
      await loadMailboxes();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "删除失效邮箱失败。");
    } finally {
      setIsDeletingInvalidMailboxes(false);
    }
  }

  async function exportSelectedMailboxes(): Promise<void> {
    const mailboxIds = [...selectedMailboxIds];
    if (mailboxIds.length === 0) {
      setErrorMessage("请先选择需要导出的邮箱。");
      return;
    }

    setIsExportingSelectedMailboxes(true);
    setErrorMessage(null);
    try {
      const exportContent = await requestApiText(adminToken, "/api/v1/admin/mailboxes/export", {
        method: "POST",
        body: JSON.stringify({ mailbox_ids: mailboxIds }),
      });
      downloadTextFile(buildMailboxExportFilename(), exportContent);
      setNotice(`已导出 ${mailboxIds.length} 个邮箱为 txt 文件（格式：邮箱----密码----ClientID----RefreshToken）。`);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "导出选中邮箱失败。");
    } finally {
      setIsExportingSelectedMailboxes(false);
    }
  }

  async function deleteSelectedMailboxes(): Promise<void> {
    const mailboxIds = [...selectedMailboxIds];
    if (mailboxIds.length === 0) {
      setErrorMessage("请先选择需要删除的邮箱。");
      return;
    }

    const selectedEmails = mailboxes
      .filter((mailbox) => selectedMailboxIds.has(mailbox.id))
      .map((mailbox) => mailbox.primary_email);
    const previewEmails = selectedEmails.slice(0, 5).join("、");
    const remainingCount = Math.max(selectedEmails.length - 5, 0);
    const previewSuffix = remainingCount > 0 ? ` 等 ${selectedEmails.length} 个` : "";
    const shouldDelete = window.confirm(
      `确认删除选中的 ${mailboxIds.length} 个邮箱？\n${previewEmails}${previewSuffix}\n\n关联租约会一并删除，且操作不可恢复。`,
    );
    if (!shouldDelete) {
      return;
    }

    setIsDeletingSelectedMailboxes(true);
    setErrorMessage(null);
    try {
      const result = await requestApi<MailboxBatchDeleteResult>(
        adminToken,
        "/api/v1/admin/mailboxes/delete",
        {
          method: "POST",
          body: JSON.stringify({ mailbox_ids: mailboxIds }),
        },
      );
      const missingCount = result.missing_mailbox_ids.length;
      setNotice(
        missingCount > 0
          ? `已删除 ${result.deleted} 个邮箱；另有 ${missingCount} 个 ID 不存在或已删除。`
          : `已删除 ${result.deleted} 个邮箱。`,
      );
      setSelectedMailboxIds(new Set());
      await loadMailboxes();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "删除选中邮箱失败。");
    } finally {
      setIsDeletingSelectedMailboxes(false);
    }
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

  async function changeEmailSiteUsagePage(nextPage: number): Promise<void> {
    await loadEmailSiteUsages(nextPage);
  }

  async function createUsageSite(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const formData = new FormData(form);
    const code = String(formData.get("code") ?? "").trim().toLowerCase();
    const displayName = String(formData.get("display_name") ?? "").trim();
    const enabled = formData.get("enabled") === "on";
    if (!code || !displayName) {
      setErrorMessage("code 与展示名不能为空。");
      return;
    }
    setIsSavingUsageSite(true);
    setErrorMessage(null);
    try {
      await requestApi<UsageSiteItem>(adminToken, "/api/v1/admin/usage-sites", {
        method: "POST",
        body: JSON.stringify({ code, display_name: displayName, enabled }),
      });
      setIsUsageSiteCreateDialogOpen(false);
      setNotice(`注册站点「${code}」已创建。`);
      await loadUsageSites();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法创建注册站点。");
    } finally {
      setIsSavingUsageSite(false);
    }
  }

  async function toggleUsageSiteEnabled(site: UsageSiteItem): Promise<void> {
    const nextEnabled = !site.enabled;
    const actionLabel = nextEnabled ? "启用" : "禁用";
    const shouldContinue = window.confirm(
      `${actionLabel}站点「${site.code}」？${nextEnabled ? "" : "禁用后调用方不能再声明该站点。"}`,
    );
    if (!shouldContinue) {
      return;
    }
    setErrorMessage(null);
    try {
      const updated = await requestApi<UsageSiteItem>(
        adminToken,
        `/api/v1/admin/usage-sites/${encodeURIComponent(site.code)}`,
        {
          method: "PATCH",
          body: JSON.stringify({ enabled: nextEnabled }),
        },
      );
      setUsageSites((currentSites) =>
        currentSites.map((currentSite) => (currentSite.code === updated.code ? updated : currentSite)),
      );
      setNotice(`站点「${site.code}」已${actionLabel}。`);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法更新注册站点。");
    }
  }


  async function openEmailSiteUsagesForEmail(primaryEmail: string): Promise<void> {
    const normalizedEmail = primaryEmail.trim().toLowerCase();
    setEmailSiteUsageEmailFilter(normalizedEmail);
    setEmailSiteUsageSiteFilter("");
    setEmailSiteUsageIncludeRevoked(true);
    setActiveNavigationSection("email-site-usages");
    setErrorMessage(null);
    void loadUsageSites();
    await loadEmailSiteUsages(1, undefined, {
      allocatedEmail: normalizedEmail,
      usageSite: "",
      includeRevoked: true,
    });
  }

  async function deleteUsageSite(site: UsageSiteItem): Promise<void> {
    const activeUsageCount = site.active_usage_count ?? 0;
    if (activeUsageCount > 0) {
      setErrorMessage(`站点「${site.code}」仍有 ${activeUsageCount} 条未撤销占用，无法删除。请先在「站点占用」中撤销。`);
      return;
    }
    const shouldDelete = window.confirm(
      `删除注册站点「${site.code}」？仅当无未撤销占用时可删除；已撤销占用会一并清理。`,
    );
    if (!shouldDelete) {
      return;
    }
    setDeletingUsageSiteCode(site.code);
    setErrorMessage(null);
    try {
      await requestApi(adminToken, `/api/v1/admin/usage-sites/${encodeURIComponent(site.code)}`, {
        method: "DELETE",
      });
      setNotice(`注册站点「${site.code}」已删除。`);
      await loadUsageSites();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法删除注册站点。");
    } finally {
      setDeletingUsageSiteCode(null);
    }
  }

  async function revokeEmailSiteUsage(usage: EmailSiteUsageItem): Promise<void> {
    const shouldRevoke = window.confirm(
      `撤销占用「${usage.allocated_email} @ ${usage.usage_site}」？撤销后该地址可再次用于此站点。`,
    );
    if (!shouldRevoke) {
      return;
    }
    setIsRevokingUsageId(usage.id);
    setErrorMessage(null);
    try {
      await requestApi(adminToken, `/api/v1/admin/email-site-usages/${usage.id}/revoke`, {
        method: "POST",
      });
      setNotice(`已撤销 ${usage.allocated_email} 在 ${usage.usage_site} 的占用。`);
      await loadEmailSiteUsages(emailSiteUsagePagination.page);
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法撤销占用。");
    } finally {
      setIsRevokingUsageId(null);
    }
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

  function openCreateProxyDialog(): void {
    setErrorMessage(null);
    setProxyDialogDraft({
      sourceProxyId: null,
      name: "",
      protocol: "socks5",
      host: "",
      port: 1080,
      priority: 100,
      enabled: true,
      hasSourceCredentials: false,
    });
    setIsProxyDialogOpen(true);
  }

  function openCopyProxyDialog(proxy: EgressProxy): void {
    setErrorMessage(null);
    setProxyDialogDraft({
      sourceProxyId: proxy.id,
      name: `${proxy.name}-copy`,
      protocol: proxy.protocol,
      host: proxy.host || proxy.host_preview,
      port: proxy.port,
      priority: proxy.priority,
      enabled: proxy.enabled,
      hasSourceCredentials: proxy.has_credentials,
    });
    setIsProxyDialogOpen(true);
  }

  function closeProxyDialog(): void {
    setIsProxyDialogOpen(false);
    setProxyDialogDraft(null);
  }

  async function createProxy(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    // Do not trim passwords; only treat truly empty fields as omitted.
    const username = String(formData.get("username") ?? "");
    const password = String(formData.get("password") ?? "");
    const hasExplicitUsername = username.length > 0;
    const hasExplicitPassword = password.length > 0;
    const payload: Record<string, unknown> = {
      name: String(formData.get("name") ?? "").trim(),
      protocol: String(formData.get("protocol") ?? "socks5") as ProxyProtocol,
      host: String(formData.get("host") ?? "").trim(),
      port: Number(formData.get("port")),
      priority: Number(formData.get("priority")),
      enabled: formData.get("enabled") === "on",
    };
    if (hasExplicitUsername) {
      payload.username = username.trim();
    }
    if (hasExplicitPassword) {
      payload.password = password;
    }
    // Always tell the server the source id when copying, so blank auth fields clone source secrets.
    if (proxyDialogDraft?.sourceProxyId) {
      payload.copy_credentials_from_proxy_id = proxyDialogDraft.sourceProxyId;
    }

    try {
      await requestApi<EgressProxy>(adminToken, "/api/v1/admin/egress-proxies", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      closeProxyDialog();
      await loadEgressProxies();
      setErrorMessage(null);
      setNotice(
        proxyDialogDraft?.sourceProxyId
          ? "已根据源代理创建副本。未填写的认证凭证已从源代理解密后重新加密保存。"
          : "出口代理已创建。认证信息不会再次显示。",
      );
    } catch (error) {
      setNotice(null);
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
    setNotice(null);
    setErrorMessage(null);
    try {
      const result = await requestApi<ConnectivityResult>(
        adminToken,
        `/api/v1/admin/egress-proxies/${proxy.id}/test`,
        { method: "POST" },
      );
      // Reload may clear messages; re-apply result after refresh so the user always sees feedback.
      await loadEgressProxies();
      if (result.successful) {
        setErrorMessage(null);
        setNotice(`代理 ${proxy.name} 连接测试成功。`);
      } else {
        setNotice(null);
        setErrorMessage(
          result.error_summary
            ? `代理 ${proxy.name} 连接测试失败：${result.error_summary}`
            : `代理 ${proxy.name} 连接测试失败。`,
        );
      }
    } catch (error) {
      try {
        await loadEgressProxies();
      } catch {
        // Keep the original test error even if list refresh fails.
      }
      setNotice(null);
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

  async function updateClientKey(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!editingClientKey) {
      return;
    }
    const formData = new FormData(event.currentTarget);
    const name = String(formData.get("name") ?? "").trim();
    const scopes = formData
      .getAll("scopes")
      .map((scopeValue) => String(scopeValue))
      .filter((scopeValue): scopeValue is ClientKeyScope =>
        CLIENT_KEY_SCOPE_OPTIONS.some((option) => option.id === scopeValue),
      );
    if (!name) {
      setErrorMessage("Client Key 名称不能为空。");
      return;
    }
    if (scopes.length === 0) {
      setErrorMessage("请至少选择一个权限 scope。");
      return;
    }

    setIsUpdatingClientKey(true);
    setErrorMessage(null);
    try {
      const updatedClientKey = await requestApi<ClientKeyListItem>(
        adminToken,
        `/api/v1/admin/client-keys/${editingClientKey.id}`,
        {
          method: "PATCH",
          body: JSON.stringify({ name, scopes }),
        },
      );
      setClientKeys((currentClientKeys) =>
        currentClientKeys.map((currentClientKey) =>
          currentClientKey.id === updatedClientKey.id ? updatedClientKey : currentClientKey,
        ),
      );
      setEditingClientKey(null);
      setNotice(`Client Key「${updatedClientKey.name}」已更新名称与权限。`);
      void loadClientKeys();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : "无法更新 Client Key。");
    } finally {
      setIsUpdatingClientKey(false);
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
          <button className={`navigation-item ${activeNavigationSection === "usage-sites" ? "active" : ""}`} type="button" onClick={() => navigateToSection("usage-sites")} aria-current={activeNavigationSection === "usage-sites" ? "page" : undefined}><Globe2 size={16} /> 注册站点</button>
          <button className={`navigation-item ${activeNavigationSection === "email-site-usages" ? "active" : ""}`} type="button" onClick={() => navigateToSection("email-site-usages")} aria-current={activeNavigationSection === "email-site-usages" ? "page" : undefined}><ListFilter size={16} /> 站点占用</button>
          <button className={`navigation-item ${activeNavigationSection === "egress-proxies" ? "active" : ""}`} type="button" onClick={() => navigateToSection("egress-proxies")} aria-current={activeNavigationSection === "egress-proxies" ? "page" : undefined}><Settings2 size={16} /> 出口代理</button>
          <button className={`navigation-item ${activeNavigationSection === "providers" ? "active" : ""}`} type="button" onClick={() => navigateToSection("providers")} aria-current={activeNavigationSection === "providers" ? "page" : undefined}><Globe2 size={16} /> 邮箱 Provider</button>
          <button className={`navigation-item ${activeNavigationSection === "operator-console" ? "active" : ""}`} type="button" onClick={() => navigateToSection("operator-console")} aria-current={activeNavigationSection === "operator-console" ? "page" : undefined}><RefreshCw size={16} /> 联调工作台</button>
          <button className={`navigation-item ${activeNavigationSection === "client-keys" ? "active" : ""}`} type="button" onClick={() => navigateToSection("client-keys")} aria-current={activeNavigationSection === "client-keys" ? "page" : undefined}><KeyRound size={16} /> Client Key</button>
        </nav>
        <div className="sidebar-footer">
          <div className="sidebar-actions">
            <button className="navigation-item" type="button" onClick={handleLogout}>
              <LogOut size={16} /> 退出登录
            </button>
            <a className="navigation-item" href={`${apiBaseUrl}/redoc`} target="_blank" rel="noreferrer">
              <BookOpen size={16} /> API 文档
            </a>
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
            isProbingUnprobedMailboxes={isProbingUnprobedMailboxes}
            isExportingSelectedMailboxes={isExportingSelectedMailboxes}
            isDeletingSelectedMailboxes={isDeletingSelectedMailboxes}
            isDeletingInvalidMailboxes={isDeletingInvalidMailboxes}
            onPageChange={(nextPage) => void changeMailboxPage(nextPage)}
            onOpenImport={openMailboxImportDialog}
            onRefreshAllAccessTokens={() => void refreshAllAccessTokens()}
            onRefreshSelectedAccessTokens={() => void refreshSelectedAccessTokens()}
            onProbeUnprobedMailboxes={() => void probeUnprobedMailboxes()}
            onExportSelectedMailboxes={() => void exportSelectedMailboxes()}
            onDeleteSelectedMailboxes={() => void deleteSelectedMailboxes()}
            onDeleteInvalidMailboxes={() => void deleteInvalidMailboxes()}
            onToggleAllMailboxSelection={toggleAllMailboxSelection}
            onToggleMailboxSelection={toggleMailboxSelection}
            onOpenSiteUsages={(primaryEmail) => void openEmailSiteUsagesForEmail(primaryEmail)}
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
        ) : activeNavigationSection === "usage-sites" ? (
          <UsageSitesPage
            sites={usageSites}
            isCreateDialogOpen={isUsageSiteCreateDialogOpen}
            isSaving={isSavingUsageSite}
            deletingCode={deletingUsageSiteCode}
            onOpenCreateDialog={() => {
              setErrorMessage(null);
              setIsUsageSiteCreateDialogOpen(true);
            }}
            onCloseCreateDialog={() => setIsUsageSiteCreateDialogOpen(false)}
            onCreate={(event) => void createUsageSite(event)}
            onToggleEnabled={(site) => void toggleUsageSiteEnabled(site)}
            onDelete={(site) => void deleteUsageSite(site)}
            onRefresh={() => void loadUsageSites()}
          />
        ) : activeNavigationSection === "email-site-usages" ? (
          <EmailSiteUsagesPage
            usages={emailSiteUsages}
            page={emailSiteUsagePagination.page}
            pageSize={emailSiteUsagePagination.pageSize}
            total={emailSiteUsagePagination.total}
            totalPages={emailSiteUsagePagination.totalPages}
            allocatedEmailFilter={emailSiteUsageEmailFilter}
            usageSiteFilter={emailSiteUsageSiteFilter}
            includeRevoked={emailSiteUsageIncludeRevoked}
            siteOptions={usageSites}
            isRevokingId={isRevokingUsageId}
            onAllocatedEmailFilterChange={setEmailSiteUsageEmailFilter}
            onUsageSiteFilterChange={setEmailSiteUsageSiteFilter}
            onIncludeRevokedChange={setEmailSiteUsageIncludeRevoked}
            onSearch={() => void loadEmailSiteUsages(1)}
            onPageChange={(nextPage) => void changeEmailSiteUsagePage(nextPage)}
            onRevoke={(usage) => void revokeEmailSiteUsage(usage)}
          />
        ) : activeNavigationSection === "operator-console" ? (
          <OperatorConsolePage
            catalog={providerCatalog}
            adminToken={adminToken}
            onError={setErrorMessage}
            onNotice={setNotice}
          />
        ) : activeNavigationSection === "providers" ? (
          <ProvidersPage
            catalog={providerCatalog}
            smsbower={smsbowerSettings}
            apiKeyDraft={smsbowerApiKeyDraft}
            isSaving={isSavingSmsbower}
            isReplenishing={isReplenishingSmsbower}
            adminToken={adminToken}
            onApiKeyDraftChange={setSmsbowerApiKeyDraft}
            onRefresh={() => void loadProviders()}
            onToggleEnabled={(enabled) => void updateSmsbowerSettings({ enabled })}
            onSaveBasics={(fields) => void updateSmsbowerSettings(fields)}
            onSaveApiKey={() => {
              if (!smsbowerApiKeyDraft.trim()) {
                setErrorMessage("请输入 API Key，或使用「清除密钥」。");
                return;
              }
              void updateSmsbowerSettings({ api_key: smsbowerApiKeyDraft.trim() });
            }}
            onClearApiKey={() => {
              if (!window.confirm("确定清除已保存的 SMSBower API Key？")) {
                return;
              }
              void updateSmsbowerSettings({ clear_api_key: true });
            }}
            onReplenish={() => void replenishSmsbower()}
            onError={setErrorMessage}
            onNotice={setNotice}
          />
        ) : activeNavigationSection === "client-keys" ? (
          <ClientKeysPage
            clientKeys={clientKeys}
            createdApiKey={createdClientApiKey}
            filterText={clientKeyFilterText}
            isCreating={isCreatingClientKey}
            isCreateDialogOpen={isClientKeyCreateDialogOpen}
            isUpdating={isUpdatingClientKey}
            editingClientKey={editingClientKey}
            onCloseCreateDialog={() => setIsClientKeyCreateDialogOpen(false)}
            onCloseEditDialog={() => setEditingClientKey(null)}
            onCopyApiKey={() => void copyCreatedClientApiKey()}
            onCreate={(event) => void createClientKey(event)}
            onUpdate={(event) => void updateClientKey(event)}
            onDisable={(clientKey) => void disableClientKey(clientKey)}
            onFilterTextChange={setClientKeyFilterText}
            onOpenCreateDialog={() => {
              setErrorMessage(null);
              setEditingClientKey(null);
              setIsClientKeyCreateDialogOpen(true);
            }}
            onOpenEditDialog={(clientKey) => {
              setErrorMessage(null);
              setIsClientKeyCreateDialogOpen(false);
              setEditingClientKey(clientKey);
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
          <button className="button button-primary" type="button" onClick={openCreateProxyDialog} disabled={!adminToken}>
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
            <table className="egress-proxies-table">
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
                    <td className="cell-start">
                      <strong>{proxy.name}</strong>
                      <div className="muted-copy">{proxy.has_credentials ? "已配置认证" : "无认证"}</div>
                    </td>
                    <td className="cell-center">{proxy.protocol === "socks5" ? "SOCKS5" : "HTTP CONNECT"}<div className="muted-copy">{proxy.host}:{proxy.port}</div></td>
                    <td className="cell-center"><StatusBadge proxy={proxy} /></td>
                    <td className="cell-center">{proxy.priority}</td>
                    <td className="cell-center">{proxy.bound_mailbox_count}</td>
                    <td className="cell-center">{formatTime(proxy.last_success_at)}</td>
                    <td className="cell-center">
                      <div className="cell-actions">
                        <button className="button" type="button" onClick={() => void testProxy(proxy)}>测试</button>
                        {proxy.status === "cooldown" && <button className="button" type="button" onClick={() => void recoverProxy(proxy)}>恢复</button>}
                        <button className="button" type="button" onClick={() => void toggleProxy(proxy)}>{proxy.enabled ? "停用" : "启用"}</button>
                        <button className="button" type="button" onClick={() => openCopyProxyDialog(proxy)}>
                          <Copy size={14} /> 复制
                        </button>
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

      {activeNavigationSection === "egress-proxies" && isProxyDialogOpen && proxyDialogDraft && (
        <div className="dialog-backdrop" role="presentation">
          <form className="dialog" key={proxyDialogDraft.sourceProxyId ?? "create"} onSubmit={(event) => void createProxy(event)}>
            <div className="section-header">
              <div>
                <h2 className="section-title">
                  {proxyDialogDraft.sourceProxyId ? "复制出口代理" : "添加出口代理"}
                </h2>
                <p className="page-subtitle">
                  {proxyDialogDraft.sourceProxyId
                    ? "已预填源代理配置，可修改后保存为新代理。未填写用户名/密码时，将从源代理加密复制认证凭证。"
                    : "认证凭证仅会加密写入，无法从列表读取。"}
                </p>
              </div>
            </div>
            <div className="form-grid">
              <label className="form-field">
                名称
                <input className="input" name="name" required placeholder="hk-socks-01" defaultValue={proxyDialogDraft.name} />
              </label>
              <label className="form-field">
                协议
                <select className="select" name="protocol" defaultValue={proxyDialogDraft.protocol}>
                  <option value="socks5">SOCKS5</option>
                  <option value="http_connect">HTTP CONNECT</option>
                </select>
              </label>
              <label className="form-field">
                主机
                <input className="input" name="host" required placeholder="proxy.example.com" defaultValue={proxyDialogDraft.host} />
              </label>
              <label className="form-field">
                端口
                <input className="input" name="port" type="number" min="1" max="65535" defaultValue={proxyDialogDraft.port} required />
              </label>
              <label className="form-field">
                用户名（可选）
                <input
                  className="input"
                  name="username"
                  autoComplete="off"
                  placeholder={
                    proxyDialogDraft.sourceProxyId && proxyDialogDraft.hasSourceCredentials
                      ? "留空则沿用源代理用户名"
                      : undefined
                  }
                />
              </label>
              <label className="form-field">
                密码（可选）
                <input
                  className="input"
                  name="password"
                  type="password"
                  autoComplete="new-password"
                  placeholder={
                    proxyDialogDraft.sourceProxyId && proxyDialogDraft.hasSourceCredentials
                      ? "留空则沿用源代理密码"
                      : undefined
                  }
                />
              </label>
              <label className="form-field">
                优先级
                <input className="input" name="priority" type="number" min="0" defaultValue={proxyDialogDraft.priority} required />
              </label>
              <label className="checkbox-label" style={{ alignSelf: "end", minHeight: 34 }}>
                <input type="checkbox" name="enabled" defaultChecked={proxyDialogDraft.enabled} /> 创建后立即启用
              </label>
            </div>
            {proxyDialogDraft.sourceProxyId && proxyDialogDraft.hasSourceCredentials && (
              <p className="muted-copy" style={{ marginTop: 12 }}>
                源代理已配置认证。若用户名与密码都留空，将自动复制源代理的加密凭证；若填写任一字段，则以本次输入为准。
              </p>
            )}
            <div className="dialog-actions">
              <button className="button" type="button" onClick={closeProxyDialog}>取消</button>
              <button className="button button-primary" type="submit">
                {proxyDialogDraft.sourceProxyId ? "创建副本" : "安全保存"}
              </button>
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
