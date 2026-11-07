// What the server's read API returns (internal/server/query.go, api.go).
export type Status = "FAIL" | "ERROR" | "MANUAL" | "WAIVED" | "PASS" | "NOT_APPLICABLE";
export const STATUSES: Status[] = ["FAIL", "ERROR", "MANUAL", "WAIVED", "PASS", "NOT_APPLICABLE"];
export type Counts = Partial<Record<Status, number>>;

export interface HostSummary {
  id: number;
  name: string;
  hostId: string;
  lastScanAt: string;
  latestScan: number;
  counts: Counts;
  score: number | null;
  stale: boolean;
  signed: boolean;
  keyFingerprint?: string;
  /** The profile the counts are of, and whether the host scanned with another one (it has no counts here). */
  profile?: string;
  otherProfile?: boolean;
}
export interface ControlRow { profile: string; id: string; title: string; titleKo?: string; severity: string; status: Status }
export interface ScanRow { id: number; receivedAt: string; startedAt: string; toolVersion: string; counts: Counts; score: number | null; signed: boolean }
export interface HostDetail extends HostSummary { profiles?: string[]; controls: ControlRow[]; scans: ScanRow[] }
export interface ScanJob { id: number; profile: string; state: "queued" | "claimed" | "done" | "failed" | "expired"; createdAt: string; finishedAt?: string; scan?: number; error?: string }
export interface AgentInfo { online: boolean; profiles: string[]; job?: ScanJob }
export interface FailingControl { profile: string; id: string; title: string; titleKo?: string; severity: string; hosts: number }
export interface RegressedControl { hostId: number; host: string; profile: string; id: string; title: string; titleKo?: string; severity: string; status: Status; receivedAt: string }
export interface Overview {
  hosts: number; hostsFailing: number; hostsStale: number; counts: Counts; score: number | null;
  topFailing: FailingControl[]; recentRegressions: RegressedControl[]; staleAfterDays: number;
  profile?: string; hostsOther?: number;
}
export interface CheckChange { ref: string; title: string; old: Status | ""; new: Status | "" }
export interface ControlChange { profile: string; id: string; title: string; titleKo?: string; severity: string; old: Status | ""; new: Status | ""; checks: CheckChange[] }
export interface Diff {
  old: { file: string; scanned: string }; new: { file: string; scanned: string }; notes: string[];
  regressed: ControlChange[]; fixed: ControlChange[]; changed: ControlChange[]; added: ControlChange[]; removed: ControlChange[]; unchanged: number;
}
// The stored result document: only the parts the dashboard shows. Every string is host text.
export interface Evidence { key: string; text: string; source?: string }
export interface DocCheck { ref: string; title: string; status: Status; reason?: string; remediation?: string; evidence?: Evidence[]; evidenceOmitted?: number }
export interface DocControl { profile: string; id: string; reason?: string; checks: string[]; waiver?: { reason: string; expires: string } }
export interface ScanDoc { controls: DocControl[]; checks: DocCheck[] }

export interface ControlSummary { profile: string; id: string; title: string; titleKo?: string; severity: string; counts: Counts }
export interface ControlHost { hostId: number; host: string; status: Status; stale: boolean }
export interface CheckInfo { id: string; title: string; titleKo?: string; description: string; rationale: string; remediation: string }
export interface ControlInfo { titleKo?: string; manual?: string; checks: CheckInfo[] }
export interface ControlDetail extends ControlSummary { hosts: ControlHost[] }
export interface MatrixControl { profile: string; id: string; title: string; titleKo?: string; severity: string }
export interface MatrixHost { id: number; name: string; stale: boolean; statuses: string }
export interface Matrix { controls: MatrixControl[]; hosts: MatrixHost[]; profile?: string; other?: number }
export interface ProfileList { profiles: { id: string; hosts: number }[]; default: string; titles: Record<string, string> }
