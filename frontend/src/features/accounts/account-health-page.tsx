import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Activity, Trash2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";

import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  deleteAccounts,
  probeBuildAccountHealth,
  type AccountTaskProgressDTO,
  type HealthProbeItemDTO,
  type HealthProbeStatus,
  type HealthProbeSummaryDTO,
} from "@/features/accounts/accounts-api";
import { EmptyState, LoadingState } from "@/shared/components/data-state";
import { DataTableShell } from "@/shared/components/data-table-shell";
import { cn } from "@/shared/lib/cn";

function isAbortError(error: unknown): boolean {
  return (error instanceof DOMException || error instanceof Error) && error.name === "AbortError";
}

export function AccountHealthPage() {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const probeAbortRef = useRef<AbortController | null>(null);
  const [probeProgress, setProbeProgress] = useState<AccountTaskProgressDTO | null>(null);
  const [probeItems, setProbeItems] = useState<HealthProbeItemDTO[]>([]);
  const [probeSummary, setProbeSummary] = useState<HealthProbeSummaryDTO | null>(null);
  const [probeFilter, setProbeFilter] = useState<HealthProbeStatus | "all">("all");
  const [deleteForbiddenOpen, setDeleteForbiddenOpen] = useState(false);

  useEffect(() => () => {
    probeAbortRef.current?.abort();
  }, []);

  const probeMutation = useMutation({
    mutationFn: () => {
      const controller = new AbortController();
      probeAbortRef.current = controller;
      setProbeProgress(null);
      setProbeItems([]);
      setProbeSummary(null);
      setProbeFilter("all");
      return probeBuildAccountHealth(setProbeProgress, (item) => {
        setProbeItems((current) => {
          const next = current.filter((entry) => entry.accountId !== item.accountId);
          next.push(item);
          return next;
        });
      }, controller.signal);
    },
    onSuccess: (result) => {
      setProbeSummary(result);
      setProbeItems(result.items);
      toast.success(t("accounts.probeCompleted", result));
    },
    onError: (error) => {
      if (!isAbortError(error)) {
        toast.error(error instanceof Error ? error.message : t("errors.generic"));
      }
    },
    onSettled: () => {
      probeAbortRef.current = null;
      setProbeProgress(null);
    },
  });

  const forbiddenItems = useMemo(
    () => probeItems.filter((item) => item.status === "forbidden"),
    [probeItems],
  );

  const deleteForbiddenMutation = useMutation({
    mutationFn: () => deleteAccounts(forbiddenItems.map((item) => item.accountId), "grok_build"),
    onSuccess: (result) => {
      const removed = new Set(forbiddenItems.map((item) => item.accountId));
      setProbeItems((current) => current.filter((item) => !removed.has(item.accountId)));
      setProbeSummary((current) => {
        if (!current) return current;
        const remaining = current.items.filter((item) => !removed.has(item.accountId));
        return {
          ...current,
          total: remaining.length,
          forbidden: 0,
          items: remaining,
          healthy: remaining.filter((item) => item.status === "healthy").length,
          unauthorized: remaining.filter((item) => item.status === "unauthorized").length,
          payment: remaining.filter((item) => item.status === "payment").length,
          rateLimited: remaining.filter((item) => item.status === "rate_limited").length,
          network: remaining.filter((item) => item.status === "network").length,
          error: remaining.filter((item) => item.status === "error").length,
          unknown: remaining.filter((item) => item.status === "unknown").length,
        };
      });
      setDeleteForbiddenOpen(false);
      void queryClient.invalidateQueries({ queryKey: ["accounts"] });
      toast.success(t("accounts.probeDeleteForbiddenCompleted", { deleted: result.deleted, count: forbiddenItems.length }));
    },
    onError: (error) => {
      toast.error(error instanceof Error ? error.message : t("errors.generic"));
    },
  });

  const visibleItems = useMemo(
    () => [...probeItems]
      .filter((item) => probeFilter === "all" || item.status === probeFilter)
      .sort((left, right) => healthProbeStatusRank(left.status) - healthProbeStatusRank(right.status) || left.name.localeCompare(right.name)),
    [probeItems, probeFilter],
  );

  return (
    <div className="space-y-8">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-medium">{t("accounts.probeHealthTitle")}</h1>
          <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{t("accounts.probeHealthDescription")}</p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={probeMutation.isPending || forbiddenItems.length === 0}
            onClick={() => setDeleteForbiddenOpen(true)}
          >
            <Trash2 />
            {t("accounts.probeDeleteForbidden", { count: forbiddenItems.length })}
          </Button>
          <Button
            type="button"
            size="sm"
            disabled={probeMutation.isPending}
            onClick={() => probeMutation.mutate()}
          >
            {probeMutation.isPending ? <Spinner /> : <Activity />}
            {probeItems.length > 0 || probeSummary ? t("accounts.probeHealthAgain") : t("accounts.probeHealth")}
          </Button>
        </div>
      </header>

      <section className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        <ProbeMetric label={t("accounts.probeMetricTotal")} value={probeSummary?.total ?? probeItems.length} loading={probeMutation.isPending && probeItems.length === 0} />
        <ProbeMetric label={t("accounts.probeStatus.healthy")} value={probeSummary?.healthy ?? countStatus(probeItems, "healthy")} loading={probeMutation.isPending && probeItems.length === 0} tone="healthy" />
        <ProbeMetric label={t("accounts.probeStatus.forbidden")} value={probeSummary?.forbidden ?? countStatus(probeItems, "forbidden")} loading={probeMutation.isPending && probeItems.length === 0} tone="danger" />
        <ProbeMetric label={t("accounts.probeStatus.rateLimited")} value={probeSummary?.rateLimited ?? countStatus(probeItems, "rate_limited")} loading={probeMutation.isPending && probeItems.length === 0} tone="warn" />
      </section>

      <DataTableShell
        toolbar={(
          <>
            <div className="flex min-w-0 flex-1 flex-wrap items-center gap-2 text-xs text-muted-foreground">
              {probeMutation.isPending ? (
                <span className="inline-flex items-center gap-2"><Spinner className="size-3.5" />{probeProgress ? t("accounts.probeProgress", probeProgress) : t("common.loading")}</span>
              ) : probeSummary ? (
                <span className="truncate">{t("accounts.probeSummary", probeSummary)}</span>
              ) : (
                <span>{t("accounts.probeIdle")}</span>
              )}
            </div>
            <div className="flex flex-wrap gap-1.5">
              {([
                ["all", t("common.all")],
                ["healthy", t("accounts.probeStatus.healthy")],
                ["unauthorized", t("accounts.probeStatus.unauthorized")],
                ["payment", t("accounts.probeStatus.payment")],
                ["forbidden", t("accounts.probeStatus.forbidden")],
                ["rate_limited", t("accounts.probeStatus.rateLimited")],
                ["network", t("accounts.probeStatus.network")],
                ["error", t("accounts.probeStatus.error")],
                ["unknown", t("accounts.probeStatus.unknown")],
              ] as const).map(([value, label]) => (
                <Button key={value} type="button" size="sm" variant={probeFilter === value ? "default" : "secondary"} className="h-7 px-2 text-xs" onClick={() => setProbeFilter(value)}>
                  {label}
                </Button>
              ))}
            </div>
          </>
        )}
      >
        {probeItems.length === 0 && probeMutation.isPending ? <LoadingState className="min-h-48" /> : null}
        {probeItems.length === 0 && !probeMutation.isPending ? <EmptyState message={t("accounts.probeEmpty")} /> : null}
        {probeItems.length > 0 ? (
          <Table className="table-fixed border-collapse min-w-[780px]">
            <colgroup>
              <col style={{ width: "34%" }} />
              <col style={{ width: "14%" }} />
              <col style={{ width: "10%" }} />
              <col style={{ width: "12%" }} />
              <col style={{ width: "30%" }} />
            </colgroup>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>{t("accounts.account")}</TableHead>
                <TableHead className="whitespace-nowrap">{t("accounts.probeResult")}</TableHead>
                <TableHead className="whitespace-nowrap">HTTP</TableHead>
                <TableHead className="whitespace-nowrap">{t("accounts.probeElapsed")}</TableHead>
                <TableHead>{t("accounts.probeDetail")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {visibleItems.map((item) => (
                <TableRow key={item.accountId}>
                  <TableCell>
                    <div className="min-w-0">
                      <div className="truncate font-medium">{item.name}</div>
                      <div className="truncate text-xs text-muted-foreground">
                        {item.email || item.accountId}
                        {item.enabled ? "" : ` · ${t("common.disabled")}`}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell><HealthProbeStatusBadge status={item.status} /></TableCell>
                  <TableCell className="tabular-nums text-muted-foreground">{item.httpStatus || "-"}</TableCell>
                  <TableCell className="tabular-nums text-muted-foreground">{item.elapsedMs}ms</TableCell>
                  <TableCell className="truncate text-xs text-muted-foreground" title={item.error || undefined}>{item.error || "-"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        ) : null}
      </DataTableShell>

      <AlertDialog open={deleteForbiddenOpen} onOpenChange={setDeleteForbiddenOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t("accounts.probeDeleteForbiddenTitle", { count: forbiddenItems.length })}</AlertDialogTitle>
            <AlertDialogDescription>{t("accounts.probeDeleteForbiddenDescription", { count: forbiddenItems.length })}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("common.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-white hover:bg-destructive/90"
              disabled={deleteForbiddenMutation.isPending || forbiddenItems.length === 0}
              onClick={(event) => {
                event.preventDefault();
                deleteForbiddenMutation.mutate();
              }}
            >
              {deleteForbiddenMutation.isPending ? <Spinner /> : null}
              {t("common.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function countStatus(items: HealthProbeItemDTO[], status: HealthProbeStatus): number {
  return items.filter((item) => item.status === status).length;
}

function healthProbeStatusRank(status: HealthProbeStatus): number {
  switch (status) {
    case "forbidden": return 0;
    case "unauthorized": return 1;
    case "payment": return 2;
    case "rate_limited": return 3;
    case "error": return 4;
    case "unknown": return 5;
    case "network": return 6;
    case "healthy": return 7;
    default: return 8;
  }
}

function HealthProbeStatusBadge({ status }: { status: HealthProbeStatus }) {
  const { t } = useTranslation();
  const label = t(`accounts.probeStatus.${status === "rate_limited" ? "rateLimited" : status}`);
  const className = status === "healthy"
    ? "border-transparent bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
    : status === "forbidden" || status === "unauthorized"
      ? "border-transparent bg-destructive/15 text-destructive"
      : status === "payment" || status === "rate_limited"
        ? "border-transparent bg-amber-500/15 text-amber-700 dark:text-amber-300"
        : status === "network"
          ? "border-transparent bg-sky-500/15 text-sky-700 dark:text-sky-300"
          : "border-transparent bg-muted text-muted-foreground";
  return <Badge variant="outline" className={className}>{label}</Badge>;
}

function ProbeMetric({ label, value, loading, tone }: { label: string; value: number; loading: boolean; tone?: "healthy" | "danger" | "warn" }) {
  return (
    <div className="min-h-24 rounded-lg bg-card p-4">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={cn(
        "mt-3 flex min-h-7 items-center text-xl font-medium tabular-nums",
        tone === "healthy" && "text-emerald-700 dark:text-emerald-300",
        tone === "danger" && "text-destructive",
        tone === "warn" && "text-amber-700 dark:text-amber-300",
      )}
      >
        {loading ? <Spinner /> : value}
      </div>
    </div>
  );
}
