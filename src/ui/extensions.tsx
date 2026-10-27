import { Globe } from "@phosphor-icons/react";
import { useState } from "react";
import type { AgentState, ScanSummary } from "../shared";
import { cx, VerdictBadge } from "./primitives";

export type ExtensionProps = {
  state: AgentState;
  /** Call a `@callable()` method on your agent, e.g. `call("setPolicy", [policy])`. */
  call: (method: string, args: unknown[]) => Promise<unknown>;
};

function ScanCard({ scan, onOpen }: { scan: ScanSummary; onOpen: () => void }) {
  return (
    <button
      type="button"
      onClick={onOpen}
      className="group w-40 shrink-0 overflow-hidden rounded-lg border border-line bg-panel text-left transition hover:border-brand/50"
    >
      <img
        src={scan.screenshot}
        alt={`Screenshot of ${scan.host}`}
        className="h-24 w-full object-cover object-top"
        loading="lazy"
      />
      <div className="space-y-1 p-2">
        <div className="flex items-center gap-1">
          <VerdictBadge verdict={scan.verdict} />
          <span className="ml-auto font-mono text-[10px] text-faint">
            {Math.round(scan.risk * 100)}%
          </span>
        </div>
        <p className="truncate text-xs font-medium">{scan.host}</p>
        <p className="truncate text-[10px] text-faint">
          {scan.category}
          {scan.brand !== "none" &&
            scan.verdict !== "allow" &&
            ` · looks like ${scan.brand}`}
        </p>
      </div>
    </button>
  );
}

/** Recent scans with screenshot evidence from R2. Click one to see it full size. */
export function SidebarExtras({ state }: ExtensionProps) {
  const [open, setOpen] = useState<ScanSummary | null>(null);
  if (state.scans.length === 0) return null;
  return (
    <section className="border-b border-line px-4 py-3">
      <div className="mb-2 flex items-center gap-2">
        <Globe weight="duotone" className="text-brand" />
        <h2 className="text-sm font-semibold tracking-tight">Recent scans</h2>
        <span className="ml-auto font-mono text-[10px] text-faint">
          {state.scans.length}
        </span>
      </div>
      <div className="scrollbar-thin flex gap-2 overflow-x-auto pb-1">
        {state.scans.map((scan) => (
          <ScanCard key={scan.id} scan={scan} onOpen={() => setOpen(scan)} />
        ))}
      </div>
      {open && (
        <div
          role="dialog"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-6"
          onClick={() => setOpen(null)}
        >
          <figure className="max-h-full max-w-4xl overflow-auto rounded-xl border border-line bg-panel">
            <img
              src={open.screenshot}
              alt={`Screenshot of ${open.host}`}
              className="w-full"
            />
            <figcaption className="space-y-1 p-3 text-sm">
              <div className="flex items-center gap-2">
                <VerdictBadge verdict={open.verdict} />
                <span className="font-medium">{open.title || open.host}</span>
              </div>
              <p className="font-mono text-xs break-all text-muted">
                {open.url}
              </p>
              {open.reasons.length > 0 && (
                <p
                  className={cx(
                    "text-xs",
                    open.verdict === "block" ? "text-block" : "text-review",
                  )}
                >
                  {open.reasons.join(" · ")}
                </p>
              )}
            </figcaption>
          </figure>
        </div>
      )}
    </section>
  );
}
