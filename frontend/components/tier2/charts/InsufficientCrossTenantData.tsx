/**
 * The genuine empty/insufficient-data state every Tier 2 chart falls back to instead of
 * rendering a misleadingly empty (or worse, single-tenant-only) axis. docs/10's copy
 * guidance: "Empty states direct rather than apologize" — this says exactly what is
 * missing and, when known, exactly how many tenants there are today.
 */
export function InsufficientCrossTenantData({
  tenantCount,
  needs = 2,
  detail,
}: {
  tenantCount: number;
  needs?: number;
  detail?: string;
}) {
  return (
    <div className="flex flex-col items-center gap-1 rounded-md border border-dashed border-[var(--color-border)] px-4 py-10 text-center">
      <p className="text-sm text-[var(--color-text-mid)]">
        Cross-tenant comparison needs {needs}+ tenants with ingested data — currently {tenantCount}.
      </p>
      {detail && <p className="max-w-md text-xs text-[var(--color-text-lo)]">{detail}</p>}
    </div>
  );
}
