"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useRouter } from "next/navigation";
import { useEffect, useId, useRef, useState } from "react";
import { Controller, useForm } from "react-hook-form";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { formatCountdown, parseRateLimitError, remainingSeconds } from "@/lib/retry-after";
import { type ScanMode, type ScanRequest, scanRequestSchema } from "@/lib/scanner/validation";

const MODE_OPTIONS: { value: ScanMode; label: string }[] = [
  { value: "site", label: "Site" },
  { value: "repo", label: "Repo" },
  { value: "both", label: "Both" },
];

const DEFAULT_429_SECONDS = 60;
const DEFAULT_503_SECONDS = 30;

function retryAfterHeaderSeconds(response: Response, fallback: number): number {
  const raw = response.headers.get("retry-after");
  if (!raw) {
    return fallback;
  }
  const seconds = Number.parseInt(raw, 10);
  return Number.isFinite(seconds) && seconds > 0 ? seconds : fallback;
}

async function responseMessage(response: Response, fallback: string): Promise<string> {
  try {
    const body = (await response.json()) as { message?: unknown };
    return typeof body.message === "string" && body.message !== "" ? body.message : fallback;
  } catch {
    return fallback;
  }
}

export function ScanForm() {
  const router = useRouter();
  const uid = useId();
  const modeLabelId = `${uid}-mode-label`;
  const siteUrlId = `${uid}-site-url`;
  const siteUrlErrorId = `${uid}-site-url-error`;
  const repoUrlId = `${uid}-repo-url`;
  const repoUrlErrorId = `${uid}-repo-url-error`;
  const ownershipId = `${uid}-accepted-ownership`;
  const ownershipLabelId = `${uid}-accepted-ownership-label`;
  const ownershipErrorId = `${uid}-accepted-ownership-error`;
  const countdownId = `${uid}-countdown`;
  const politeId = `${uid}-polite`;

  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  // Server-imposed cooldown (429/503): submit stays disabled until it ends.
  const [cooldown, setCooldown] = useState<{ message: string; retryAt: number } | null>(null);
  const [secondsLeft, setSecondsLeft] = useState<number | null>(null);
  const [politeMessage, setPoliteMessage] = useState("");
  const announcedMinuteRef = useRef<number | null>(null);

  const {
    register,
    handleSubmit,
    control,
    watch,
    formState: { errors },
  } = useForm<ScanRequest>({
    resolver: zodResolver(scanRequestSchema),
    defaultValues: {
      mode: "site",
      siteUrl: "",
      repoUrl: "",
      acceptedOwnership: false,
    },
  });

  const mode = watch("mode");
  const showSite = mode !== "repo";
  const showRepo = mode !== "site";

  useEffect(() => {
    if (!cooldown) {
      return;
    }
    announcedMinuteRef.current = null;

    const update = () => {
      const remaining = remainingSeconds(cooldown.retryAt);
      setSecondsLeft(remaining);
      if (remaining <= 0) {
        setCooldown(null);
        setSecondsLeft(null);
        setPoliteMessage("You can submit again now.");
        return;
      }
      // Announce politely only when the remaining minutes change, so screen
      // readers are not spammed every second.
      const minute = Math.floor(remaining / 60);
      if (announcedMinuteRef.current !== minute) {
        announcedMinuteRef.current = minute;
        setPoliteMessage(`You can try again in ${formatCountdown(remaining)}.`);
      }
    };

    update();
    const interval = setInterval(update, 1000);
    return () => clearInterval(interval);
  }, [cooldown]);

  function startCooldown(message: string, retryAfterSeconds: number) {
    setCooldown({ message, retryAt: Date.now() + retryAfterSeconds * 1000 });
    setSecondsLeft(retryAfterSeconds);
    announcedMinuteRef.current = Math.floor(retryAfterSeconds / 60);
    setPoliteMessage(`You can try again in ${formatCountdown(retryAfterSeconds)}.`);
  }

  async function onSubmit(values: ScanRequest) {
    setIsSubmitting(true);
    setSubmitError(null);
    try {
      const response = await fetch("/api/scans", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values),
      });

      // 201 = new scan; 200 = an identical scan was reused (deduplicated).
      if (response.status === 201 || response.status === 200) {
        const body = (await response.json()) as { id?: unknown };
        if (typeof body.id === "string") {
          router.push(`/scan/${body.id}`);
          return;
        }
      }
      if (response.status === 429) {
        const bodyJson: unknown = await response.json().catch(() => null);
        const payload = parseRateLimitError(bodyJson);
        const retryAfter =
          payload?.retryAfterSeconds ?? retryAfterHeaderSeconds(response, DEFAULT_429_SECONDS);
        const fallbackMessage =
          typeof bodyJson === "object" &&
          bodyJson !== null &&
          "message" in bodyJson &&
          typeof bodyJson.message === "string" &&
          bodyJson.message !== ""
            ? bodyJson.message
            : "Please wait a moment before trying again.";
        startCooldown(payload?.message ?? fallbackMessage, retryAfter);
      } else if (response.status === 503) {
        const retryAfter = retryAfterHeaderSeconds(response, DEFAULT_503_SECONDS);
        const message = await responseMessage(
          response,
          "Scanning is temporarily unavailable. Please try again in a moment.",
        );
        startCooldown(message, retryAfter);
      } else {
        setSubmitError("Something went wrong. Please try again.");
      }
    } catch {
      setSubmitError("We couldn't reach the server. Check your connection and try again.");
    } finally {
      setIsSubmitting(false);
    }
  }

  const cooldownActive = cooldown !== null;

  return (
    <form onSubmit={handleSubmit(onSubmit)} noValidate className="w-full">
      <div className="flex flex-col gap-4">
        <div>
          <span id={modeLabelId} className="mb-2 block text-sm font-medium text-[var(--ink)]">
            What do you want to scan?
          </span>
          <Controller
            name="mode"
            control={control}
            render={({ field }) => (
              <ToggleGroup
                type="single"
                value={field.value}
                onValueChange={(value) => {
                  if (value) {
                    field.onChange(value as ScanMode);
                  }
                }}
                aria-labelledby={modeLabelId}
              >
                {MODE_OPTIONS.map((option) => (
                  <ToggleGroupItem key={option.value} value={option.value}>
                    {option.label}
                  </ToggleGroupItem>
                ))}
              </ToggleGroup>
            )}
          />
        </div>

        {showSite ? (
          <div>
            <Label htmlFor={siteUrlId}>Site URL</Label>
            <Input
              id={siteUrlId}
              type="url"
              inputMode="url"
              autoComplete="url"
              placeholder="https://your-app.com"
              className="mt-1.5 font-mono"
              aria-invalid={Boolean(errors.siteUrl)}
              aria-describedby={errors.siteUrl ? siteUrlErrorId : undefined}
              {...register("siteUrl")}
            />
            {errors.siteUrl ? (
              <p id={siteUrlErrorId} role="alert" className="mt-1.5 text-sm text-[var(--critical)]">
                {errors.siteUrl.message}
              </p>
            ) : null}
          </div>
        ) : null}

        {showRepo ? (
          <div>
            <Label htmlFor={repoUrlId}>GitHub repo URL</Label>
            <Input
              id={repoUrlId}
              type="url"
              inputMode="url"
              autoComplete="url"
              placeholder="https://github.com/owner/repo"
              className="mt-1.5 font-mono"
              aria-invalid={Boolean(errors.repoUrl)}
              aria-describedby={errors.repoUrl ? repoUrlErrorId : undefined}
              {...register("repoUrl")}
            />
            {errors.repoUrl ? (
              <p id={repoUrlErrorId} role="alert" className="mt-1.5 text-sm text-[var(--critical)]">
                {errors.repoUrl.message}
              </p>
            ) : null}
          </div>
        ) : null}

        <div>
          <Button
            type="submit"
            size="lg"
            disabled={isSubmitting || cooldownActive}
            className="w-full sm:w-auto"
          >
            {isSubmitting ? "Starting…" : cooldownActive ? "Please wait…" : "Run pre-flight"}
          </Button>
        </div>

        {cooldown ? (
          <div role="alert" className="text-sm text-[var(--critical)]">
            <p>{cooldown.message}</p>
            <p id={countdownId} aria-live="off" className="mt-1">
              You can try again in {formatCountdown(secondsLeft ?? 0)}.
            </p>
          </div>
        ) : null}

        <p id={politeId} aria-live="polite" className="sr-only">
          {politeMessage}
        </p>

        <div className="flex items-start gap-3">
          <Controller
            name="acceptedOwnership"
            control={control}
            render={({ field }) => (
              <Checkbox
                id={ownershipId}
                checked={field.value}
                onCheckedChange={(checked) => field.onChange(checked === true)}
                aria-invalid={Boolean(errors.acceptedOwnership)}
                aria-labelledby={ownershipLabelId}
                aria-describedby={errors.acceptedOwnership ? ownershipErrorId : undefined}
                className="mt-0.5"
              />
            )}
          />
          <div>
            <Label id={ownershipLabelId} htmlFor={ownershipId} className="cursor-pointer">
              I own this site or repo, or have permission to scan it.
            </Label>
            {errors.acceptedOwnership ? (
              <p id={ownershipErrorId} role="alert" className="mt-1 text-sm text-[var(--critical)]">
                {errors.acceptedOwnership.message}
              </p>
            ) : null}
          </div>
        </div>

        {submitError ? (
          <p role="alert" className="text-sm text-[var(--critical)]">
            {submitError}
          </p>
        ) : null}
      </div>
    </form>
  );
}
