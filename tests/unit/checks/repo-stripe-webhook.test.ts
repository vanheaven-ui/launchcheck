import { describe, expect, it } from "vitest";
import { stripeWebhookCheck } from "@/lib/scanner/checks/repo/stripe-webhook";
import type { RepoFile } from "@/lib/scanner/types";
import { makeRepoContext } from "../../helpers/repo";

function file(path: string, text: string): RepoFile {
  return { path, text, truncated: false };
}

function ctx(files: RepoFile[]) {
  return makeRepoContext({ files });
}

describe("repo.stripe.webhook", () => {
  it("flags a webhook+stripe path with no constructEvent", async () => {
    const findings = await stripeWebhookCheck.run(
      ctx([
        file(
          "app/api/webhooks/stripe/route.ts",
          'if (body.type === "checkout.session.completed") {}',
        ),
      ]),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      severity: "high",
      confidence: "medium",
      title: "Possible Stripe webhook without signature verification",
    });
    expect(findings[0].location).toContain("/blob/");
  });

  it("flags on stripe-signature header alone", async () => {
    const findings = await stripeWebhookCheck.run(
      ctx([file("app/api/hook/route.ts", 'request.headers.get("Stripe-Signature")')]),
    );
    expect(findings).toHaveLength(1);
  });

  it("flags on a Stripe event type string alone", async () => {
    const findings = await stripeWebhookCheck.run(
      ctx([file("lib/handler.ts", 'switch (event.type) { case "invoice.paid": }')]),
    );
    expect(findings).toHaveLength(1);
  });

  it("does not flag files calling constructEvent or constructEventAsync", async () => {
    for (const call of ["stripe.webhooks.constructEvent(", "constructEventAsync("]) {
      const findings = await stripeWebhookCheck.run(
        ctx([
          file(
            "app/api/webhooks/stripe/route.ts",
            `${call} body, sig, secret); // checkout.session.completed`,
          ),
        ]),
      );
      expect(findings).toEqual([]);
    }
  });

  it("lowers confidence when a local stripe/webhook import exists", async () => {
    const findings = await stripeWebhookCheck.run(
      ctx([
        file(
          "app/api/webhooks/stripe/route.ts",
          'import { verify } from "../stripe-verify"; checkout.session.completed',
        ),
      ]),
    );
    expect(findings[0].confidence).toBe("low");
  });

  it("downgrades test-like paths to low/low", async () => {
    const findings = await stripeWebhookCheck.run(
      ctx([file("tests/webhooks/stripe.test.ts", "checkout.session.completed")]),
    );
    expect(findings[0]).toMatchObject({ severity: "low", confidence: "low" });
  });

  it("caps findings at 5", async () => {
    const files = Array.from({ length: 8 }, (_, i) =>
      file(`app/api/webhook${i}/stripe${i}/route.ts`, "checkout.session.completed"),
    );
    const findings = await stripeWebhookCheck.run(ctx(files));
    expect(findings).toHaveLength(5);
  });

  it("completes a 2MB pathological file under 1s", async () => {
    const pathological = "create table ".repeat(0) + "stripe-signature ".repeat(200_000);
    const start = Date.now();
    await stripeWebhookCheck.run(ctx([file("app/api/stripe-webhook/route.ts", pathological)]));
    expect(Date.now() - start).toBeLessThan(1000);
  });
});
