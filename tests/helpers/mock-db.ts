import { findings } from "@/lib/db/schema";
import type { Db } from "@/lib/scanner/persist";
import type { Severity } from "@/lib/scanner/types";

export type MockDb = {
  db: Db;
  calls: string[];
  /** Queries passed to each db.batch() call. */
  batches: unknown[][];
  insertedRows: Record<string, unknown>[][];
  /** WHERE conditions passed to each db.delete().where() call. */
  deleteWheres: unknown[];
};

export function mockDb(findingRows: { severity: Severity; title: string }[] = []): MockDb {
  const calls: string[] = [];
  const batches: unknown[][] = [];
  const insertedRows: Record<string, unknown>[][] = [];
  const deleteWheres: unknown[] = [];
  const db = {
    delete: () => ({
      where: (condition: unknown) => {
        calls.push("delete");
        deleteWheres.push(condition);
        return { kind: "delete" };
      },
    }),
    insert: () => ({
      values: (rows: Record<string, unknown>[]) => {
        calls.push("insert");
        insertedRows.push(rows);
        return { kind: "insert", rows };
      },
    }),
    batch: async (queries: unknown[]) => {
      calls.push("batch");
      batches.push(queries);
    },
    select: () => ({
      from: (table: unknown) => ({
        where: async () => {
          if (table === findings) {
            return findingRows;
          }
          throw new Error("unexpected select");
        },
      }),
    }),
  };
  return { db: db as unknown as Db, calls, batches, insertedRows, deleteWheres };
}
