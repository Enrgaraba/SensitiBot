import nock from "nock";
import { Probot, ProbotOctokit } from "probot";
import myProbotApp from "../index.js";
import { getModifiedFiles, createIssue, analyzeCsvFiles, analyzeTxtFiles } from "../utils/githubUtils.js";
import { fetchFileContent } from "../utils/fileUtils.js";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { describe, beforeEach, afterEach, test } from "node:test";
import assert from "node:assert";

// Mock de fetchFileContent para evitar llamadas reales
jest.mock("../utils/fileUtils.js", () => ({
  fetchFileContent: jest.fn(() => Promise.resolve("mocked content")),
}));

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const privateKey = fs.readFileSync(
  path.join(__dirname, "fixtures/mock-cert.pem"),
  "utf-8"
);

describe("Probot App Tests", () => {
  let probot;

  beforeEach(() => {
    nock.disableNetConnect();
    probot = new Probot({
      appId: 123,
      privateKey,
      Octokit: ProbotOctokit.defaults({
        retry: { enabled: false },
        throttle: { enabled: false },
      }),
    });
    probot.load(myProbotApp);
  });

  test("Processes a push event and creates an issue if vulnerabilities are found", async () => {
    const payload = JSON.parse(
      fs.readFileSync(
        path.join(__dirname, "fixtures/push_event.json"),
        "utf-8"
      )
    );

    const mock = nock("https://api.github.com")
      .post("/app/installations/2/access_tokens")
      .reply(200, {
        token: "test",
        permissions: { issues: "write" },
      })
      .post("/repos/test-owner/test-repo/issues", (body) => {
        assert.ok(body.title.includes("Sensitive information found"));
        return true;
      })
      .reply(200);

    await probot.receive({ name: "push", payload });

    assert.deepStrictEqual(mock.pendingMocks(), []);
  });

  afterEach(() => {
    nock.cleanAll();
    nock.enableNetConnect();
  });
});
