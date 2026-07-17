import { test } from "node:test";
import assert from "node:assert/strict";
import { smtpReplyComplete, smtpAdvertisesStartTls } from "../src/smtp.js";

test("smtpReplyComplete detects a complete single-line reply", () => {
  assert.equal(smtpReplyComplete("220 mail.example.com ESMTP\r\n"), true);
  assert.equal(smtpReplyComplete("220 mail.example.com ESMTP"), false); // no terminator yet
});

test("smtpReplyComplete waits for the final line of a multi-line reply", () => {
  // '250-' lines are continuations; only '250 ' (space) ends the reply.
  assert.equal(smtpReplyComplete("250-mail.example.com\r\n250-PIPELINING\r\n"), false);
  assert.equal(smtpReplyComplete("250-mail.example.com\r\n250-STARTTLS\r\n250 8BITMIME\r\n"), true);
});

test("smtpAdvertisesStartTls detects the STARTTLS capability", () => {
  assert.equal(smtpAdvertisesStartTls("250-mail\r\n250-STARTTLS\r\n250 8BITMIME\r\n"), true);
  assert.equal(smtpAdvertisesStartTls("250 STARTTLS\r\n"), true);
  assert.equal(smtpAdvertisesStartTls("250-mail\r\n250 8BITMIME\r\n"), false);
});
