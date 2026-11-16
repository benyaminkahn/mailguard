/**
 * MailGuard: Gmail Add-on (thin client).
 *
 * Responsibilities, and nothing more:
 *   1. Read the open email (with the per-message access token Gmail provides).
 *   2. Send its metadata and content to the MailGuard backend.
 *   3. Render the backend's explainable verdict as a card.
 *
 * All analysis happens on the backend. The add-on never opens, fetches or
 * resolves any URL found in the email, and never logs email content.
 */

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

var BACKEND_URL = "https://placeholder.ngrok.app/analyze";
// MVP only: anyone with edit access to this script can read this key.
// For production, store it in Script Properties instead of in the source.
var API_KEY = "mailguard-demo-key-993"; // must match MAILGUARD_API_KEY on the backend

// Field limits. They mirror backend/schemas.py so a normal email never gets
// a 422, and they keep the request well below the backend's 1 MB cap.
var LIMITS = {
  NAME: 256,
  ADDRESS: 320,
  SUBJECT: 998,
  BODY_PLAIN: 100000,
  BODY_HTML: 200000,
  ATTACHMENTS: 50,
  ATTACHMENT_NAME: 255,
  PAYLOAD_BYTES: 900 * 1024 // headroom under the backend's 1 MB limit
};

// Limits applied to the backend's response before it is rendered.
var RESPONSE_LIMITS = {
  SHORT_TEXT: 100,
  LONG_TEXT: 2000,
  ITEM_TEXT: 500,
  FINDINGS: 25,
  RECOMMENDATIONS: 10
};

var THEME = {
  BRAND: "#5A2CFF",   // deep purple: neutral headings
  SAFE: "#188038",
  WARNING: "#E37400", // orange: pure yellow is unreadable on a white card
  DANGER: "#FF0000",
  MUTED: "#5F6368"
};

// The UI level comes from the backend's verdict, never from re-computing
// thresholds here, so the add-on can never disagree with the backend.
var VERDICT_LEVELS = {
  Low: "safe",
  Medium: "warning",
  High: "danger",
  Critical: "danger"
};

// ---------------------------------------------------------------------------
// Trigger entry points (public: these names are referenced in appsscript.json)
// ---------------------------------------------------------------------------

/** Homepage, shown when no email is open. */
function onHomepage() {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader().setTitle("MailGuard"))
    .addSection(
      CardService.newCardSection().addWidget(
        CardService.newTextParagraph().setText(
          "Open an email to analyze it for phishing, spoofing and malware."
        )
      )
    )
    .build();
}

/** Contextual trigger: runs when the user opens an email. */
function onGmailMessageOpen(e) {
  return [buildCardForEvent_(e)];
}

/** "Try again" button on the error card. */
function onRetry(e) {
  return CardService.newActionResponseBuilder()
    .setNavigation(CardService.newNavigation().updateCard(buildCardForEvent_(e)))
    .build();
}

// ---------------------------------------------------------------------------
// Orchestration: every failure path ends in a card, never in a thrown error
// ---------------------------------------------------------------------------

function buildCardForEvent_(e) {
  var payload;
  try {
    payload = buildPayload_(getCurrentMessage_(e));
  } catch (err) {
    logError_("read_message", err);
    return buildErrorCard_("MailGuard could not read this email.");
  }

  var result = callBackend_(payload);
  if (result.error) {
    return buildErrorCard_(result.error);
  }

  try {
    return buildResultCard_(result.data);
  } catch (err) {
    logError_("render", err);
    return buildErrorCard_("MailGuard received a result but could not display it.");
  }
}

// ---------------------------------------------------------------------------
// Extraction
// ---------------------------------------------------------------------------

function getCurrentMessage_(e) {
  if (!e || !e.gmail || !e.gmail.messageId || !e.gmail.accessToken) {
    throw new Error("Missing Gmail event context");
  }
  // Grants read access to this one message only (current.message scope).
  GmailApp.setCurrentMessageAccessToken(e.gmail.accessToken);
  return GmailApp.getMessageById(e.gmail.messageId);
}

function buildPayload_(message) {
  var from = parseAddress_(message.getFrom());

  return {
    sender_name: from.name ? truncate_(from.name, LIMITS.NAME) : null,
    sender_email: truncate_(from.email, LIMITS.ADDRESS),
    reply_to: nullIfEmpty_(truncate_(safeString_(message.getReplyTo()), LIMITS.ADDRESS)),
    subject: truncate_(safeString_(message.getSubject()), LIMITS.SUBJECT),
    body_plain: nullIfEmpty_(truncate_(safeString_(message.getPlainBody()), LIMITS.BODY_PLAIN)),
    // Not in the original field list: without the HTML the backend cannot see
    // <a> tags, so it could never detect link text / href mismatches.
    body_html: nullIfEmpty_(truncate_(safeString_(message.getBody()), LIMITS.BODY_HTML)),
    attachment_names: getAttachmentNames_(message)
  };
}

/** Split 'Display Name <addr@domain>' into its parts. */
function parseAddress_(raw) {
  var value = safeString_(raw).trim();
  var match = value.match(/^\s*"?([^"<]*?)"?\s*<([^<>]*)>\s*$/);
  if (match) {
    return { name: match[1].trim(), email: match[2].trim() };
  }
  return { name: "", email: value };
}

function getAttachmentNames_(message) {
  var names = [];
  try {
    var attachments = message.getAttachments({
      includeInlineImages: false,
      includeAttachments: true
    });
    for (var i = 0; i < attachments.length && names.length < LIMITS.ATTACHMENTS; i++) {
      var name = safeString_(attachments[i].getName());
      if (name) {
        // Keep the END of an overlong name: an attacker can pad the name so
        // that cutting from the front would hide a ".exe" extension.
        names.push(name.length > LIMITS.ATTACHMENT_NAME
          ? name.slice(name.length - LIMITS.ATTACHMENT_NAME)
          : name);
      }
    }
  } catch (err) {
    // Not fatal: analyze the rest of the email without attachment names.
    logError_("attachments", err);
  }
  return names;
}

// ---------------------------------------------------------------------------
// Backend call
// ---------------------------------------------------------------------------

/**
 * Returns { data: <validated result> } or { error: <user-facing message> }.
 * Never throws.
 */
function callBackend_(payload) {
  var response;
  try {
    response = UrlFetchApp.fetch(BACKEND_URL, {
      method: "post",
      contentType: "application/json",
      headers: {
        "X-API-Key": API_KEY,
        "ngrok-skip-browser-warning": "true"
      },
      payload: serializePayload_(payload),
      muteHttpExceptions: true,       // 4xx/5xx come back as a response, not an exception
      followRedirects: false,         // never send the API key on to another host
      validateHttpsCertificates: true
    });
  } catch (err) {
    // Network failure, DNS error, timeout, or a URL not on the allowlist.
    logError_("fetch", err);
    return { error: "The MailGuard service could not be reached. It may be offline or took too long to respond." };
  }

  var status = response.getResponseCode();
  if (status !== 200) {
    console.warn("MailGuard: backend returned HTTP " + status);
    return { error: describeHttpError_(status) };
  }

  var data;
  try {
    data = JSON.parse(response.getContentText());
  } catch (err) {
    logError_("parse_response", err);
    return { error: "The MailGuard service returned an unreadable response." };
  }

  var result = validateResult_(data);
  if (!result) {
    console.warn("MailGuard: backend response failed validation");
    return { error: "The MailGuard service returned an unexpected response." };
  }
  return { data: result };
}

/**
 * Serialize, shrinking the bodies (HTML first) if the UTF-8 size would
 * exceed the budget. Non-ASCII and escaped characters can make the JSON
 * several times larger than the character count.
 */
function serializePayload_(payload) {
  var json = JSON.stringify(payload);
  for (var attempt = 0; attempt < 10 && byteLength_(json) > LIMITS.PAYLOAD_BYTES; attempt++) {
    if (payload.body_html) {
      payload.body_html = nullIfEmpty_(truncate_(payload.body_html, Math.floor(payload.body_html.length / 2)));
    } else if (payload.body_plain) {
      payload.body_plain = nullIfEmpty_(truncate_(payload.body_plain, Math.floor(payload.body_plain.length / 2)));
    } else {
      break; // nothing left to shrink; the backend's 413 is handled gracefully
    }
    json = JSON.stringify(payload);
  }
  return json;
}

function describeHttpError_(status) {
  switch (status) {
    case 401:
    case 403:
      return "The add-on could not authenticate with the MailGuard service (HTTP " + status + "). Check the API key.";
    case 413:
      return "This email is too large for MailGuard to analyze (HTTP 413).";
    case 422:
      return "MailGuard could not process this email's data (HTTP 422).";
    case 429:
      return "The MailGuard service is busy. Please try again shortly (HTTP 429).";
    default:
      if (status >= 500) {
        return "The MailGuard service hit an internal error (HTTP " + status + "). Please try again later.";
      }
      return "The MailGuard service returned an unexpected status (HTTP " + status + ").";
  }
}

/**
 * Defense in depth: validate the response shape and bound every string and
 * list before rendering. Returns null if the response is not usable.
 */
function validateResult_(data) {
  if (!data || typeof data !== "object") return null;

  var score = data.score;
  if (typeof score !== "number" || !isFinite(score) || score < 0 || score > 100) return null;
  if (!Object.prototype.hasOwnProperty.call(VERDICT_LEVELS, data.verdict)) return null;

  // category_scores is deliberately ignored: internal scoring math is not shown.
  return {
    score: Math.round(score),
    verdict: data.verdict,
    attackType: cleanString_(data.attack_type, RESPONSE_LIMITS.SHORT_TEXT) || "Unknown",
    explanation: cleanString_(data.explanation, RESPONSE_LIMITS.LONG_TEXT),
    findings: cleanList_(data.findings, RESPONSE_LIMITS.FINDINGS, RESPONSE_LIMITS.ITEM_TEXT),
    recommendations: cleanList_(data.recommendations, RESPONSE_LIMITS.RECOMMENDATIONS, RESPONSE_LIMITS.ITEM_TEXT)
  };
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

/**
 * Visual style for each level. The score is a 0-100 risk score, not a
 * probability, so it is shown as "N/100", never as a percentage.
 */
function levelStyle_(level, score) {
  switch (level) {
    case "safe":
      return { banner: "🟢 SAFE", headerTitle: "🟢 Safe", color: THEME.SAFE };
    case "warning":
      return { banner: "⚠️ THREAT LEVEL: " + score + "/100", headerTitle: "⚠️ Suspicious email", color: THEME.WARNING };
    default:
      return { banner: "🚨 CRITICAL DANGER: " + score + "/100", headerTitle: "🚨 Dangerous email", color: THEME.DANGER };
  }
}

/** Neutral section heading in the brand color (inside a TextParagraph, so it can be styled). */
function heading_(text) {
  return CardService.newTextParagraph().setText(
    '<font color="' + THEME.BRAND + '"><b>' + escapeHtml_(text) + "</b></font>"
  );
}

function colored_(text, color, bold) {
  var inner = escapeHtml_(text);
  return '<font color="' + color + '">' + (bold ? "<b>" + inner + "</b>" : inner) + "</font>";
}

function buildResultCard_(result) {
  var level = VERDICT_LEVELS[result.verdict];
  var style = levelStyle_(level, result.score);
  var isSafe = level === "safe";

  // Card headers are plain text (no color), so the emoji carries the signal.
  var header = CardService.newCardHeader()
    .setTitle(style.headerTitle)
    .setSubtitle("MailGuard email security scan");

  // 1. The "blink test": one big colored line that answers "is this safe?".
  var banner = colored_(style.banner, style.color, true);
  if (!isSafe) {
    banner += "<br>" + colored_("Attack type: ", THEME.BRAND, true)
      + colored_(result.attackType, style.color, true);
  }
  var verdictSection = CardService.newCardSection()
    .addWidget(CardService.newTextParagraph().setText(banner));

  // 2. Why: the most important part for the user.
  var whySection = CardService.newCardSection()
    .addWidget(heading_(isSafe ? "Why is this considered safe?" : "Why is this dangerous?"))
    .addWidget(CardService.newTextParagraph().setText(
      escapeHtml_(result.explanation || "No explanation was provided.")
    ));

  // 3. Findings. Safe emails get a reassuring line, not an empty list.
  //    Minor notes on a safe email use ℹ️, not 🚩, so the card never
  //    shows red flags under a "SAFE" banner.
  var findingsSection = CardService.newCardSection();
  if (!result.findings.length) {
    findingsSection.addWidget(CardService.newTextParagraph().setText(
      colored_("🛡️ No suspicious links, attachments, or sender anomalies detected.", THEME.SAFE, true)
    ));
  } else {
    var marker = isSafe ? "ℹ️ " : "🚩 ";
    findingsSection.addWidget(heading_(isSafe
      ? "Minor notes (" + result.findings.length + ")"
      : "Red flags (" + result.findings.length + ")"));
    result.findings.forEach(function (finding) {
      findingsSection.addWidget(CardService.newTextParagraph().setText(marker + escapeHtml_(finding)));
    });
    // Heading + top 3 stay visible; the rest collapse behind "Show more".
    if (result.findings.length > 3) {
      findingsSection.setCollapsible(true).setNumUncollapsibleWidgets(4);
    }
  }

  // 4. Recommendations.
  var recsSection = CardService.newCardSection().addWidget(heading_("What should you do?"));
  (result.recommendations.length ? result.recommendations : ["No specific action required."])
    .forEach(function (rec) {
      recsSection.addWidget(CardService.newTextParagraph().setText("👉 " + escapeHtml_(rec)));
    });

  var footerSection = CardService.newCardSection().addWidget(
    CardService.newTextParagraph().setText(colored_(
      "Deterministic rule-based analysis. MailGuard does not store emails or visit links.",
      THEME.MUTED, false
    ))
  );

  return CardService.newCardBuilder()
    .setHeader(header)
    .addSection(verdictSection)
    .addSection(whySection)
    .addSection(findingsSection)
    .addSection(recsSection)
    .addSection(footerSection)
    .build();
}

function buildErrorCard_(message) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle("⚠️ Scan unavailable")
      .setSubtitle("MailGuard email security scan"))
    .addSection(CardService.newCardSection()
      .addWidget(CardService.newTextParagraph().setText(
        colored_("⚠️ This email could not be analyzed.", THEME.WARNING, true)
      ))
      .addWidget(CardService.newTextParagraph().setText(escapeHtml_(message)))
      .addWidget(heading_("What should you do?"))
      .addWidget(CardService.newTextParagraph().setText(
        "👉 Until it is scanned, treat unexpected links, attachments and requests with caution."
      ))
      .addWidget(CardService.newButtonSet().addButton(
        CardService.newTextButton()
          .setText("Try again")
          .setOnClickAction(CardService.newAction().setFunctionName("onRetry"))
      )))
    .build();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function safeString_(value) {
  return typeof value === "string" ? value : "";
}

function nullIfEmpty_(value) {
  return value ? value : null;
}

/** Truncate to maxLen characters without splitting a UTF-16 surrogate pair. */
function truncate_(value, maxLen) {
  var text = safeString_(value);
  if (text.length <= maxLen) return text;
  var cut = text.slice(0, maxLen);
  var last = cut.charCodeAt(cut.length - 1);
  if (last >= 0xD800 && last <= 0xDBFF) cut = cut.slice(0, -1);
  return cut;
}

function byteLength_(text) {
  return Utilities.newBlob(text).getBytes().length;
}

function cleanString_(value, maxLen) {
  return truncate_(safeString_(value).trim(), maxLen);
}

function cleanList_(value, maxItems, maxLen) {
  if (!Array.isArray(value)) return [];
  return value
    .filter(function (item) { return typeof item === "string" && item.trim(); })
    .slice(0, maxItems)
    .map(function (item) { return cleanString_(item, maxLen); });
}

/**
 * Card text widgets render a subset of HTML. Escape everything that comes
 * from the backend (and so possibly from the email), so text from an email
 * can never inject markup or a clickable link into the card.
 */
function escapeHtml_(text) {
  return safeString_(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Log only where it failed and the error type, never email content. */
function logError_(stage, err) {
  console.error("MailGuard: " + stage + " failed (" + (err && err.name ? err.name : "Error") + ")");
}
