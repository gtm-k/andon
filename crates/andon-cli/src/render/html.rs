//! The self-contained HTML report.
//!
//! # The design, and the one idea it is built on
//!
//! An andon is not a gauge. It is a board above a production line carrying one
//! lamp per station, each lamp either dark or lit, with a word beside it — and
//! the board never adds the stations up, because "the paint shop has stopped" is
//! not a number you average with "the press line is fine". That is the product's
//! own identity in physical form (PRE-DECISIONS non-goal 1: no composite score,
//! ever), so the report is drawn as the board.
//!
//! The station row is the signature element, and it is deliberately the place a
//! reader would most expect a headline figure. Instead each station shows its own
//! strongest band and its own count, side by side, with the refusal written under
//! them. Putting the refusal where the score would go is the point.
//!
//! # Severity is carried three ways, and colour is the least of them
//!
//! Every band appears as a **word** (`MED`), a **shape** (`=`), and a **chip
//! treatment** — outline below the MED+ band, filled at or above it. The
//! outline/filled split is not decoration: it draws the one boundary policy
//! actually acts on. Colour rides along on top and carries nothing on its own,
//! so the report reads identically in greyscale, in print, and to a reader who
//! cannot distinguish red from green.
//!
//! # Self-contained, and why that is a requirement rather than a preference
//!
//! No external stylesheet, no font file, no script, no image. A report is
//! attached to a review, emailed, and opened three weeks later on a machine with
//! no network — and a report that renders as unstyled text in those conditions is
//! a report nobody reads. Typefaces are system stacks, chosen so the condensed
//! signage face degrades to an ordinary sans rather than to a fallback that
//! breaks the layout.
//!
//! # Everything interpolated is escaped
//!
//! Paths, commit messages, engine failure reasons, and citation text all
//! originate in the repository under measurement, which is to say in input the
//! change being examined controls. A report that executed a path name would be a
//! tamper-detection tool with an injection hole in the artefact it hands to the
//! reviewer.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use andon_core::schema::enums::{Completeness, Severity};
use andon_core::schema::payload::{MeasurementRecord, MeasurementResult};

use crate::measure::{scope_label, value_label, Measurement};
use crate::render::{
    absences, attestation_line, completeness_note, findings, fired_flags, is_absence,
    severity_mark, severity_word, verdict_meaning, verdict_word,
};
use crate::resolve::{short, Substitution};

/// Render a fresh measurement as a complete HTML document.
pub fn render(measurement: &Measurement) -> String {
    document(
        &measurement.record,
        Some(&measurement.how),
        measurement.substitution.as_ref(),
        &measurement.excluded,
        &measurement.notices,
    )
}

/// Render a record read back from disk.
pub fn render_record(record: &MeasurementRecord) -> String {
    document(record, None, None, &[], &[])
}

fn document(
    record: &MeasurementRecord,
    how: Option<&str>,
    substitution: Option<&Substitution>,
    excluded: &[String],
    notices: &[String],
) -> String {
    let mut out = String::new();
    let verdict = record.verdict.verdict;
    let range = format!(
        "{} → {}",
        short(&record.compare_context.base_oid),
        short(&record.compare_context.head_oid)
    );

    let _ = write!(
        out,
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>Andon · {} · {}</title>\n<style>{}</style>\n</head>\n<body>\n",
        escape(verdict_word(verdict)),
        escape(&range),
        STYLE
    );

    masthead(&mut out, record, how, &range);
    lamp(&mut out, record);
    if let Some(substitution) = substitution {
        substitution_panel(&mut out, substitution);
    }
    station_board(&mut out, record);
    why(&mut out, record);
    flags(&mut out, record);
    finding_list(&mut out, record);
    absence_list(&mut out, record);
    trust(&mut out, record, excluded, notices);
    colophon(&mut out, record);

    let _ = writeln!(out, "</body>\n</html>");
    out
}

fn masthead(out: &mut String, record: &MeasurementRecord, how: Option<&str>, range: &str) {
    // `how` already contains the range when a measurement produced it, so
    // printing both would read the tuple twice with different punctuation. The
    // resolution alone is what a record read back from disk can offer.
    let engines: std::collections::BTreeSet<&str> = record
        .results
        .iter()
        .map(|r| r.engine_id.as_str())
        .collect();
    let _ = write!(
        out,
        "<header class=\"masthead\">\n\
           <div class=\"wordmark\"><span class=\"cord\" aria-hidden=\"true\"></span>ANDON</div>\n\
           <div class=\"masthead-meta\">\n\
             <span class=\"mono\">{}</span>\n\
             <span>{} engine(s) · {} result(s) · record {}</span>\n\
           </div>\n\
         </header>\n",
        escape(how.unwrap_or(range)),
        engines.len(),
        record.results.len(),
        escape(&format!("{:?}", record.completeness).to_lowercase()),
    );
}

fn lamp(out: &mut String, record: &MeasurementRecord) {
    let verdict = record.verdict.verdict;
    let tone = verdict_tone(verdict);
    let _ = write!(
        out,
        "<section class=\"lamp lamp-{tone}\">\n\
           <div class=\"lamp-face\" role=\"img\" aria-label=\"verdict: {word}\">\n\
             <span class=\"lamp-glyph\" aria-hidden=\"true\">{glyph}</span>\n\
             <span class=\"lamp-word\">{word}</span>\n\
           </div>\n\
           <p class=\"lamp-meaning\">{meaning}</p>\n\
         </section>\n",
        tone = tone,
        word = escape(verdict_word(verdict)),
        glyph = escape(verdict_glyph(verdict)),
        meaning = escape(verdict_meaning(verdict)),
    );
}

fn substitution_panel(out: &mut String, substitution: &Substitution) {
    let _ = write!(
        out,
        "<section class=\"panel notice\">\n\
           <h2 class=\"eyebrow\">This is not your working change</h2>\n\
           <dl class=\"pairs\">\n\
             <dt>Asked for</dt><dd>{asked}</dd>\n\
             <dt>Measured</dt><dd>{measured}</dd>\n\
           </dl>\n\
           <p class=\"muted\">{because}</p>\n\
         </section>\n",
        asked = escape(&substitution.asked_for),
        measured = escape(&substitution.measured),
        because = escape(&substitution.because),
    );
}

/// The signature element: one station per engine, and the refusal underneath.
fn station_board(out: &mut String, record: &MeasurementRecord) {
    let mut stations: BTreeMap<&str, (Severity, usize, usize)> = BTreeMap::new();
    for result in &record.results {
        let entry = stations
            .entry(result.engine_id.as_str())
            .or_insert((Severity::Info, 0, 0));
        entry.0 = entry.0.max(result.severity);
        if is_absence(result) {
            entry.2 += 1;
        } else {
            entry.1 += 1;
        }
    }

    let _ = write!(
        out,
        "<section class=\"board\">\n<h2 class=\"eyebrow\">Stations</h2>\n<div class=\"stations\">\n"
    );
    for (engine_id, (worst, measured, absent)) in &stations {
        let _ = write!(
            out,
            "<article class=\"station\">\n\
               <h3 class=\"station-name\">{name}</h3>\n\
               {chip}\n\
               <p class=\"station-counts\">{measured} measured{absent_part}</p>\n\
             </article>\n",
            name = escape(engine_id),
            chip = chip(*worst),
            measured = measured,
            absent_part = if *absent > 0 {
                format!(" · {absent} not measured")
            } else {
                String::new()
            },
        );
    }
    let _ = write!(
        out,
        "</div>\n<p class=\"board-note\">Each station reports its own strongest finding. \
         They are not added together, weighted, or ranked into a figure — there is no score in \
         this tool and there is not going to be one. A verdict is one of four words, and it is \
         at the top of this page.</p>\n</section>\n"
    );
}

fn why(out: &mut String, record: &MeasurementRecord) {
    if record.verdict.reasons.is_empty() {
        return;
    }
    let _ = write!(
        out,
        "<section class=\"panel\">\n<h2 class=\"eyebrow\">Why</h2>\n<ul class=\"reasons\">\n"
    );
    for reason in &record.verdict.reasons {
        let _ = write!(
            out,
            "<li class=\"reason\">\n{chip}\n<div>\n<p class=\"reason-code mono\">{code}</p>\n\
             <p>{message}</p>\n{metrics}</div>\n</li>\n",
            chip = chip(reason.severity),
            code = escape(&reason.code),
            message = escape(&reason.message),
            metrics = if reason.metric_ids.is_empty() {
                String::new()
            } else {
                format!(
                    "<p class=\"muted mono small\">{}</p>\n",
                    escape(&reason.metric_ids.join(", "))
                )
            },
        );
    }
    let _ = writeln!(out, "</ul>\n</section>");
}

fn flags(out: &mut String, record: &MeasurementRecord) {
    let fired = fired_flags(record);
    if fired.is_empty() {
        return;
    }
    let _ = write!(
        out,
        "<section class=\"panel\">\n<h2 class=\"eyebrow\">Tamper signals that fired</h2>\n\
         <p class=\"muted\">A detector found a pattern that moves a number for a reason other \
         than the code getting better. A firing on a partial view is still a firing; the \
         severity beside it is capped, the finding is not.</p>\n<ul class=\"reasons\">\n"
    );
    for result in fired {
        let _ = write!(
            out,
            "<li class=\"reason\">\n{chip}\n<div>\n<p class=\"reason-code mono\">{metric}</p>\n\
             <p class=\"muted small\">{scope}</p>\n</div>\n</li>\n",
            chip = chip(result.severity),
            metric = escape(&result.metric_id),
            scope = escape(&scope_label(result)),
        );
    }
    let _ = writeln!(out, "</ul>\n</section>");
}

fn finding_list(out: &mut String, record: &MeasurementRecord) {
    let all = findings(record);
    let _ = write!(
        out,
        "<section class=\"panel\">\n<h2 class=\"eyebrow\">Findings</h2>\n"
    );
    if all.is_empty() {
        let _ = write!(
            out,
            "<p class=\"muted\">Nothing was measured on this change. The stations above say \
             which engines ran.</p>\n</section>\n"
        );
        return;
    }
    let _ = writeln!(
        out,
        "<p class=\"muted\">Worst first. This is a sort, not a score.</p>"
    );
    for result in all {
        finding(out, result);
    }
    let _ = writeln!(out, "</section>");
}

fn finding(out: &mut String, result: &MeasurementResult) {
    let delta = result
        .delta
        .as_ref()
        .map(|d| {
            format!(
                "<span class=\"delta mono\">Δ {}</span>",
                escape(&value_label(d))
            )
        })
        .unwrap_or_default();

    let _ = write!(
        out,
        "<article class=\"finding\">\n\
           <div class=\"finding-head\">\n{chip}\n\
             <div class=\"finding-id\">\n<p class=\"metric mono\">{metric}</p>\n\
             <p class=\"scope muted small\">{scope}</p>\n</div>\n\
             <p class=\"value mono\">{value}{delta}</p>\n\
           </div>\n",
        chip = chip(result.severity),
        metric = escape(&result.metric_id),
        scope = escape(&scope_label(result)),
        value = escape(&value_label(&result.value)),
        delta = delta,
    );

    // The evidence block. It is the reason this tool exists, so it is part of
    // every finding rather than a footnote a reader has to go and find.
    let _ = write!(
        out,
        "<div class=\"evidence\">\n\
           <dl class=\"pairs\">\n\
             <dt>Evidence</dt><dd>tier {tier}{stale} · {citation}</dd>\n\
             <dt>Claim</dt><dd class=\"mono small\">{claim}</dd>\n\
             <dt>Actionable</dt><dd>{class}</dd>\n\
           </dl>\n",
        tier = escape(&format!("{:?}", result.evidence.tier)),
        stale = if result.evidence.stale {
            " · <strong>stale</strong>, past its re-review date"
        } else {
            ""
        },
        citation = escape(&result.evidence.citation),
        claim = escape(&result.evidence.claim_id),
        class = match result.metric_class {
            andon_core::schema::enums::MetricClass::DiffActionable =>
                "yes — fixable inside this change",
            andon_core::schema::enums::MetricClass::ContextInformational =>
                "no — true and worth knowing, about the surrounding code. Never blocks.",
        },
    );

    if !result.evidence.does_not_predict.is_empty() {
        let _ = write!(
            out,
            "<p class=\"eyebrow small\">What this number does not tell you</p>\n<ul class=\"nots\">\n"
        );
        for line in &result.evidence.does_not_predict {
            let _ = writeln!(out, "<li>{}</li>", escape(line));
        }
        let _ = writeln!(out, "</ul>");
    }

    if result.completeness != Completeness::Complete {
        let _ = writeln!(
            out,
            "<p class=\"caveat\"><span class=\"mono\">{state}</span> — {note}</p>",
            state = escape(&format!("{:?}", result.completeness).to_lowercase()),
            note = escape(completeness_note(result.completeness)),
        );
    }
    let _ = writeln!(out, "</div>\n</article>");
}

fn absence_list(out: &mut String, record: &MeasurementRecord) {
    let absent = absences(record);
    if absent.is_empty() {
        return;
    }
    let _ = write!(
        out,
        "<section class=\"panel\">\n<h2 class=\"eyebrow\">Not measured</h2>\n\
         <p class=\"muted\">There is no number for these, and the reason is beside each one. \
         An absence is never reported as a zero: a file with no history has no churn, and a \
         zero would say it had never changed.</p>\n\
         <div class=\"scroll\"><table>\n\
         <thead><tr><th>Metric</th><th>Scope</th><th>Why there is no number</th></tr></thead>\n\
         <tbody>\n"
    );
    for result in absent {
        let _ = writeln!(
            out,
            "<tr><td class=\"mono small\">{metric}</td><td class=\"mono small\">{scope}</td>\
             <td>{why}</td></tr>",
            metric = escape(&result.metric_id),
            scope = escape(&scope_label(result)),
            why = escape(&value_label(&result.value)),
        );
    }
    let _ = writeln!(out, "</tbody>\n</table></div>\n</section>");
}

fn trust(out: &mut String, record: &MeasurementRecord, excluded: &[String], notices: &[String]) {
    let _ = write!(
        out,
        "<section class=\"panel\">\n<h2 class=\"eyebrow\">Trust</h2>\n\
           <dl class=\"pairs\">\n\
             <dt>Attestation</dt><dd>{attestation}</dd>\n\
             <dt>Record</dt><dd>{kind}, completeness <span class=\"mono\">{completeness}</span></dd>\n\
             <dt>Measured by</dt><dd class=\"mono small\">{tool} {version} (build {build}){attested}</dd>\n\
             <dt>Base</dt><dd class=\"mono small\">{base} · resolved as {resolution}</dd>\n\
             <dt>Head</dt><dd class=\"mono small\">{head}</dd>\n\
             <dt>git</dt><dd class=\"mono small\">{git}</dd>\n\
             <dt>Policy digest</dt><dd class=\"mono small\">{policy}</dd>\n\
           </dl>\n",
        attestation = escape(attestation_line(record.attestation.value)),
        kind = escape(&format!("{:?}", record.record_kind).to_lowercase()),
        completeness = escape(&format!("{:?}", record.completeness).to_lowercase()),
        tool = escape(&record.tool.name),
        version = escape(&record.tool.version),
        build = escape(&short(&record.tool.build_oid)),
        attested = if record.tool.attested_release {
            ""
        } else {
            " — not an attested release, so this measurement is provisional"
        },
        base = escape(&record.compare_context.base_oid),
        resolution = escape(&record.compare_context.base_resolution),
        head = escape(&record.compare_context.head_oid),
        git = escape(&record.compare_context.git_version),
        policy = escape(&short(&record.policy_hash)),
    );

    if !excluded.is_empty() {
        let _ = write!(
            out,
            "<p class=\"caveat\">{n} path(s) were withheld by <span class=\"mono\">\
             [self_measure] excluded_paths</span>: <span class=\"mono small\">{paths}</span></p>",
            n = excluded.len(),
            paths = escape(&excluded.join(", ")),
        );
    }
    for notice in notices {
        let _ = writeln!(out, "<p class=\"caveat\">{}</p>", escape(notice));
    }
    let _ = writeln!(out, "</section>");
}

fn colophon(out: &mut String, record: &MeasurementRecord) {
    let _ = write!(
        out,
        "<footer class=\"colophon\">\n\
           <p>Payload schema v{schema}. Every number on this page names the claim it stands \
           on; <span class=\"mono\">andon explain &lt;metric-id&gt;</span> prints the claim in \
           full, including what it does not predict.</p>\n\
         </footer>\n",
        schema = record.schema_version,
    );
}

/// A severity chip: word, shape, and a treatment that draws the MED+ boundary.
fn chip(severity: Severity) -> String {
    let filled = if severity.is_med_plus() {
        "filled"
    } else {
        "hollow"
    };
    format!(
        "<span class=\"chip chip-{tone} chip-{filled}\">\
           <span class=\"chip-mark\" aria-hidden=\"true\">{mark}</span>{word}</span>",
        tone = severity_tone(severity),
        filled = filled,
        mark = escape(severity_mark(severity)),
        word = escape(severity_word(severity)),
    )
}

fn severity_tone(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "med",
        Severity::High => "high",
        Severity::Critical => "crit",
    }
}

fn verdict_tone(verdict: andon_core::schema::enums::Verdict) -> &'static str {
    use andon_core::schema::enums::Verdict;
    match verdict {
        Verdict::Pass => "pass",
        Verdict::Advise => "advise",
        Verdict::Block => "block",
        Verdict::EscalateToHuman => "escalate",
    }
}

/// A shape per verdict, so the lamp is not read by colour alone.
fn verdict_glyph(verdict: andon_core::schema::enums::Verdict) -> &'static str {
    use andon_core::schema::enums::Verdict;
    match verdict {
        Verdict::Pass => "●",
        Verdict::Advise => "◐",
        Verdict::Block => "■",
        Verdict::EscalateToHuman => "▲",
    }
}

/// HTML-escape text that came from the repository under measurement.
///
/// Single quotes are escaped along with double, because the same helper is used
/// for attribute values, and an attribute delimiter that is safe in one context
/// and not the other is a hole waiting for the next attribute this file grows.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// The whole stylesheet. Inline because the report has to survive being one file.
const STYLE: &str = r#"
:root {
  color-scheme: light dark;
  --ground: #f1f3f1;
  --panel: #ffffff;
  --ink: #16191a;
  --ink-muted: #59615f;
  --rule: #d7dbd8;
  --rule-strong: #b6bdb9;
  --cord: #e8a200;
  --pass: #1f7a4c;
  --advise: #0f6e8c;
  --med: #9c6408;
  --high: #b8420b;
  --crit: #a91616;
  --shadow: 0 1px 0 rgba(22,25,26,.06), 0 8px 24px -18px rgba(22,25,26,.5);
  --font-display: "Roboto Condensed","Liberation Sans Narrow","Arial Narrow",
                  "Helvetica Neue",ui-sans-serif,system-ui,sans-serif;
  --font-body: ui-sans-serif,system-ui,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  --font-mono: ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ground: #121514;
    --panel: #1a1f1d;
    --ink: #e9edeb;
    --ink-muted: #9aa4a1;
    --rule: #2c3331;
    --rule-strong: #414a47;
    --cord: #f0b429;
    --pass: #4cc38a;
    --advise: #4bb3d4;
    --med: #e0a331;
    --high: #f08150;
    --crit: #ff6b6b;
    --shadow: 0 1px 0 rgba(0,0,0,.4), 0 8px 24px -18px #000;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--ground);
  color: var(--ink);
  font-family: var(--font-body);
  font-size: 16px;
  line-height: 1.55;
  -webkit-text-size-adjust: 100%;
}
.mono { font-family: var(--font-mono); font-size: .92em; }
.small { font-size: .85rem; }
.muted { color: var(--ink-muted); }
.eyebrow {
  font-family: var(--font-display);
  text-transform: uppercase;
  letter-spacing: .14em;
  font-size: .78rem;
  font-weight: 700;
  color: var(--ink-muted);
  margin: 0 0 .75rem;
}

/* ---- masthead: the cord runs across the top ------------------------------ */
.masthead {
  display: flex; flex-wrap: wrap; gap: .75rem 1.5rem;
  align-items: baseline; justify-content: space-between;
  max-width: 62rem; margin: 0 auto; padding: 2rem 1.5rem 1rem;
}
.wordmark {
  font-family: var(--font-display);
  font-weight: 700; font-size: 1.5rem;
  letter-spacing: .28em; text-transform: uppercase;
  display: flex; align-items: center; gap: .6rem;
}
.cord {
  display: inline-block; width: 4px; height: 1.5rem;
  background: var(--cord); border-radius: 2px;
}
.masthead-meta {
  display: flex; flex-wrap: wrap; gap: .35rem 1.25rem;
  color: var(--ink-muted); font-size: .9rem;
}
.masthead::after {
  content: ""; flex-basis: 100%; height: 2px;
  background: linear-gradient(90deg, var(--cord) 0 4rem, var(--rule) 4rem);
  margin-top: .75rem;
}

/* ---- the lamp ------------------------------------------------------------ */
.lamp { max-width: 62rem; margin: 0 auto; padding: 2rem 1.5rem 1rem; }
.lamp-face {
  display: inline-flex; align-items: center; gap: 1rem;
  padding: 1rem 1.75rem;
  border: 2px solid currentColor;
  border-radius: 4px;
  font-family: var(--font-display);
  animation: lamp-on .32s ease-out both;
}
.lamp-glyph { font-size: 1.5rem; line-height: 1; }
.lamp-word {
  font-size: clamp(1.75rem, 6vw, 2.75rem);
  font-weight: 700; letter-spacing: .1em; text-transform: uppercase;
}
.lamp-meaning { margin: 1rem 0 0; max-width: 44rem; font-size: 1.05rem; }
.lamp-pass .lamp-face { color: var(--pass); }
.lamp-advise .lamp-face { color: var(--advise); }
.lamp-block .lamp-face { color: var(--crit); border-style: double; border-width: 5px; }
.lamp-escalate .lamp-face { color: var(--high); border-style: dashed; }
@keyframes lamp-on { from { opacity: .25; } to { opacity: 1; } }
@media (prefers-reduced-motion: reduce) {
  .lamp-face { animation: none; }
}

/* ---- the station board: the signature -------------------------------------
   One card per engine. No card knows about any other, which is the point. */
.board { max-width: 62rem; margin: 0 auto; padding: 1.5rem 1.5rem 0; }
.stations {
  display: grid; gap: .75rem;
  grid-template-columns: repeat(auto-fit, minmax(9.5rem, 1fr));
}
.station {
  background: var(--panel);
  border: 1px solid var(--rule);
  border-top: 3px solid var(--rule-strong);
  border-radius: 3px;
  padding: .9rem 1rem;
  box-shadow: var(--shadow);
}
.station-name {
  font-family: var(--font-display); text-transform: uppercase;
  letter-spacing: .1em; font-size: .82rem; font-weight: 700;
  margin: 0 0 .6rem;
}
.station-counts { margin: .6rem 0 0; font-size: .82rem; color: var(--ink-muted); }
.board-note {
  max-width: 44rem; margin: 1rem 0 0;
  font-size: .9rem; color: var(--ink-muted);
  border-left: 3px solid var(--cord); padding-left: .9rem;
}

/* ---- panels -------------------------------------------------------------- */
.panel {
  max-width: 62rem; margin: 1.5rem auto 0; padding: 1.5rem;
  background: var(--panel);
  border: 1px solid var(--rule); border-radius: 3px;
  box-shadow: var(--shadow);
}
.notice { border-left: 4px solid var(--cord); }
.panel > p:last-child { margin-bottom: 0; }

.pairs { display: grid; grid-template-columns: max-content 1fr; gap: .35rem 1.25rem; margin: 0; }
.pairs dt {
  font-family: var(--font-display); text-transform: uppercase;
  letter-spacing: .08em; font-size: .76rem; font-weight: 700;
  color: var(--ink-muted); padding-top: .15rem;
}
.pairs dd { margin: 0; overflow-wrap: anywhere; }
@media (max-width: 34rem) {
  .pairs { grid-template-columns: 1fr; gap: .1rem; }
  .pairs dd { margin-bottom: .5rem; }
}

/* ---- severity chips: word + shape + treatment ---------------------------- */
.chip {
  display: inline-flex; align-items: center; gap: .35rem;
  font-family: var(--font-display); font-weight: 700;
  text-transform: uppercase; letter-spacing: .08em; font-size: .74rem;
  padding: .15rem .55rem; border-radius: 2px; white-space: nowrap;
  border: 1.5px solid currentColor;
}
.chip-mark { font-family: var(--font-mono); letter-spacing: 0; }
.chip-hollow { background: transparent; }
.chip-filled { color: var(--panel) !important; }
.chip-info { color: var(--ink-muted); border-style: dotted; }
.chip-low { color: var(--advise); border-style: dashed; }
.chip-med.chip-filled { background: var(--med); border-color: var(--med); }
.chip-high.chip-filled { background: var(--high); border-color: var(--high); }
.chip-crit.chip-filled { background: var(--crit); border-color: var(--crit); border-style: double; border-width: 4px; }

/* ---- reasons ------------------------------------------------------------- */
.reasons { list-style: none; margin: 0; padding: 0; }
.reason {
  display: flex; gap: .9rem; align-items: flex-start;
  padding: .75rem 0; border-top: 1px solid var(--rule);
}
.reason:first-child { border-top: 0; padding-top: 0; }
.reason p { margin: 0 0 .2rem; }
.reason-code { font-weight: 600; }

/* ---- findings ------------------------------------------------------------ */
.finding { border-top: 1px solid var(--rule); padding: 1rem 0 .25rem; }
.finding-head {
  display: flex; flex-wrap: wrap; gap: .5rem .9rem; align-items: baseline;
}
.finding-id { flex: 1 1 16rem; min-width: 0; }
.metric { margin: 0; font-weight: 600; overflow-wrap: anywhere; }
.scope { margin: 0; overflow-wrap: anywhere; }
.value { margin: 0; font-size: 1.15rem; font-weight: 700; }
.delta { margin-left: .6rem; font-size: .85rem; font-weight: 400; color: var(--ink-muted); }
.evidence {
  margin: .75rem 0 0; padding: .85rem 1rem;
  background: var(--ground); border-radius: 3px;
  border-left: 3px solid var(--rule-strong);
  font-size: .9rem;
}
.evidence .eyebrow { margin: .8rem 0 .35rem; }
.nots { margin: 0; padding-left: 1.1rem; }
.nots li { margin-bottom: .2rem; }
.caveat {
  margin: .75rem 0 0; padding-left: .9rem;
  border-left: 3px solid var(--cord);
  font-size: .9rem; color: var(--ink-muted);
}

/* ---- tables -------------------------------------------------------------- */
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: .9rem; }
th, td { text-align: left; padding: .5rem .75rem .5rem 0; border-bottom: 1px solid var(--rule); vertical-align: top; }
th {
  font-family: var(--font-display); text-transform: uppercase;
  letter-spacing: .08em; font-size: .74rem; color: var(--ink-muted);
}

/* ---- colophon ------------------------------------------------------------ */
.colophon {
  max-width: 62rem; margin: 2rem auto 0; padding: 1.25rem 1.5rem 3rem;
  border-top: 1px solid var(--rule);
  color: var(--ink-muted); font-size: .85rem;
}
.colophon p { margin: 0; }

@media print {
  body { background: #fff; color: #000; }
  .panel, .station { box-shadow: none; border-color: #999; }
  .lamp-face { animation: none; }
}
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repository_controlled_text_cannot_carry_markup_into_the_report() {
        // Paths and citation strings come from the change under measurement.
        // This is a tamper-detection tool; an injection hole in the artefact it
        // hands the reviewer would be the joke writing itself.
        let hostile = "<script>alert('x')</script>\"&";
        let escaped = escape(hostile);
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(!escaped.contains('"'));
        assert!(!escaped.contains('\''));
        assert!(escaped.contains("&lt;script&gt;"));
        assert!(escaped.contains("&amp;"));
    }

    #[test]
    fn the_med_plus_boundary_is_drawn_by_the_chip_treatment_and_not_by_colour() {
        for severity in [Severity::Info, Severity::Low] {
            assert!(chip(severity).contains("chip-hollow"), "{severity:?}");
        }
        for severity in [Severity::Medium, Severity::High, Severity::Critical] {
            assert!(chip(severity).contains("chip-filled"), "{severity:?}");
        }
    }

    #[test]
    fn every_chip_carries_its_band_as_text() {
        // Colour and shape are the accents; the word is the fact. A reader with
        // images off, in greyscale, or using a screen reader gets the band.
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            assert!(
                chip(severity).contains(severity_word(severity)),
                "{severity:?}"
            );
        }
    }
}
