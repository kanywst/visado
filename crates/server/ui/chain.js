// visado chain view. Plain DOM, no dependencies. Every value from the API is
// written with textContent, never as markup.
"use strict";

(function () {
  const POLL_MS = 2000;
  const LIMIT = 200;

  const list = document.getElementById("requests");
  const empty = document.getElementById("empty");
  const detail = document.getElementById("detail");
  const status = document.getElementById("status");
  const live = document.getElementById("live");
  const filter = document.getElementById("filter");

  let requests = [];
  let selected = decodeURIComponent(location.hash.slice(1)) || null;
  let pinned = null; // a selected entry that is no longer in the list
  let timer = null;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function clock(seconds) {
    return new Date(seconds * 1000).toLocaleTimeString([], { hour12: false });
  }

  function short(text, keep) {
    if (!text) return text;
    return text.length > keep ? text.slice(0, keep) + "…" : text;
  }

  // ---- list ----

  function renderList() {
    const shown = requests.filter(
      (r) => filter.value === "all" || r.decision === filter.value,
    );
    list.replaceChildren(...shown.map(listItem));
    empty.hidden = shown.length > 0;
  }

  function listItem(r) {
    const li = el("li");
    li.tabIndex = 0;
    li.setAttribute("aria-selected", String(r.id === selected));
    li.append(
      el("span", "badge " + r.decision, r.decision === "allow" ? "allow" : r.status),
      lineWith(el("span", "when", clock(r.time)), " ", el("span", "what", r.method + " " + path(r.resource))),
      el("span", "who", (r.caller || "unauthenticated") + (r.decision === "deny" ? " · " + r.code : "")),
    );
    li.addEventListener("click", () => select(r.id));
    li.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        select(r.id);
      }
    });
    return li;
  }

  function lineWith(...parts) {
    const span = el("span", "what");
    span.append(...parts);
    return span;
  }

  function path(resource) {
    try {
      return new URL(resource).pathname;
    } catch (_) {
      return resource;
    }
  }

  // ---- detail ----

  function select(id) {
    selected = id;
    pinned = null;
    history.replaceState(null, "", "#" + encodeURIComponent(id));
    renderList();
    renderDetail();
  }

  async function renderDetail() {
    if (!selected) return;
    let r = requests.find((x) => x.id === selected) || pinned;
    if (!r) {
      try {
        const res = await fetch("/api/requests/" + encodeURIComponent(selected), {
          headers: { accept: "application/json" },
        });
        if (res.ok) r = pinned = await res.json();
      } catch (_) {
        // shown below
      }
    }
    if (!r) {
      detail.replaceChildren(el("p", "empty", "That decision is no longer kept."));
      return;
    }
    detail.replaceChildren(summary(r), flow(r), facts(r));
  }

  function summary(r) {
    const box = el("div", "summary");
    const h2 = el("h2");
    h2.append(el("span", "badge " + r.decision, r.decision), el("code", null, r.code));
    if (r.decision === "deny") h2.append(el("span", "meta", "HTTP " + r.status));
    box.append(h2, el("p", "resource", r.method + " " + r.resource));
    return box;
  }

  function node(kind, value, meta, state) {
    const n = el("div", "node" + (state ? " " + state : ""));
    n.append(el("div", "kind", kind), el("div", "value", value));
    for (const m of [].concat(meta || [])) if (m) n.append(el("div", "meta", m));
    return n;
  }

  function edge(state, label) {
    const e = el("div", "edge" + (state ? " " + state : ""));
    e.setAttribute("aria-hidden", "true");
    e.append(el("span", "line"), el("span", "label", label || ""));
    return e;
  }

  function actorMeta(hop) {
    const meta = [];
    if (hop.actor_issuer) meta.push("issuer " + hop.actor_issuer);
    if (hop.holder && hop.actor_kind !== "key") meta.push("holder jkt " + short(hop.holder, 16));
    return meta;
  }

  function flow(r) {
    const f = el("div", "flow");
    f.setAttribute("role", "list");
    const chain = r.chain;
    const authenticated = Boolean(r.caller);
    const pdpAsked = Boolean(r.pdp);

    // Principal
    const principal = (chain && chain.principal) || r.principal;
    f.append(
      node(
        "principal",
        principal || (authenticated ? "the caller itself" : "unknown"),
        chain && !chain.principal ? "not named by " + chain.profile : null,
        principal ? null : "skipped",
      ),
    );

    // Hops
    if (chain) {
      chain.hops.forEach((hop, i) => {
        f.append(edge(hop.assurance, i === 0 ? "delegates" : hop.link.replace("_", " ")));
        f.append(
          node(
            "hop " + hop.depth + " · " + hop.assurance,
            hop.actor_kind === "key" ? "jkt " + short(hop.actor, 22) : hop.actor,
            actorMeta(hop),
            hop.assurance,
          ),
        );
      });
      if (chain.hops_omitted > 0) {
        f.append(edge("skipped", ""), node("hops", "+" + chain.hops_omitted + " more", "not kept", "skipped"));
      }
      f.append(edge(chain.holder_proof ? "verified" : "declared", chain.holder_proof ? "holder proof" : "no holder proof"));
    } else {
      f.append(edge(authenticated ? "verified" : "skipped", authenticated ? "no chain" : ""));
    }

    // Caller
    f.append(
      node(
        "caller",
        r.caller || "not authenticated",
        r.auth_method,
        authenticated ? "verified" : "deny",
      ),
    );

    // PDP
    f.append(edge(pdpAsked ? "verified" : "skipped", "AuthZEN"));
    let pdpState = "skipped";
    let pdpValue = "not asked";
    if (r.pdp) {
      pdpValue = r.pdp.result === "error" ? "error: " + r.pdp.code : r.pdp.result;
      pdpState = r.pdp.result === "allow" ? "allow" : "deny";
    }
    f.append(node("policy decision", pdpValue, null, pdpState));

    // Decision
    f.append(edge(r.decision === "allow" ? "verified" : "deny", r.decision === "allow" ? "Txn-Token" : ""));
    f.append(
      node(
        "decision",
        r.decision === "allow" ? "allow" : r.code,
        r.decision === "allow" ? "txn " + short(r.txn, 13) : "HTTP " + r.status,
        r.decision,
      ),
    );
    return f;
  }

  function facts(r) {
    const dl = el("dl", "facts");
    const add = (k, v) => {
      if (v === null || v === undefined || v === "") return;
      dl.append(el("dt", null, k), el("dd", null, v));
    };
    add("time", new Date(r.time * 1000).toISOString());
    add("check id", r.id);
    add("transaction", r.txn);
    add("caller", r.caller);
    add("auth method", r.auth_method);
    add("principal", r.principal);
    if (r.chain) {
      add("chain profile", r.chain.profile);
      add("chain issuer", r.chain.issuer);
      add("holder proof", r.chain.holder_proof ? "yes" : "no");
      r.chain.hops.forEach((hop) => {
        add("hop " + hop.depth, hop.actor_kind + " " + hop.actor + (hop.holder ? " · holder " + hop.holder : ""));
      });
    }
    return dl;
  }

  // ---- polling ----

  async function poll() {
    try {
      const res = await fetch("/api/requests?limit=" + LIMIT, {
        headers: { accept: "application/json" },
      });
      if (!res.ok) throw new Error("HTTP " + res.status);
      const body = await res.json();
      requests = body.requests;
      status.className = "status";
      status.textContent =
        requests.length + " of the last " + body.capacity + " kept · " + clock(Date.now() / 1000);
      if (!selected && requests.length) selected = requests[0].id;
      renderList();
      renderDetail();
    } catch (e) {
      status.className = "status error";
      status.textContent = "cannot reach visado: " + e.message;
    }
  }

  function setLive(on) {
    live.setAttribute("aria-pressed", String(on));
    live.textContent = on ? "Live" : "Paused";
    clearInterval(timer);
    timer = on ? setInterval(poll, POLL_MS) : null;
    if (on) poll();
  }

  live.addEventListener("click", () => setLive(live.getAttribute("aria-pressed") !== "true"));
  filter.addEventListener("change", renderList);
  window.addEventListener("hashchange", () => {
    const id = decodeURIComponent(location.hash.slice(1));
    if (id && id !== selected) select(id);
  });

  setLive(true);
})();
