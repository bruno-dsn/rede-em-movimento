import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { JSDOM } from "jsdom";
import { createApp } from "../app.js";
import { makeNotebook, NOTE_FIELDS } from "../core.js";

const html = await readFile(new URL("../estudos.html", import.meta.url), "utf8");
const flush = () => new Promise((resolve) => setImmediate(resolve));
async function fixture(route = "inicio") {
  const dom = new JSDOM(html, {
    url: "https://netguard.test/#" + route,
    pretendToBeVisual: true,
  });
  dom.window.scrollTo = () => {};
  dom.window.matchMedia = () => ({ matches: false });
  const requests = [];
  const fetch = async (path) => {
    requests.push(path);
    assert.ok(/^data\/[a-z0-9.-]+$/.test(path));
    return new Response(await readFile(new URL("../" + path, import.meta.url)));
  };
  const app = await createApp(dom.window.document, { fetch });
  const doc = dom.window.document;
  const change = (id, value) => {
    const input = doc.getElementById(id);
    if (input.type === "checkbox") input.checked = value;
    else input.value = value;
    input.dispatchEvent(new dom.window.Event("change", { bubbles: true }));
  };
  const input = (id, value) => {
    const target = doc.getElementById(id);
    target.value = value;
    target.dispatchEvent(new dom.window.Event("input", { bubbles: true }));
  };
  const click = (action, value) => {
    const target = [...doc.querySelectorAll("[data-action]")].find(
      (el) =>
        el.dataset.action === action &&
        (value === undefined || el.dataset.value === value),
    );
    assert.ok(target, `action ${action} ${value ?? ""}`);
    target.click();
  };
  const upload = async (id, name, source) => {
    const bytes = new TextEncoder().encode(source),
      target = doc.getElementById(id);
    Object.defineProperty(target, "files", {
      configurable: true,
      value: [
        { name, size: bytes.length, arrayBuffer: async () => bytes.buffer },
      ],
    });
    target.dispatchEvent(new dom.window.Event("change", { bubbles: true }));
    const deadline = Date.now() + 5000;
    do {
      await new Promise((resolve) => setTimeout(resolve, 5));
    } while (app.state.busy && Date.now() < deadline);
    assert.equal(app.state.busy, false);
  };
  const routeTo = (route) => {
    app.state.route = route;
    app.render();
  };
  const close = () => {
    app.destroy();
    dom.window.close();
  };
  return {
    app,
    doc,
    dom,
    requests,
    change,
    input,
    click,
    upload,
    routeTo,
    close,
  };
}

test("all eight workspaces render substantive content and labeled inputs", async () => {
  const f = await fixture();
  try {
    for (const route of [
      "inicio",
      "aprender",
      "investigar",
      "metodo",
      "diagnostico",
      "inventario",
      "redes",
      "plano",
    ]) {
      f.routeTo(route);
      assert.equal(f.doc.querySelectorAll("main h1").length, 1);
      assert.ok(f.doc.getElementById("main").textContent.length > 400);
      for (const input of f.doc.querySelectorAll(
        "main input:not([type=hidden]),main textarea,main select",
      ))
        assert.ok(
          [...f.doc.querySelectorAll("label")].some(
            (l) => l.htmlFor === input.id,
          ),
          `label for ${input.id}`,
        );
    }
    assert.equal(f.requests.length, 7);
    assert.equal(f.doc.querySelectorAll("script:not([src])").length, 0);
  } finally {
    f.close();
  }
});
test("learning steps and decoder change the explanation, retaining a clear limit", async () => {
  const f = await fixture("aprender");
  try {
    f.click("field", "ip");
    assert.match(f.doc.querySelector(".field-explainer").textContent, /VPN/);
    f.click("learn-next");
    assert.equal(f.app.state.learnStep, 1);
    assert.match(f.doc.querySelector("main").textContent, /E002/);
    f.click("learn-next");
    f.click("learn-next");
    assert.equal(f.app.state.learnStep, 3);
    assert.ok(f.doc.querySelector('a[href="#investigar"]'));
  } finally {
    f.close();
  }
});
test("case switching preserves each notebook and recomputes signals", async () => {
  const f = await fixture("investigar");
  try {
    f.click("tab", "notebook");
    f.input("note-observacoes", "E008: confirmar autorização.");
    f.change("case-select", "benigno");
    assert.equal(f.app.result.signal_count, 1);
    assert.equal(f.doc.getElementById("note-observacoes").value, "");
    f.input("note-observacoes", "Senha esquecida, verificar contexto.");
    f.change("case-select", "financeiro");
    assert.equal(f.app.result.signal_count, 7);
    assert.equal(
      f.doc.getElementById("note-observacoes").value,
      "E008: confirmar autorização.",
    );
    f.change("shared", false);
    assert.equal(f.app.result.signal_count, 5);
    f.change("case-select", "benigno");
    f.change("case-select", "arquivo");
    f.click("tab", "intro");
    assert.match(
      f.doc.querySelector("main").textContent,
      /A pessoa esqueceu a senha/,
    );
    assert.ok(
      !f.doc
        .querySelector("main")
        .textContent.includes("A equipe da Loja Aurora relata"),
    );
  } finally {
    f.close();
  }
});
test("filters, stepper and evidence links select the actual event", async () => {
  const f = await fixture("investigar");
  try {
    f.change("source-filter", "financeiro");
    assert.equal(f.doc.querySelectorAll(".event-row").length, 3);
    f.input("search", "E011");
    assert.equal(f.doc.querySelectorAll(".event-row").length, 1);
    f.click("select-event", "E011");
    assert.match(f.doc.querySelector(".event-detail").textContent, /E011/);
    f.click("tab", "signals");
    f.click("evidence", "E008");
    assert.equal(f.app.state.tab, "timeline");
    assert.equal(f.app.result.events[f.app.state.selected].event_id, "E008");
    assert.equal(f.app.state.search, "");
    f.click("event-next");
    assert.equal(f.app.result.events[f.app.state.selected].event_id, "E009");
  } finally {
    f.close();
  }
});
test("notebook import binds to the original bytes and restores notes/parameters", async () => {
  const f = await fixture("investigar");
  try {
    f.click("tab", "notebook");
    const notes = Object.fromEntries(NOTE_FIELDS.map((k) => [k, ""]));
    notes.observacoes = "E011: perguntar sobre aprovação.";
    const notebook = makeNotebook(f.app.result, notes, "Meu caso");
    notebook.limiar_transferencia_brl = 40000;
    await f.upload("notebook-file", "caderno.json", JSON.stringify(notebook));
    assert.equal(
      f.doc.getElementById("note-observacoes").value,
      notes.observacoes,
    );
    assert.equal(f.app.state.threshold, 40000);
    assert.equal(f.app.result.signal_count, 5);
    await f.upload(
      "notebook-file",
      "errado.json",
      JSON.stringify({ ...notebook, arquivo_sha256: "0".repeat(64) }),
    );
    assert.match(f.doc.getElementById("toast").textContent, /outros bytes/);
    assert.equal(
      f.doc.getElementById("note-observacoes").value,
      notes.observacoes,
    );
  } finally {
    f.close();
  }
});
test("own-file import starts uncorrelated, escapes hostile text and sends no logs", async () => {
  const f = await fixture("investigar");
  try {
    f.change("case-select", "arquivo");
    assert.match(
      f.doc.getElementById("main").textContent,
      /Exemplo ainda visível/,
    );
    const example = await readFile(
      new URL("../data/caso-financeiro-ficticio.jsonl", import.meta.url),
      "utf8",
    );
    const rows = example.trim().split("\n").map(JSON.parse);
    rows[0].usuario = "<img src=x onerror=alert(1)>";
    await f.upload(
      "log-file",
      "teste.jsonl",
      rows.map(JSON.stringify).join("\n"),
    );
    assert.equal(f.app.state.shared, false);
    assert.equal(f.app.state.fileOpened, true);
    assert.equal(f.doc.querySelectorAll("main img").length, 0);
    assert.match(
      f.doc.querySelector(".event-detail").textContent,
      /<img src=x/,
    );
    assert.equal(f.requests.length, 7);
    f.click("tab", "signals");
    assert.ok(!f.doc.querySelector(".contingency"));
  } finally {
    f.close();
  }
});
test("assessment validation prevents N/A without justification and scenario import resets fields", async () => {
  const f = await fixture("diagnostico");
  try {
    const id = Object.keys(f.app.state.snapshot.answers)[0];
    f.input("evidence-" + id, "");
    f.change("answer-" + id, "na");
    assert.notEqual(f.app.state.snapshot.answers[id], "na");
    f.input(
      "evidence-" + id,
      "Não se aplica ao cenário fictício por este motivo.",
    );
    f.change("answer-" + id, "na");
    assert.equal(f.app.state.snapshot.answers[id], "na");
    f.input("evidence-" + id, "");
    f.routeTo("plano");
    assert.ok(f.doc.querySelector("main h1"));
    f.routeTo("diagnostico");
    f.change("scenario", "branco");
    assert.equal(f.doc.getElementById("answer-" + id).value, "unknown");
    assert.equal(f.app.state.snapshot.assets.length, 0);
  } finally {
    f.close();
  }
});
test("malformed inventory/assessment imports preserve the existing valid workspace", async () => {
  const f = await fixture("inventario");
  try {
    const before = f.app.state.snapshot.assets.length;
    await f.upload("inventory-file", "invalid.csv", "id,nome\na,b");
    assert.equal(f.app.state.snapshot.assets.length, before);
    assert.match(f.doc.getElementById("toast").textContent, /colunas/);
    f.routeTo("plano");
    await f.upload(
      "assessment-file",
      "invalid.json",
      '{"schema_version":1,"schema_version":2}',
    );
    assert.equal(f.app.state.snapshot.assets.length, before);
    assert.match(f.doc.getElementById("toast").textContent, /repetida/);
  } finally {
    f.close();
  }
});
test("network exercises and motion toggle expose their actual decision", async () => {
  const f = await fixture("redes");
  try {
    assert.match(f.doc.getElementById("main").textContent, /Negado/);
    f.change("network-source", "administracao");
    f.change("network-port", "22");
    assert.match(
      f.doc.querySelector(".network-node.allow").textContent,
      /Permitido/,
    );
    f.change("cidr", "2001:db8::/64");
    assert.match(f.doc.getElementById("main").textContent, /Sem broadcast/);
    f.doc.getElementById("motion-button").click();
    assert.equal(f.doc.documentElement.dataset.reducedMotion, "true");
    assert.equal(
      f.doc.getElementById("motion-button").getAttribute("aria-pressed"),
      "true",
    );
  } finally {
    f.close();
  }
});

test("guided inventory editor validates an asset, preserves invalid edits and recalculates findings", async () => {
  const f = await fixture("inventario");
  try {
    const before = f.app.state.snapshot.assets.length;
    f.click("add-asset");
    f.input("asset-nome", "Servidor de estudo");
    f.input("asset-ip", "203.0.113.12");
    f.change("asset-tipo", "servidor");
    f.change("asset-exposto_internet", "sim");
    f.input("asset-portas", "3389");
    f.click("save-asset");
    assert.equal(f.app.state.snapshot.assets.length, before + 1);
    assert.match(
      f.doc.getElementById("main").textContent,
      /Servidor de estudo/,
    );
    f.click("edit-asset", String(before));
    f.input("asset-ip", "endereço inválido");
    f.click("save-asset");
    assert.equal(f.app.state.snapshot.assets[before].ip, "203.0.113.12");
    assert.ok(f.doc.getElementById("asset-ip"));
    f.input("asset-ip", "2001:db8::10");
    f.click("save-asset");
    assert.equal(f.app.state.snapshot.assets[before].ip, "2001:db8::10");
  } finally {
    f.close();
  }
});

test("keyboard focus survives interactive rerenders and motion preference", async () => {
  const f = await fixture("aprender");
  try {
    const button = f.doc.querySelector(
      '[data-action="field"][data-value="sessao"]',
    );
    button.focus();
    button.click();
    assert.equal(f.doc.activeElement.dataset.value, "sessao");
    f.doc.getElementById("menu-button").click();
    assert.equal(
      f.doc.getElementById("menu-button").getAttribute("aria-expanded"),
      "true",
    );
    f.doc.getElementById("motion-button").click();
    assert.equal(
      f.doc.getElementById("motion-button").getAttribute("aria-label"),
      "Ativar animações",
    );
  } finally {
    f.close();
  }
});

test("Wi-Fi review requires evidence, preserves notes between practices and explains guest isolation", async () => {
  const f = await fixture("redes");
  try {
    f.click("network-tab", "wifi");
    assert.equal(f.doc.getElementById("network-tab-wifi").getAttribute("aria-pressed"), "true");
    assert.equal(f.doc.querySelectorAll("[data-wifi-status]").length, 6);
    for (const target of f.doc.querySelectorAll("main input, main select, main textarea"))
      assert.ok(f.doc.querySelector(`label[for="${target.id}"]`));
    f.change("wifi-status-encryption", "checked");
    assert.equal(f.app.state.wifi.answers.encryption, "unknown");
    assert.match(f.doc.getElementById("toast").textContent, /evidência/);
    f.input("wifi-note-encryption", "WPA3 conferido no exercício fictício em 09/10.");
    f.change("wifi-status-encryption", "checked");
    assert.equal(f.app.state.wifi.answers.encryption, "checked");
    f.input("wifi-note-encryption", "");
    assert.match(f.doc.getElementById("wifi-note-encryption").value, /WPA3/);
    f.click("network-tab", "ferramentas");
    for (const tool of ["Packet Tracer", "Wireshark", "Nmap", "Wazuh"])
      assert.ok(f.doc.getElementById("main").textContent.includes(tool));
    f.click("network-tab", "wifi");
    assert.match(f.doc.getElementById("wifi-note-encryption").value, /WPA3/);
    f.click("guest-example");
    assert.equal(f.app.state.network.destination, "servidores");
    assert.equal(f.app.state.network.port, 443);
    assert.match(f.doc.querySelector(".network-path").textContent, /Negado/);
    assert.equal(f.app.state.wifi.answers.encryption, "checked");
  } finally { f.close(); }
});

test("Wi-Fi imports preserve previous state on failure and render imported text safely", async () => {
  const f = await fixture("redes");
  try {
    f.click("network-tab", "wifi");
    const previous = f.app.state.wifi;
    await f.upload("wifi-file", "invalid.json", JSON.stringify(f.app.state.snapshot));
    assert.equal(f.app.state.wifi, previous);
    const candidate = structuredClone(previous);
    candidate.network_name = '<img src=x onerror="alert(1)">';
    candidate.notes.guest = '<script>alert("teste")</script>';
    candidate.answers.guest = "review";
    await f.upload("wifi-file", "wifi.json", JSON.stringify(candidate));
    assert.deepEqual(JSON.parse(JSON.stringify(f.app.state.wifi)), candidate);
    assert.equal(f.doc.querySelectorAll("main img, main script").length, 0);
    assert.equal(f.doc.getElementById("wifi-note-guest").value, candidate.notes.guest);
    candidate.answers.guest = "checked";
    candidate.notes.guest = "";
    await f.upload("wifi-file", "invalid-evidence.json", JSON.stringify(candidate));
    assert.equal(f.app.state.wifi.answers.guest, "review");
    assert.match(f.app.state.wifi.notes.guest, /script/);
  } finally { f.close(); }
});

test("defense method connects feedback, qualitative triage and the existing case notebook", async () => {
  const f = await fixture("metodo");
  try {
    for (let i = 0; i < 6; i++) {
      f.click("method-step", String(i));
      assert.ok(f.doc.querySelector(".method-layout").textContent.length > 800);
    }
    const claim = f.doc.querySelector('[data-claim="porta"][data-value="observacao"]');
    claim.click();
    assert.match(f.doc.querySelector('[data-claim="porta"][data-value="observacao"]').closest("article").textContent, /não tem sessão/);
    f.change("method-ongoing", "sim");
    assert.match(f.doc.getElementById("main").textContent, /Acionar resposta agora/);
    f.input("method-note-observacoes", "E008: alterar MFA exige verificar autorização.");
    assert.equal(f.doc.getElementById("method-filled").textContent, "1");
    f.routeTo("investigar");f.click("tab", "notebook");
    assert.equal(f.doc.querySelector('[data-note="observacoes"]').value, "E008: alterar MFA exige verificar autorização.");
    f.change("case-select", "benigno");f.routeTo("metodo");
    assert.equal(f.doc.getElementById("method-note-observacoes").value, "");
    f.click("method-case");await flush();await flush();
    assert.equal(f.app.state.case, "financeiro");
    f.routeTo("metodo");assert.match(f.doc.getElementById("method-note-observacoes").value, /E008/);
  } finally { f.close(); }
});

test("check-up import, comparison, filter and clear work without collecting from browser", async () => {
  const f = await fixture("checkup");
  try {
    assert.match(f.doc.getElementById('main').textContent, /Aguardando seu primeiro check-up/);
    f.click('checkup-demo');
    assert.equal(f.app.state.checkup.reports.length,2);
    assert.match(f.doc.getElementById('main').textContent,/EXEMPLO FICTÍCIO/);
    f.change('checkup-filter','unknown');
    assert.equal(f.doc.querySelectorAll('.check-card').length,1);
    f.click('checkup-clear');
    const {demoCheckups} = await import('../checkup.js');
    const [a,b]=demoCheckups();a.mode='observed';b.mode='observed';
    await f.upload('checkup-file','first.json',JSON.stringify(a));
    await f.upload('checkup-file','second.json',JSON.stringify(b));
    assert.equal(f.app.state.checkup.reports.length,2);
    const invalid=structuredClone(b);invalid.device_id='314f9fdd-6285-4cb6-8394-a41a9f7abdd2';invalid.created_at='2026-10-11T09:00:00Z';
    await f.upload('checkup-file','wrong.json',JSON.stringify(invalid));
    assert.equal(f.app.state.checkup.reports.length,2);
    assert.match(f.doc.getElementById('toast').textContent,/mesma origem/);
    assert.ok(f.requests.every(x=>x.startsWith('data/')));
  } finally {f.close();}
});
