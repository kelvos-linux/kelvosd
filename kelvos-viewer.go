// kelvos-viewer.go
//
// Live web viewer for /var/log/kelvos_traffic_monitor.jsonl
//
//   go run kelvos-viewer.go                       # http://localhost:8080
//   sudo go run kelvos-viewer.go -addr :9090      # custom port
//   sudo ./kelvos-viewer -file /var/log/kelvos_traffic_monitor.jsonl
//
// Single file, zero external dependencies (stdlib only).

package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

/* ------------------------------------------------------------------ */
/*  Broadcaster (fan-out of log lines to all SSE clients)              */
/* ------------------------------------------------------------------ */

type Hub struct {
	mu   sync.Mutex
	subs map[chan []byte]struct{}
}

func newHub() *Hub { return &Hub{subs: make(map[chan []byte]struct{})} }

func (h *Hub) subscribe() chan []byte {
	ch := make(chan []byte, 4096)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *Hub) unsubscribe(ch chan []byte) {
	h.mu.Lock()
	if _, ok := h.subs[ch]; ok {
		delete(h.subs, ch)
		close(ch)
	}
	h.mu.Unlock()
}

func (h *Hub) send(line []byte) {
	h.mu.Lock()
	for ch := range h.subs {
		select {
		case ch <- line:
		default: // slow client -> drop, don't block the tailer
		}
	}
	h.mu.Unlock()
}

/* ------------------------------------------------------------------ */
/*  Ring history (last N lines, sent to newly connected browsers)      */
/* ------------------------------------------------------------------ */

type History struct {
	mu    sync.Mutex
	max   int
	lines [][]byte
}

func newHistory(max int) *History { return &History{max: max} }

func (h *History) add(l []byte) {
	if h.max <= 0 {
		return
	}
	h.mu.Lock()
	h.lines = append(h.lines, l)
	if len(h.lines) > h.max {
		h.lines = append(h.lines[:0], h.lines[len(h.lines)-h.max:]...)
	}
	h.mu.Unlock()
}

func (h *History) snapshot() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([][]byte, len(h.lines))
	copy(out, h.lines)
	return out
}

/* ------------------------------------------------------------------ */
/*  File reader: last N lines + follow                                 */
/* ------------------------------------------------------------------ */

// readTail returns the last n complete lines and the byte offset just
// after the last complete line.
func readTail(path string, n int) ([][]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := st.Size()

	const maxScan = int64(64 << 20) // don't scan more than 64 MiB backwards
	start := int64(0)
	if size > maxScan {
		start = size - maxScan
	}
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return nil, 0, err
	}

	br := bufio.NewReaderSize(f, 1<<20)
	offset := start

	if start > 0 { // we landed mid-line, throw the partial line away
		if l, err := br.ReadBytes('\n'); err == nil {
			offset += int64(len(l))
		}
	}

	var ring [][]byte
	for {
		line, err := br.ReadBytes('\n')
		if err == nil {
			offset += int64(len(line))
			l := bytes.TrimRight(line, "\r\n")
			if len(l) > 0 && n > 0 {
				cp := make([]byte, len(l))
				copy(cp, l)
				if len(ring) < n {
					ring = append(ring, cp)
				} else {
					ring = append(ring[1:], cp)
				}
			}
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		return ring, offset, err
	}
	return ring, offset, nil
}

// followFile watches path for appended data, handles rotation/truncation.
func followFile(path string, offset int64, emit func([]byte)) {
	var (
		f       *os.File
		fi      os.FileInfo
		pending []byte
		buf     = make([]byte, 64*1024)
	)

	open := func() bool {
		nf, err := os.Open(path)
		if err != nil {
			return false
		}
		st, err := nf.Stat()
		if err != nil {
			nf.Close()
			return false
		}
		if offset > st.Size() {
			offset = 0
		}
		if _, err := nf.Seek(offset, io.SeekStart); err != nil {
			nf.Close()
			return false
		}
		f, fi = nf, st
		pending = pending[:0]
		log.Printf("tailing %s (offset %d)", path, offset)
		return true
	}

	open()

	for {
		if f == nil {
			time.Sleep(500 * time.Millisecond)
			open()
			continue
		}

		n, err := f.Read(buf)
		if n > 0 {
			offset += int64(n)
			pending = append(pending, buf[:n]...)

			consumed := 0
			for {
				i := bytes.IndexByte(pending[consumed:], '\n')
				if i < 0 {
					break
				}
				l := bytes.TrimRight(pending[consumed:consumed+i], "\r")
				if len(l) > 0 {
					cp := make([]byte, len(l))
					copy(cp, l)
					emit(cp)
				}
				consumed += i + 1
			}
			if consumed > 0 {
				pending = append(pending[:0], pending[consumed:]...)
			}
			if len(pending) > 8<<20 { // runaway line, drop it
				pending = pending[:0]
			}
			continue
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				if st, serr := os.Stat(path); serr == nil {
					if !os.SameFile(fi, st) {
						log.Printf("%s rotated, reopening", path)
						f.Close()
						f, offset = nil, 0
						continue
					}
					if st.Size() < offset {
						log.Printf("%s truncated, reopening", path)
						f.Close()
						f, offset = nil, 0
						continue
					}
				}
				time.Sleep(200 * time.Millisecond)
				continue
			}
			log.Printf("read error on %s: %v", path, err)
			f.Close()
			f = nil
			time.Sleep(time.Second)
			continue
		}
		time.Sleep(100 * time.Millisecond)
	}
}

/* ------------------------------------------------------------------ */
/*  SSE                                                                */
/* ------------------------------------------------------------------ */

func writeEvent(w io.Writer, name string, lines [][]byte) {
	var b bytes.Buffer
	if name != "" {
		b.WriteString("event: ")
		b.WriteString(name)
		b.WriteByte('\n')
	}
	for _, l := range lines {
		b.WriteString("data: ")
		b.Write(l)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	w.Write(b.Bytes())
}

func serveSSE(w http.ResponseWriter, r *http.Request, hub *Hub, hist *History) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	h := w.Header()
	h.Set("Content-Type", "text/event-stream; charset=utf-8")
	h.Set("Cache-Control", "no-cache, no-transform")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	if r.URL.Query().Get("live") != "1" {
		writeEvent(w, "history", hist.snapshot())
	}
	fmt.Fprint(w, "retry: 3000\n\n")
	fl.Flush()

	ch := hub.subscribe()
	defer hub.unsubscribe(ch)

	batch := make([][]byte, 0, 512)
	flushT := time.NewTicker(150 * time.Millisecond)
	defer flushT.Stop()
	pingT := time.NewTicker(20 * time.Second)
	defer pingT.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case line, ok := <-ch:
			if !ok {
				return
			}
			batch = append(batch, line)
			if len(batch) >= 512 {
				writeEvent(w, "batch", batch)
				fl.Flush()
				batch = batch[:0]
			}

		case <-flushT.C:
			if len(batch) > 0 {
				writeEvent(w, "batch", batch)
				fl.Flush()
				batch = batch[:0]
			}

		case <-pingT.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

/* ------------------------------------------------------------------ */
/*  main                                                               */
/* ------------------------------------------------------------------ */

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	file := flag.String("file", "/var/log/kelvos_traffic_monitor.jsonl", "JSONL log file to tail")
	histN := flag.Int("history", 500, "lines of history sent to a new browser")
	flag.Parse()

	hub := newHub()
	hist := newHistory(*histN)

	lines, offset, err := readTail(*file, *histN)
	if err != nil {
		log.Printf("warning: cannot read %s yet: %v", *file, err)
		if st, e := os.Stat(*file); e == nil {
			offset = st.Size()
		}
		lines = nil
	}
	for _, l := range lines {
		hist.add(l)
	}
	log.Printf("loaded %d historical records from %s", len(lines), *file)

	go followFile(*file, offset, func(line []byte) {
		hist.add(line)
		hub.send(line)
	})

	page := strings.Replace(indexHTML, "{{FILE}}", *file, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		io.WriteString(w, page)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		serveSSE(w, r, hub, hist)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok\n")
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("Kelvos traffic viewer  ->  http://localhost%s", *addr)
	log.Printf("watching: %s", *file)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

/* ------------------------------------------------------------------ */
/*  Embedded UI                                                        */
/* ------------------------------------------------------------------ */

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kelvos Traffic Monitor</title>
<style>
:root{
  --bg:#0a0e13; --panel:#0f1620; --panel2:#121b26; --line:#1d2937;
  --fg:#d8e3ef; --muted:#7a8ea6; --acc:#3ad1ff; --ok:#3ddc84; --warn:#ffb020; --bad:#ff5470;
  --in:#3ad1ff; --out:#c792ea;
}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{
  background:var(--bg);color:var(--fg);
  font:12.5px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
  display:flex;flex-direction:column;height:100vh;overflow:hidden;
}
/* ---------- header ---------- */
header.top{
  display:flex;align-items:center;gap:14px;padding:8px 14px;
  background:linear-gradient(180deg,#141e2b,#0f1620);
  border-bottom:1px solid var(--line);flex:0 0 auto;
}
.brand{font-weight:700;letter-spacing:.6px;color:var(--acc);white-space:nowrap}
.brand span{color:var(--muted);font-weight:400;letter-spacing:0}
.meta{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:11px;
  overflow:hidden;white-space:nowrap;text-overflow:ellipsis;max-width:44vw}
.spacer{flex:1}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block;background:var(--muted)}
.dot.on{background:var(--ok);box-shadow:0 0 8px var(--ok)}
.dot.off{background:var(--bad);box-shadow:0 0 8px var(--bad)}
button{
  background:#182333;color:var(--fg);border:1px solid var(--line);border-radius:6px;
  padding:5px 10px;cursor:pointer;font:inherit;font-size:11.5px;white-space:nowrap;
}
button:hover{background:#1e2c3f;border-color:#2b3d54}
button.active{background:#1d3a4d;border-color:var(--acc);color:var(--acc)}
/* ---------- filters ---------- */
.filters{display:flex;flex-wrap:wrap;gap:6px;align-items:center;padding:7px 14px;
  background:var(--panel);border-bottom:1px solid var(--line);flex:0 0 auto}
.filters input,.filters select{
  background:#0b121b;border:1px solid var(--line);color:var(--fg);border-radius:6px;
  padding:5px 8px;font:inherit;font-size:11.5px;outline:none;
}
.filters input:focus,.filters select:focus{border-color:var(--acc)}
#f-q{min-width:230px}
#f-minlen{width:92px}
.flags{display:flex;gap:9px;align-items:center;padding:0 8px;
  border-left:1px solid var(--line);border-right:1px solid var(--line);margin:0 4px}
.flags label,.chk{display:flex;gap:4px;align-items:center;color:var(--muted);
  font-size:11px;cursor:pointer;user-select:none}
.flags input,.chk input{accent-color:var(--acc);margin:0}
/* ---------- stats ---------- */
.stats{display:flex;gap:8px;padding:8px 14px;overflow-x:auto;
  background:var(--panel2);border-bottom:1px solid var(--line);flex:0 0 auto}
.card{background:#0d1520;border:1px solid var(--line);border-radius:8px;
  padding:5px 11px;min-width:96px;white-space:nowrap}
.card .k{color:var(--muted);font-size:9.5px;text-transform:uppercase;letter-spacing:.7px}
.card .v{font-size:14px;font-weight:700;margin-top:2px}
.card .v small{color:var(--muted);font-weight:400;font-size:10px}
.v.in{color:var(--in)} .v.out{color:var(--out)} .v.acc{color:var(--acc)}
/* ---------- table ---------- */
main{flex:1 1 auto;overflow:auto;position:relative}
table{border-collapse:separate;border-spacing:0;width:100%;font-size:11.5px}
thead th{
  position:sticky;top:0;z-index:5;background:#131c28;color:var(--muted);text-align:left;
  padding:7px 8px;border-bottom:1px solid var(--line);font-weight:600;font-size:10px;
  text-transform:uppercase;letter-spacing:.6px;white-space:nowrap;
}
tbody td{padding:4px 8px;border-bottom:1px solid #111a24;white-space:nowrap}
tbody tr:hover{background:#16212f;cursor:pointer}
tbody tr.hasdata{background:rgba(58,209,255,.05)}
tbody tr.hasdata:hover{background:#16212f}
td.ip{max-width:250px;overflow:hidden;text-overflow:ellipsis}
td.ip .p{color:var(--acc)}
td.num{text-align:right;color:var(--muted)}
td.num.pl{color:var(--warn);font-weight:700}
td.ts{color:var(--muted)}
td.arw{color:#31465e;text-align:center;width:16px}
td.app{color:#9fd6b4}
.tag{display:inline-block;padding:1px 6px;border-radius:4px;font-size:9.5px;
  font-weight:700;border:1px solid;letter-spacing:.5px}
.tag.in{color:var(--in);border-color:rgba(58,209,255,.4);background:rgba(58,209,255,.08)}
.tag.out{color:var(--out);border-color:rgba(199,146,234,.4);background:rgba(199,146,234,.08)}
.tag.unk{color:var(--muted);border-color:var(--line)}
b.f{display:inline-block;width:14px;text-align:center;border-radius:3px;
  margin-right:2px;font-size:9.5px;background:#1b2634;color:#8fa6bd}
b.f.syn{background:#1d3a4d;color:#3ad1ff}
b.f.ack{background:#16321f;color:#3ddc84}
b.f.psh{background:#3a2f10;color:#ffb020}
b.f.fin,b.f.rst{background:#3a1a22;color:#ff5470}
b.f.urg{background:#2b1d3a;color:#c792ea}
/* ---------- detail drawer ---------- */
.detail{position:fixed;top:0;right:0;bottom:0;width:min(600px,94vw);background:#0c131c;
  border-left:1px solid var(--line);z-index:50;display:flex;flex-direction:column;
  box-shadow:-24px 0 48px rgba(0,0,0,.55)}
.detail.hidden{display:none}
.dhead{display:flex;gap:8px;align-items:center;padding:8px 12px;
  border-bottom:1px solid var(--line);background:var(--panel);
  font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px}
.dhead .spacer{flex:1}
pre#detailBody{margin:0;padding:12px;overflow:auto;font-size:11.5px;color:#bcd3e8;
  flex:1;white-space:pre-wrap;word-break:break-word}
::-webkit-scrollbar{width:10px;height:10px}
::-webkit-scrollbar-track{background:#0b121b}
::-webkit-scrollbar-thumb{background:#22303f;border-radius:6px}
::-webkit-scrollbar-thumb:hover{background:#2d4054}
</style>
</head>
<body>

<header class="top">
  <div class="brand">&#9670; KELVOS <span>traffic monitor</span></div>
  <div class="meta">
    <span id="connDot" class="dot off"></span>
    <span id="connTxt">connecting&hellip;</span>
    <span>&middot;</span>
    <span id="filePath">{{FILE}}</span>
  </div>
  <div class="spacer"></div>
  <button id="btnPause">&#10074;&#10074; Pause</button>
  <button id="btnClear">Clear</button>
  <button id="btnCsv">CSV</button>
  <button id="btnJson">JSON</button>
</header>

<section class="filters">
  <input id="f-q" placeholder="search  ip / port / mac / proto / sni&hellip;">
  <select id="f-dir">
    <option value="all">dir: all</option>
    <option value="ingress">ingress</option>
    <option value="egress">egress</option>
  </select>
  <select id="f-net">
    <option value="all">net: all</option>
    <option value="IPv4">IPv4</option>
    <option value="IPv6">IPv6</option>
  </select>
  <select id="f-l4">
    <option value="all">l4: all</option>
    <option value="TCP">TCP</option>
    <option value="UDP">UDP</option>
    <option value="ICMP">ICMP</option>
    <option value="ICMPv6">ICMPv6</option>
  </select>
  <select id="f-app"><option value="all">app: all</option></select>
  <select id="f-iface"><option value="all">iface: all</option></select>
  <input id="f-ip" placeholder="ip contains" size="14">
  <input id="f-port" placeholder="port" size="6">
  <input id="f-minlen" type="number" min="0" placeholder="min bytes">
  <span class="flags">
    <label><input type="checkbox" data-flag="syn">SYN</label>
    <label><input type="checkbox" data-flag="ack">ACK</label>
    <label><input type="checkbox" data-flag="psh">PSH</label>
    <label><input type="checkbox" data-flag="fin">FIN</label>
    <label><input type="checkbox" data-flag="rst">RST</label>
    <label><input type="checkbox" data-flag="urg">URG</label>
  </span>
  <label class="chk"><input type="checkbox" id="f-hideempty">hide empty payload</label>
  <button id="btnReset">Reset</button>
</section>

<div class="stats" id="stats"></div>

<main>
  <table>
    <thead>
      <tr>
        <th>time</th><th>dir</th><th>l4</th><th>source</th><th></th><th>destination</th>
        <th>flags</th><th>len</th><th>payload</th><th>app</th><th>iface</th>
      </tr>
    </thead>
    <tbody id="rows"></tbody>
  </table>
</main>

<aside id="detail" class="detail hidden">
  <div class="dhead">
    <span>record detail</span>
    <span class="spacer"></span>
    <button id="btnCopy">copy</button>
    <button id="btnCloseDetail">&#10005;</button>
  </div>
  <pre id="detailBody"></pre>
</aside>

<script>
(function () {
"use strict";

var MAX = 5000;

var buf = [];                 // parsed records, newest last
var byId = new Map();         // id -> record  (for the detail drawer)
var nextId = 1;
var paused = false;
var filters = {};
var appVals = new Set();
var ifaceVals = new Set();

var rowsEl     = document.getElementById("rows");
var statsEl    = document.getElementById("stats");
var connDot    = document.getElementById("connDot");
var connTxt    = document.getElementById("connTxt");
var detailEl   = document.getElementById("detail");
var detailBody = document.getElementById("detailBody");
var appSel     = document.getElementById("f-app");
var ifaceSel   = document.getElementById("f-iface");

/* ---------------- helpers ---------------- */

function esc(s) {
  return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) {
    return c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : "&quot;";
  });
}

function human(n) {
  if (n < 1024) return n + " B";
  var u = ["KB", "MB", "GB", "TB"], i = -1;
  do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
  return n.toFixed(1) + " " + u[i];
}

function haystack(r) {
  var n = r.network || {}, t = r.transport || {}, a = r.services || {}, e = r.ethernet || {};
  return [
    r.direction, r.interface, r.timestamp,
    n.source_ip, n.destination_ip, n.protocol, n.protocol_number,
    t.protocol, t.source_port, t.destination_port,
    a.protocol,
    e.source_mac, e.destination_mac
  ].join(" ").toLowerCase();
}

function flagStr(f) {
  if (!f) return "";
  var out = [];
  if (f.syn) out.push("SYN");
  if (f.ack) out.push("ACK");
  if (f.psh) out.push("PSH");
  if (f.fin) out.push("FIN");
  if (f.rst) out.push("RST");
  if (f.urg) out.push("URG");
  return out.join(",");
}

function flagHTML(f) {
  if (!f) return "";
  var s = "";
  if (f.syn) s += '<b class="f syn">S</b>';
  if (f.ack) s += '<b class="f ack">A</b>';
  if (f.psh) s += '<b class="f psh">P</b>';
  if (f.fin) s += '<b class="f fin">F</b>';
  if (f.rst) s += '<b class="f rst">R</b>';
  if (f.urg) s += '<b class="f urg">U</b>';
  return s;
}

/* ---------------- filters ---------------- */

function readFilters() {
  var flags = {};
  var boxes = document.querySelectorAll("input[data-flag]");
  for (var i = 0; i < boxes.length; i++) {
    if (boxes[i].checked) flags[boxes[i].getAttribute("data-flag")] = true;
  }
  filters = {
    q:        document.getElementById("f-q").value.trim().toLowerCase(),
    dir:      document.getElementById("f-dir").value,
    net:      document.getElementById("f-net").value,
    l4:       document.getElementById("f-l4").value,
    app:      appSel.value,
    iface:    ifaceSel.value,
    ip:       document.getElementById("f-ip").value.trim().toLowerCase(),
    port:     document.getElementById("f-port").value.trim(),
    minlen:   parseInt(document.getElementById("f-minlen").value, 10) || 0,
    hideempty: document.getElementById("f-hideempty").checked,
    flags:    flags
  };
}

function match(r, f) {
  if (f.dir !== "all" && (r.direction || "") !== f.dir) return false;

  var n = r.network || {}, t = r.transport || {}, a = r.services || {}, p = r.payload || {};

  if (f.net !== "all" && (n.protocol || "") !== f.net) return false;
  if (f.l4 !== "all" && (t.protocol || "") !== f.l4) return false;
  if (f.app !== "all" && ((a.protocol || "Unknown")) !== f.app) return false;
  if (f.iface !== "all" && (r.interface || "") !== f.iface) return false;
  if (f.q && r._s.indexOf(f.q) < 0) return false;

  if (f.ip) {
    var s = (n.source_ip || "").toLowerCase();
    var d = (n.destination_ip || "").toLowerCase();
    if (s.indexOf(f.ip) < 0 && d.indexOf(f.ip) < 0) return false;
  }
  if (f.port) {
    if (String(t.source_port || "") !== f.port && String(t.destination_port || "") !== f.port) return false;
  }
  if (f.minlen > 0 && (p.length || 0) < f.minlen) return false;
  if (f.hideempty && !(p.length || 0)) return false;

  for (var k in f.flags) {
    if (!t.flags || !t.flags[k]) return false;
  }
  return true;
}

/* ---------------- row rendering ---------------- */

function rowHTML(r) {
  var n = r.network || {}, t = r.transport || {}, a = r.services || {}, p = r.payload || {};

  var dir = r.direction === "ingress"
    ? '<span class="tag in">IN</span>'
    : r.direction === "egress"
      ? '<span class="tag out">OUT</span>'
      : '<span class="tag unk">?</span>';

  var ts = (r.timestamp || "").substr(11, 12);
  var plen = p.length || 0;
  var sip = n.source_ip || "";
  var dip = n.destination_ip || "";

  return '<tr data-id="' + r._id + '"' + (plen ? ' class="hasdata"' : "") + '>'
    + '<td class="ts">' + esc(ts) + '</td>'
    + '<td>' + dir + '</td>'
    + '<td>' + esc(t.protocol || n.protocol || "?") + '</td>'
    + '<td class="ip" title="' + esc(sip) + '">' + esc(sip)
      + '<span class="p">:' + esc(t.source_port || "") + '</span></td>'
    + '<td class="arw">&#8594;</td>'
    + '<td class="ip" title="' + esc(dip) + '">' + esc(dip)
      + '<span class="p">:' + esc(t.destination_port || "") + '</span></td>'
    + '<td>' + flagHTML(t.flags) + '</td>'
    + '<td class="num">' + (n.total_length || 0) + '</td>'
    + '<td class="num' + (plen ? ' pl' : '') + '">' + plen + '</td>'
    + '<td class="app">' + esc(a.protocol || "Unknown") + '</td>'
    + '<td>' + esc(r.interface || "") + '</td>'
    + '</tr>';
}

function trimRows() {
  while (rowsEl.childElementCount > MAX) {
    rowsEl.removeChild(rowsEl.lastElementChild);
  }
}

function renderAll() {
  var html = "", n = 0;
  for (var i = buf.length - 1; i >= 0; i--) {
    if (match(buf[i], filters)) {
      html += rowHTML(buf[i]);
      if (++n >= MAX) break;
    }
  }
  rowsEl.innerHTML = html;
  updateStats();
}

/* ---------------- incoming data ---------------- */

function resetBuffer() {
  buf = [];
  byId.clear();
  rowsEl.innerHTML = "";
}

function onLines(lines) {
  var parsed = [];

  for (var i = 0; i < lines.length; i++) {
    var s = lines[i];
    if (!s) continue;
    var r;
    try { r = JSON.parse(s); } catch (e) { continue; }
    if (typeof r !== "object" || r === null) continue;

    r._id = nextId++;
    r._s  = haystack(r);
    byId.set(r._id, r);
    buf.push(r);
    parsed.push(r);

    var ap = (r.services && r.services.protocol) || "Unknown";
    appVals.add(ap);
    if (r.interface) ifaceVals.add(r.interface);
  }

  while (buf.length > MAX) {
    byId.delete(buf.shift()._id);
  }

  if (!paused && parsed.length) {
    var html = "";
    for (var k = parsed.length - 1; k >= 0; k--) {
      if (match(parsed[k], filters)) html += rowHTML(parsed[k]);
    }
    if (html) {
      rowsEl.insertAdjacentHTML("afterbegin", html);
      trimRows();
    }
  }

  updateStats();
}

/* ---------------- stats ---------------- */

function card(k, v, cls) {
  return '<div class="card"><div class="k">' + k + '</div><div class="v ' + (cls || "") + '">' + v + '</div></div>';
}

function syncSelect(sel, set, label) {
  var cur = sel.value;
  var vals = Array.from(set).sort();
  var html = '<option value="all">' + label + ': all</option>';
  for (var i = 0; i < vals.length; i++) {
    html += '<option value="' + esc(vals[i]) + '">' + esc(vals[i]) + '</option>';
  }
  if (sel.getAttribute("data-sig") !== html) {
    sel.innerHTML = html;
    sel.setAttribute("data-sig", html);
    sel.value = cur;
    if (sel.value !== cur) sel.value = "all";
  }
}

function updateStats() {
  syncSelect(appSel, appVals, "app");
  syncSelect(ifaceSel, ifaceVals, "iface");

  var f = filters;
  var total = 0, tin = 0, tout = 0, bytes = 0;
  var v4 = 0, v6 = 0, tcp = 0, udp = 0, icmp = 0, other = 0;
  var srcs = new Map(), dsts = new Map();

  for (var i = 0; i < buf.length; i++) {
    var r = buf[i];
    if (!match(r, f)) continue;

    total++;
    if (r.direction === "ingress") tin++;
    else if (r.direction === "egress") tout++;

    var n = r.network || {}, t = r.transport || {};
    bytes += n.total_length || 0;

    if (n.protocol === "IPv4") v4++;
    else if (n.protocol === "IPv6") v6++;

    var tp = t.protocol || "";
    if (tp === "TCP") tcp++;
    else if (tp === "UDP") udp++;
    else if (tp.indexOf("ICMP") === 0) icmp++;
    else other++;

    if (n.source_ip) srcs.set(n.source_ip, (srcs.get(n.source_ip) || 0) + 1);
    if (n.destination_ip) dsts.set(n.destination_ip, (dsts.get(n.destination_ip) || 0) + 1);
  }

  var top = Array.from(srcs.entries()).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 2);
  var topHtml = top.length
    ? top.map(function (e) { return esc(e[0].length > 22 ? e[0].substr(0, 21) + "\u2026" : e[0]) + " <small>x" + e[1] + "</small>"; }).join("<br>")
    : "\u2014";

  statsEl.innerHTML =
    card("records", total + ' <small>/ ' + buf.length + '</small>', "acc") +
    card("ingress", tin, "in") +
    card("egress", tout, "out") +
    card("bytes", human(bytes)) +
    card("ipv4 / ipv6", v4 + ' / ' + v6) +
    card("tcp/udp/icmp", tcp + '/' + udp + '/' + icmp) +
    card("uniq src/dst", srcs.size + ' / ' + dsts.size) +
    card("top source", topHtml);
}

/* ---------------- detail drawer ---------------- */

function clean(r) {
  var o = {};
  for (var k in r) {
    if (k === "_id" || k === "_s") continue;
    o[k] = r[k];
  }
  return o;
}

function showDetail(r) {
  detailBody.textContent = JSON.stringify(clean(r), null, 2);
  detailEl.classList.remove("hidden");
}

rowsEl.addEventListener("click", function (ev) {
  var tr = ev.target.closest("tr");
  if (!tr) return;
  var id = parseInt(tr.getAttribute("data-id"), 10);
  var r = byId.get(id);
  if (r) showDetail(r);
});

document.getElementById("btnCloseDetail").onclick = function () {
  detailEl.classList.add("hidden");
};
document.getElementById("btnCopy").onclick = function () {
  if (navigator.clipboard) navigator.clipboard.writeText(detailBody.textContent);
};
document.addEventListener("keydown", function (e) {
  if (e.key === "Escape") detailEl.classList.add("hidden");
});

/* ---------------- export ---------------- */

function csvCell(v) {
  v = v == null ? "" : String(v);
  return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
}

function filteredRecords() {
  var out = [];
  for (var i = 0; i < buf.length; i++) {
    if (match(buf[i], filters)) out.push(buf[i]);
  }
  return out;
}

function download(name, text, mime) {
  var b = new Blob([text], { type: mime });
  var u = URL.createObjectURL(b);
  var a = document.createElement("a");
  a.href = u;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function () { URL.revokeObjectURL(u); }, 3000);
}

document.getElementById("btnCsv").onclick = function () {
  var recs = filteredRecords();
  var head = ["timestamp", "direction", "interface", "net_protocol",
              "src_ip", "src_port", "dst_ip", "dst_port", "l4", "flags",
              "total_length", "payload_length", "app_protocol", "server_name",
              "alpn", "src_mac", "dst_mac"];
  var out = [head.join(",")];
  for (var i = 0; i < recs.length; i++) {
    var r = recs[i], n = r.network || {}, t = r.transport || {},
        a = r.services || {}, e = r.ethernet || {}, p = r.payload || {};
    out.push([
      r.timestamp, r.direction, r.interface, n.protocol,
      n.source_ip, t.source_port, n.destination_ip, t.destination_port,
      t.protocol, flagStr(t.flags), n.total_length, p.length,
      a.protocol, a.server_name, a.alpn, e.source_mac, e.destination_mac
    ].map(csvCell).join(","));
  }
  download("kelvos-traffic.csv", out.join("\n"), "text/csv");
};

document.getElementById("btnJson").onclick = function () {
  var recs = filteredRecords().map(clean);
  download("kelvos-traffic.json", JSON.stringify(recs, null, 2), "application/json");
};

/* ---------------- toolbar ---------------- */

document.getElementById("btnPause").onclick = function () {
  paused = !paused;
  this.classList.toggle("active", paused);
  this.innerHTML = paused ? "&#9654; Resume" : "&#10074;&#10074; Pause";
  if (!paused) renderAll();
};

document.getElementById("btnClear").onclick = function () {
  resetBuffer();
  updateStats();
};

document.getElementById("btnReset").onclick = function () {
  document.getElementById("f-q").value = "";
  document.getElementById("f-ip").value = "";
  document.getElementById("f-port").value = "";
  document.getElementById("f-minlen").value = "";
  document.getElementById("f-dir").value = "all";
  document.getElementById("f-net").value = "all";
  document.getElementById("f-l4").value = "all";
  appSel.value = "all";
  ifaceSel.value = "all";
  document.getElementById("f-hideempty").checked = false;
  var boxes = document.querySelectorAll("input[data-flag]");
  for (var i = 0; i < boxes.length; i++) boxes[i].checked = false;
  readFilters();
  renderAll();
};

/* ---------------- live stream ---------------- */

function setConn(ok, txt) {
  connDot.className = "dot " + (ok ? "on" : "off");
  connTxt.textContent = txt;
}

function connect(liveOnly) {
  var es = new EventSource("/events" + (liveOnly ? "?live=1" : ""));

  es.onopen = function () { setConn(true, "live"); };
  es.onerror = function () { setConn(false, "reconnecting\u2026"); };

  es.addEventListener("history", function (e) {
    resetBuffer();
    onLines(e.data.split("\n"));
    setConn(true, "live");
  });

  es.addEventListener("batch", function (e) {
    onLines(e.data.split("\n"));
  });

  es.onmessage = function (e) {
    onLines(e.data.split("\n"));
  };
}

/* ---------------- filter wiring ---------------- */

var inputs = document.querySelectorAll(".filters input, .filters select");
for (var i = 0; i < inputs.length; i++) {
  inputs[i].addEventListener("input", function () {
    readFilters();
    renderAll();
  });
  inputs[i].addEventListener("change", function () {
    readFilters();
    renderAll();
  });
}

/* ---------------- boot ---------------- */

readFilters();
updateStats();
connect(false);

// after a reconnect the browser reuses the same URL, so mark it live-only
setTimeout(function () { /* no-op, EventSource reuses URL */ }, 0);

})();
</script>
</body>
</html>
`
