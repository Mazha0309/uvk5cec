"use strict";

const $ = (id) => document.getElementById(id);
const textDecoder = new TextDecoder();
const EXPECTED_FIRMWARE_VERSION = "*Mazha0309 03VC";

const PROTOCOL_XOR = Uint8Array.from([
  0x16, 0x6c, 0x14, 0xe6, 0x2e, 0x91, 0x0d, 0x40,
  0x21, 0x35, 0xd5, 0x40, 0x13, 0x03, 0xe9, 0x80,
]);

const FIRMWARE_XOR = Uint8Array.from([
  0x47, 0x22, 0xc0, 0x52, 0x5d, 0x57, 0x48, 0x94, 0xb1, 0x60, 0x60, 0xdb, 0x6f, 0xe3, 0x4c, 0x7c,
  0xd8, 0x4a, 0xd6, 0x8b, 0x30, 0xec, 0x25, 0xe0, 0x4c, 0xd9, 0x00, 0x7f, 0xbf, 0xe3, 0x54, 0x05,
  0xe9, 0x3a, 0x97, 0x6b, 0xb0, 0x6e, 0x0c, 0xfb, 0xb1, 0x1a, 0xe2, 0xc9, 0xc1, 0x56, 0x47, 0xe9,
  0xba, 0xf1, 0x42, 0xb6, 0x67, 0x5f, 0x0f, 0x96, 0xf7, 0xc9, 0x3c, 0x84, 0x1b, 0x26, 0xe1, 0x4e,
  0x3b, 0x6f, 0x66, 0xe6, 0xa0, 0x6a, 0xb0, 0xbf, 0xc6, 0xa5, 0x70, 0x3a, 0xba, 0x18, 0x9e, 0x27,
  0x1a, 0x53, 0x5b, 0x71, 0xb1, 0x94, 0x1e, 0x18, 0xf2, 0xd6, 0x81, 0x02, 0x22, 0xfd, 0x5a, 0x28,
  0x91, 0xdb, 0xba, 0x5d, 0x64, 0xc6, 0xfe, 0x86, 0x83, 0x9c, 0x50, 0x1c, 0x73, 0x03, 0x11, 0xd6,
  0xaf, 0x30, 0xf4, 0x2c, 0x77, 0xb2, 0x7d, 0xbb, 0x3f, 0x29, 0x28, 0x57, 0x22, 0xd6, 0x92, 0x8b,
]);

let parsedFirmware = null;
let serialBusy = false;

function crc16Xmodem(data) {
  let crc = 0;
  for (const value of data) {
    crc ^= value << 8;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc;
}

function concatBytes(...parts) {
  const size = parts.reduce((total, part) => total + part.length, 0);
  const result = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function hexBytes(data) {
  return Array.from(data, (value) => value.toString(16).padStart(2, "0").toUpperCase()).join(" ");
}

function appendLog(element, message, replace = false) {
  const stamp = new Date().toLocaleTimeString("zh-CN", { hour12: false });
  const line = `[${stamp}] ${message}`;
  element.textContent = replace ? line : `${element.textContent}\n${line}`.trim();
  element.scrollTop = element.scrollHeight;
}

function errorMessage(error) {
  if (error?.name === "NotFoundError") return "已取消选择串口。";
  return error instanceof Error ? error.message : String(error);
}

function setActiveTab(name) {
  document.querySelectorAll(".tab").forEach((button) => {
    const active = button.dataset.tab === name;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
  });
  document.querySelectorAll("[data-panel]").forEach((panel) => {
    const active = panel.dataset.panel === name;
    panel.classList.toggle("active", active);
    panel.hidden = !active;
  });
}

document.querySelectorAll(".tab").forEach((button) => {
  button.addEventListener("click", () => setActiveTab(button.dataset.tab));
});

// ---------------------------------------------------------------------------
// Vero BSS parser

function decodeHexInput(input) {
  let candidate = input.trim();
  if (candidate.includes(":")) candidate = candidate.slice(candidate.lastIndexOf(":") + 1);
  candidate = candidate.replace(/0x/gi, "").replace(/[^0-9a-f]/gi, "");
  if (!candidate) throw new Error("没有找到十六进制数据。");
  if (candidate.length % 2 !== 0) throw new Error(`hex 长度为奇数，末尾缺少半个字节：${candidate.length} 字符。`);
  return Uint8Array.from(candidate.match(/../g), (pair) => Number.parseInt(pair, 16));
}

function signed24BE(data, offset) {
  let value = (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2];
  if (value & 0x800000) value -= 0x1000000;
  return value;
}

function signed16BE(data, offset) {
  const value = (data[offset] << 8) | data[offset + 1];
  return value & 0x8000 ? value - 0x10000 : value;
}

function unsigned16BE(data, offset) {
  return (data[offset] << 8) | data[offset + 1];
}

function parseBss(data) {
  if (data.length < 6) throw new Error(`BSS 头至少需要 6 字节，当前只有 ${data.length} 字节。`);

  const warnings = [];
  const fields = [];
  if (data[0] !== 0x01) warnings.push(`字节 0 应为 BSS 标记 01，实际为 ${hexBytes(data.slice(0, 1))}。`);
  if (data[1] !== 0x8b) warnings.push(`字节 1 应为身份类型 8B，实际为 ${hexBytes(data.slice(1, 2))}。`);

  const uid = ((data[2] * 0x1000000) + (data[3] << 16) + (data[4] << 8) + data[5]) >>> 0;
  fields.push({ offset: 0, length: 1, name: "BSS 标记", value: data[0] === 1 ? "01（BSS）" : `未知 0x${data[0].toString(16).padStart(2, "0")}` });
  fields.push({ offset: 1, length: 1, name: "身份类型", value: data[1] === 0x8b ? "8B（Vero User ID）" : `未知 0x${data[1].toString(16).padStart(2, "0")}` });
  fields.push({ offset: 2, length: 4, name: "User ID", value: `${uid} / 0x${uid.toString(16).padStart(8, "0").toUpperCase()}` });

  const result = { uid, station: null, latitude: null, longitude: null, altitude: null, speed: null, heading: null, fields, warnings };
  let offset = 6;
  while (offset < data.length) {
    const length = data[offset];
    if (length < 1) {
      warnings.push(`偏移 ${offset} 的 TLV 长度为 0，停止解析。`);
      fields.push({ offset, length: 1, name: "无效 TLV", value: "长度 0" });
      break;
    }
    const next = offset + 1 + length;
    if (next > data.length) {
      warnings.push(`偏移 ${offset} 声明 ${length} 字节，但包已截断。`);
      fields.push({ offset, length: data.length - offset, name: "截断 TLV", value: `声明长度 ${length}` });
      break;
    }

    const type = data[offset + 1];
    const payloadOffset = offset + 2;
    const payloadLength = length - 1;
    if (type === 0x20) {
      const stationBytes = data.slice(payloadOffset, payloadOffset + payloadLength);
      result.station = Array.from(stationBytes, (byte) => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : "�").join("");
      fields.push({ offset, length: length + 1, name: "台站 / 呼号 (20)", value: result.station || "空" });
    } else if (type === 0x25) {
      if (payloadLength !== 12) {
        warnings.push(`位置字段 25 应有 12 字节负载，实际为 ${payloadLength}。`);
        fields.push({ offset, length: length + 1, name: "位置 (25)", value: `长度异常：${payloadLength}` });
      } else {
        const latitudeRaw = signed24BE(data, payloadOffset);
        const longitudeRaw = signed24BE(data, payloadOffset + 3);
        result.latitude = latitudeRaw / 30000;
        result.longitude = longitudeRaw / 30000;
        result.altitude = signed16BE(data, payloadOffset + 6);
        result.speed = unsigned16BE(data, payloadOffset + 8);
        const headingRaw = unsigned16BE(data, payloadOffset + 10);
        result.heading = headingRaw === 0xffff ? null : headingRaw;
        fields.push({
          offset,
          length: length + 1,
          name: "位置 (25)",
          value: `${result.latitude.toFixed(6)}, ${result.longitude.toFixed(6)} · ${result.altitude} m · 速度 ${result.speed} · 航向 ${result.heading ?? "未知"}`,
        });
      }
    } else {
      fields.push({ offset, length: length + 1, name: `未知 TLV 0x${type.toString(16).padStart(2, "0").toUpperCase()}`, value: `${payloadLength} 字节负载` });
    }
    offset = next;
  }
  return result;
}

function renderBss(data, result) {
  const summary = $("bss-summary");
  summary.replaceChildren();
  const grid = document.createElement("div");
  grid.className = "result-grid";
  const values = [
    ["User ID", `${result.uid}`],
    ["呼号", result.station ?? "未包含"],
    ["纬度", result.latitude == null ? "未包含" : `${result.latitude.toFixed(6)}°`],
    ["经度", result.longitude == null ? "未包含" : `${result.longitude.toFixed(6)}°`],
    ["海拔", result.altitude == null ? "未包含" : `${result.altitude} m`],
    ["航向", result.heading == null ? (result.latitude == null ? "未包含" : "FFFF / 未知") : `${result.heading}°`],
  ];
  for (const [label, value] of values) {
    const item = document.createElement("div");
    item.className = "result-value";
    const labelNode = document.createElement("span");
    labelNode.textContent = label;
    const valueNode = document.createElement("strong");
    valueNode.textContent = value;
    item.append(labelNode, valueNode);
    grid.append(item);
  }
  summary.append(grid);
  if (result.warnings.length) {
    const warning = document.createElement("p");
    warning.className = "parse-warning";
    warning.textContent = result.warnings.join(" ");
    summary.append(warning);
  }

  $("bss-byte-count").textContent = `${data.length} 字节`;
  const body = $("bss-fields");
  body.replaceChildren();
  for (const field of result.fields) {
    const row = document.createElement("tr");
    const cells = [
      `0x${field.offset.toString(16).padStart(2, "0").toUpperCase()}`,
      hexBytes(data.slice(field.offset, field.offset + field.length)),
      field.name,
      field.value,
    ];
    for (const value of cells) {
      const cell = document.createElement("td");
      cell.textContent = value;
      row.append(cell);
    }
    body.append(row);
  }
}

function showBssError(error) {
  const summary = $("bss-summary");
  summary.replaceChildren();
  const message = document.createElement("p");
  message.className = "empty-state parse-error";
  message.textContent = errorMessage(error);
  summary.append(message);
  $("bss-byte-count").textContent = "解析失败";
  $("bss-fields").innerHTML = '<tr><td colspan="4" class="muted">请检查输入</td></tr>';
}

function runBssParser() {
  try {
    const data = decodeHexInput($("bss-input").value);
    renderBss(data, parseBss(data));
  } catch (error) {
    showBssError(error);
  }
}

$("parse-bss").addEventListener("click", runBssParser);

// ---------------------------------------------------------------------------
// Quansheng serial framing and bootloader flashing

function xorProtocol(data) {
  return Uint8Array.from(data, (value, index) => value ^ PROTOCOL_XOR[index % PROTOCOL_XOR.length]);
}

function packetize(data) {
  const crc = crc16Xmodem(data);
  const protectedData = new Uint8Array(data.length + 2);
  protectedData.set(data);
  protectedData[data.length] = crc & 0xff;
  protectedData[data.length + 1] = crc >> 8;
  const encrypted = xorProtocol(protectedData);
  const packet = new Uint8Array(data.length + 8);
  packet.set([0xab, 0xcd, data.length & 0xff, data.length >> 8], 0);
  packet.set(encrypted, 4);
  packet.set([0xdc, 0xba], packet.length - 2);
  return packet;
}

class SerialConnection {
  constructor(port) {
    this.port = port;
    this.reader = null;
    this.writer = null;
    this.buffer = new Uint8Array();
  }

  async open() {
    await this.port.open({ baudRate: 38400, dataBits: 8, stopBits: 1, parity: "none", flowControl: "none" });
    if (!this.port.readable || !this.port.writable) throw new Error("串口不可读写。");
    this.reader = this.port.readable.getReader();
    this.writer = this.port.writable.getWriter();
  }

  async close() {
    if (this.reader) {
      try { await this.reader.cancel(); } catch (_) { /* port may already be gone */ }
      this.reader.releaseLock();
      this.reader = null;
    }
    if (this.writer) {
      this.writer.releaseLock();
      this.writer = null;
    }
    try { await this.port.close(); } catch (_) { /* already closed */ }
  }

  async send(data) {
    await this.writer.write(packetize(data));
  }

  append(data) {
    this.buffer = concatBytes(this.buffer, data);
  }

  extractPacket() {
    while (this.buffer.length >= 2 && !(this.buffer[0] === 0xab && this.buffer[1] === 0xcd)) {
      this.buffer = this.buffer.slice(1);
    }
    if (this.buffer.length < 4) return null;
    const length = this.buffer[2] | (this.buffer[3] << 8);
    if (length > 4096) {
      this.buffer = this.buffer.slice(1);
      return null;
    }
    const total = length + 8;
    if (this.buffer.length < total) return null;
    if (this.buffer[length + 6] !== 0xdc || this.buffer[length + 7] !== 0xba) {
      this.buffer = this.buffer.slice(1);
      return null;
    }
    const result = xorProtocol(this.buffer.slice(4, 4 + length));
    this.buffer = this.buffer.slice(total);
    return result;
  }

  async readPacket(predicate = () => true, timeoutMs = 2500) {
    const deadline = performance.now() + timeoutMs;
    while (performance.now() < deadline) {
      let packet;
      while ((packet = this.extractPacket()) !== null) {
        if (predicate(packet)) return packet;
      }
      const remaining = Math.max(1, deadline - performance.now());
      let timer;
      const timeout = new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("等待手台回复超时。")), remaining);
      });
      try {
        const { value, done } = await Promise.race([this.reader.read(), timeout]);
        if (done) throw new Error("串口已关闭。");
        if (value?.length) this.append(value);
      } finally {
        clearTimeout(timer);
      }
    }
    throw new Error("等待手台回复超时。");
  }
}

async function openSerial() {
  if (!("serial" in navigator)) throw new Error("当前浏览器不支持 Web Serial，请使用 Chrome 或 Edge。");
  const port = await navigator.serial.requestPort();
  const connection = new SerialConnection(port);
  await connection.open();
  return connection;
}

// ---------------------------------------------------------------------------
// Packed firmware inspection and bootloader flasher

function unpackFirmware(fileBytes) {
  if (fileBytes.length < 0x2000 + 18) throw new Error("文件太短，不是可刷写的 UV-K5 打包固件。");
  const encoded = fileBytes.slice(0, -2);
  const expectedCrc = fileBytes[fileBytes.length - 2] | (fileBytes[fileBytes.length - 1] << 8);
  const actualCrc = crc16Xmodem(encoded);
  if (actualCrc !== expectedCrc) {
    throw new Error(`CRC16 不匹配：文件 0x${expectedCrc.toString(16).padStart(4, "0").toUpperCase()}，计算 0x${actualCrc.toString(16).padStart(4, "0").toUpperCase()}。`);
  }

  const decoded = Uint8Array.from(encoded, (value, index) => value ^ FIRMWARE_XOR[index % FIRMWARE_XOR.length]);
  const versionBytes = decoded.slice(0x2000, 0x2010);
  const zero = versionBytes.indexOf(0);
  const version = textDecoder.decode(zero < 0 ? versionBytes : versionBytes.slice(0, zero));
  if (version !== EXPECTED_FIRMWARE_VERSION) {
    throw new Error(`固件版本应为 ${EXPECTED_FIRMWARE_VERSION}，实际为 ${JSON.stringify(version)}。本页只刷写当前 CEC BSS 补丁固件。`);
  }

  const raw = new Uint8Array(decoded.length - 16);
  raw.set(decoded.slice(0, 0x2000));
  raw.set(decoded.slice(0x2010), 0x2000);
  if (raw.length > 0xefff) throw new Error(`原始固件 ${raw.length} 字节，超过 0xEFFF 安全上限。`);
  return { raw, versionBytes, version, crc: actualCrc, packedSize: fileBytes.length };
}

function updateFlashButton() {
  const serialAvailable = "serial" in navigator;
  $("flash-firmware").disabled = !parsedFirmware || !$("flash-confirm").checked || !serialAvailable || serialBusy;
}

async function selectFirmware() {
  parsedFirmware = null;
  $("flash-progress").value = 0;
  $("flash-percent").textContent = "0%";
  const file = $("firmware-file").files[0];
  const info = $("firmware-info");
  if (!file) {
    info.className = "file-info";
    info.textContent = "未选择文件。";
    $("flash-stage").textContent = "等待文件";
    updateFlashButton();
    return;
  }
  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    parsedFirmware = unpackFirmware(bytes);
    info.className = "file-info valid";
    info.textContent = `${file.name}\n版本：${parsedFirmware.version}\n打包：${parsedFirmware.packedSize} B · 实体：${parsedFirmware.raw.length} B\nCRC16：0x${parsedFirmware.crc.toString(16).padStart(4, "0").toUpperCase()} ✓`;
    $("flash-stage").textContent = "文件校验通过";
    appendLog($("flash-log"), `已识别 ${parsedFirmware.version}，等待连接刷机模式。`, true);
  } catch (error) {
    info.className = "file-info invalid";
    info.textContent = `拒绝该文件：${errorMessage(error)}`;
    $("flash-stage").textContent = "文件无效";
    appendLog($("flash-log"), `错误：${errorMessage(error)}`, true);
  }
  updateFlashButton();
}

function makeFlashCommand(block, address, totalSize) {
  const padded = new Uint8Array(0x100);
  padded.set(block);
  const roundedEnd = (totalSize + 0xff) & ~0xff;
  if (roundedEnd > 0xf000) throw new Error("固件四舍五入后超过 0xF000。");
  return Uint8Array.from([
    0x19, 0x05, 0x0c, 0x01, 0x8a, 0x8d, 0x9f, 0x1d,
    (address >> 8) & 0xff, address & 0xff,
    (roundedEnd >> 8) & 0xff, roundedEnd & 0xff,
    0x01, 0x00, 0x00, 0x00,
    ...padded,
  ]);
}

async function flashFirmware() {
  if (!parsedFirmware || serialBusy) return;
  serialBusy = true;
  updateFlashButton();
  const log = $("flash-log");
  const progress = $("flash-progress");
  const stage = $("flash-stage");
  let connection;
  try {
    appendLog(log, "请选择已进入刷机模式的手台串口……", true);
    stage.textContent = "连接串口";
    connection = await openSerial();
    appendLog(log, "串口已打开，等待 bootloader 0x18 心跳……");
    await connection.readPacket((packet) => packet[0] === 0x18, 4000);
    appendLog(log, "已检测到刷机模式。");

    stage.textContent = "版本协商";
    const init = new Uint8Array(20);
    init.set([0x30, 0x05, 0x10, 0x00]);
    init.set(parsedFirmware.versionBytes, 4);
    await connection.send(init);
    const initReply = await connection.readPacket((packet) => packet[0] === 0x18, 3000);
    if (parsedFirmware.versionBytes[0] !== 0x2a && initReply.length > 0x14 && initReply[0x14] !== parsedFirmware.versionBytes[0]) {
      throw new Error("固件机型版本与 bootloader 不匹配。");
    }
    appendLog(log, `版本校验通过：${parsedFirmware.version}。`);

    stage.textContent = "正在写入 Flash";
    progress.value = 0;
    for (let address = 0; address < parsedFirmware.raw.length; address += 0x100) {
      const block = parsedFirmware.raw.slice(address, address + 0x100);
      await connection.send(makeFlashCommand(block, address, parsedFirmware.raw.length));
      await connection.readPacket((packet) => packet[0] === 0x1a, 3500);
      const percent = Math.min(100, (address + block.length) * 100 / parsedFirmware.raw.length);
      progress.value = percent;
      $("flash-percent").textContent = `${percent.toFixed(1)}%`;
      if (address % 0x1000 === 0) appendLog(log, `已写入 0x${address.toString(16).padStart(4, "0").toUpperCase()}……`);
    }
    progress.value = 100;
    $("flash-percent").textContent = "100%";
    stage.textContent = "刷写完成";
    appendLog(log, "固件刷写成功。请关机，松开 PTT 后正常开机。");
  } catch (error) {
    stage.textContent = "刷写中止";
    appendLog(log, `错误：${errorMessage(error)}`);
  } finally {
    if (connection) await connection.close();
    serialBusy = false;
    updateFlashButton();
  }
}

$("firmware-file").addEventListener("change", selectFirmware);
$("flash-confirm").addEventListener("change", updateFlashButton);
$("flash-firmware").addEventListener("click", flashFirmware);
updateFlashButton();

if (!("serial" in navigator)) {
  $("flash-log").textContent = "当前浏览器没有 Web Serial。可解析文件，但不能刷写。";
}

// Small read-only surface for browser smoke tests and protocol debugging.
window.K5DigitalLab = Object.freeze({
  crc16Xmodem,
  decodeHexInput,
  parseBss,
  unpackFirmware,
});
