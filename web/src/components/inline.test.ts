import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { createElement } from "react";
import { Inline } from "./ui";

const html = (text: string) => renderToStaticMarkup(createElement(Inline, { text }));

describe("Inline", () => {
  it("makes code of what is in backticks", () => {
    expect(html("Set `PermitRootLogin no` now")).toBe("<span>Set </span><code>PermitRootLogin no</code><span> now</span>");
  });
  it("keeps an unclosed backtick as text", () => {
    expect(html("a `b")).toBe("<span>a `b</span>");
  });
  it("never lets host or pack text become markup", () => {
    expect(html("`<img src=x onerror=alert(1)>` <b>x</b>")).toBe("<span></span><code>&lt;img src=x onerror=alert(1)&gt;</code><span> &lt;b&gt;x&lt;/b&gt;</span>");
  });
});
