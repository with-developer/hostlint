import { useState } from "react";
import { useI18n } from "../lib/i18n";

/** A command to copy: what the first run needs, with this page's own address filled in. */
function Command({ text }: { text: string }) {
  const { t } = useI18n();
  const [done, setDone] = useState(false);
  const copy = () => {
    // The clipboard is not there on plain http or without permission: the text is selectable anyway.
    navigator.clipboard?.writeText(text).then(
      () => {
        setDone(true);
        setTimeout(() => setDone(false), 1500);
      },
      () => {},
    );
  };
  return (
    <div className="command">
      <pre>{text}</pre>
      <button onClick={copy}>{done ? t("copied") : t("copy")}</button>
    </div>
  );
}

/** The first run: nothing has reported yet, so the page says how to send a result. */
export function GettingStarted() {
  const { t } = useI18n();
  const server = location.origin;
  return (
    <section className="card start">
      <h2>{t("start.title")}</h2>
      <p className="muted">{t("start.lead")}</p>
      <h3>{t("start.step1")}</h3>
      <Command text="vmsctl server token create --name web-01 --host web-01" />
      <h3>{t("start.step2")}</h3>
      <Command text={`sudo VMSCTL_TOKEN=hlt_ing_… vmsctl scan --push ${server}`} />
      <h3>{t("start.step3")}</h3>
      <p className="muted small">{t("start.note")}</p>
    </section>
  );
}
