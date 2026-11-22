import { createSignal, onCleanup, Show } from "solid-js";
import { render } from "@solidjs/web";
import { Compose } from "./compose";
import { Icon } from "./icons";
import { Logo } from "./logo";
import { Reveal } from "./reveal";
import { Security } from "./security";
import { CryptoClient } from "./worker-client";
import { playSound, setSounds, soundsEnabled } from "./share-sounds";
import { changeView, trackInput } from "./transitions";
import { IconButton } from "./ui";
import "./style.css";
import "./motion.css";

// The security page used to live at /#security. Move old links to its own path.
if (location.pathname === "/" && location.hash === "#security") history.replaceState(null, "", "/security");
const path = location.pathname;
// Home and the security page are views of one screen, so a half-written note survives a visit.
const home = path === "/" || path === "/security";
const securityPath = "/security";
const onSecurity = () => location.pathname === securityPath;
const titles = {
  note: "Tightlip: send a password or file that burns after reading",
  security: "How Tightlip keeps a secret: encryption, burn and limits",
  share: "A sealed note for you · Tightlip",
};
document.title = onSecurity() ? titles.security : home ? titles.note : titles.share;

// Read the share key and replace the URL shown in the address bar.
// On the home page the only fragment with a meaning is the security page.
let fragment = "";
if (!onSecurity() && (location.hash || location.href.endsWith("#"))) {
  fragment = home ? "" : location.hash.slice(1);
  const address = new URL(location.href);
  address.hash = "";
  history.replaceState(history.state, "", address);
}

function takeFragment(): string {
  const value = fragment;
  fragment = "";
  return value;
}

function App() {
  const client = new CryptoClient();
  const [sound, setSound] = createSignal(soundsEnabled());
  const [security, setSecurity] = createSignal(onSecurity());
  onCleanup(trackInput());
  onCleanup(() => client.close());

  const sync = () => {
    setSecurity(onSecurity());
    if (home) document.title = onSecurity() ? titles.security : titles.note;
  };
  window.addEventListener("popstate", sync);
  window.addEventListener("hashchange", sync);
  onCleanup(() => {
    window.removeEventListener("popstate", sync);
    window.removeEventListener("hashchange", sync);
  });

  // On the home page the security page is a view, so a half-written note survives the visit.
  function show(open: boolean, event: MouseEvent) {
    if (!home || event.metaKey || event.ctrlKey || event.shiftKey || event.button !== 0) return;
    event.preventDefault();
    if (open === security()) return;
    history.pushState(null, "", open ? securityPath : "/");
    document.title = open ? titles.security : titles.note;
    void changeView("compose", () => setSecurity(open), event.detail > 0).then(() => {
      window.scrollTo({ top: 0 });
      if (event.detail === 0) document.getElementById(open ? "security-title" : "share-text")?.focus();
    });
  }

  return (
    <div class="shell">
      <header>
        <a class="logo" href="/" aria-label="tightlip, write a secret" onClick={(event) => show(false, event)}><Logo /></a>
        <nav aria-label="Site">
          <a class="icon-button" href={securityPath} target={home ? undefined : "_blank"}
            rel={home ? undefined : "noopener"} title="How Tightlip protects a secret" aria-label="Security"
            aria-current={security() ? "page" : undefined} onClick={(event) => show(true, event)}>
            <Icon name="shield" />
          </a>
          <a class="nav-link" href="https://www.kurolabs.in" target="_blank" rel="noopener noreferrer"
            title="KuroLabs, the studio behind Tightlip">KuroLabs<Icon name="external" /></a>
        </nav>
      </header>
      <div class="desk" data-page={security() ? "security" : "note"}>
        <main>
          <Show when={home} fallback={<Reveal client={client} path={path} takeFragment={takeFragment} />}>
            <div hidden={security()}><Compose client={client} /></div>
            <Show when={security()}><Security back={(event) => show(false, event)} /></Show>
          </Show>
        </main>
        <footer>
          <span>Your browser encrypts shares before upload.</span>
          <div class="footer-actions">
            <IconButton icon={sound() ? "sound" : "mute"} label={sound() ? "Turn sounds off" : "Turn sounds on"}
              pressed={sound()} onClick={() => {
                const enabled = !sound();
                setSound(enabled);
                setSounds(enabled);
                if (enabled) playSound("tap");
              }} />
          </div>
        </footer>
      </div>
    </div>
  );
}

const app = document.getElementById("app");
if (app) render(() => <App />, app);
