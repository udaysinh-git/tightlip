import { createSignal, onCleanup } from "solid-js";
import { render } from "@solidjs/web";
import { Compose } from "./compose";
import { Reveal } from "./reveal";
import { CryptoClient } from "./worker-client";
import { playSound, setSounds, soundsEnabled } from "./share-sounds";
import { trackInput } from "./transitions";
import { IconButton } from "./ui";
import "./style.css";
import "./motion.css";

const path = location.pathname;
let fragment = location.hash.slice(1);
if (location.hash || location.href.endsWith("#")) {
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
  onCleanup(trackInput());
  onCleanup(() => client.close());
  return (
    <div class="shell">
      <header>tightlip</header>
      <div class="desk">
        <main>{path === "/" ? <Compose client={client} /> : <Reveal client={client} path={path} takeFragment={takeFragment} />}</main>
        <footer>
          <span>End-to-end encrypted. The server never sees the secret.</span>
          <div class="footer-actions">
            <a href="https://github.com/udaysinh-git/tightlip#threat-model">Threat model</a>
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
