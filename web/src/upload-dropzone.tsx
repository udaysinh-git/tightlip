// Adapted from Bencho "Upload dropzone" (bencho.dev), used under the Bencho Pro licence.
import { For, createSignal } from "solid-js";
import { IconButton, fileSize } from "./ui";

export interface PickedFile {
  id: number;
  file: File;
  thumbnail?: string;
}

export function UploadDropzone(props: {
  disabled: boolean;
  items: PickedFile[];
  pick: (files: FileList, pointer: boolean) => void;
  remove: (item: PickedFile, pointer: boolean) => void;
}) {
  const [over, setOver] = createSignal(false);
  let picker: HTMLInputElement | undefined;
  let pickedWithPointer = false;
  let depth = 0;

  const carriesFiles = (event: DragEvent) => event.dataTransfer?.types.includes("Files") === true;
  return (
    <>
      <div class="drop-zone" data-over={over() && !props.disabled ? "" : undefined}
        onDragEnter={(event) => {
          if (!carriesFiles(event)) return;
          event.preventDefault();
          depth += 1;
          setOver(true);
        }}
        onDragOver={(event) => {
          if (!carriesFiles(event)) return;
          event.preventDefault();
          if (event.dataTransfer) event.dataTransfer.dropEffect = props.disabled ? "none" : "copy";
        }}
        onDragLeave={() => {
          depth = Math.max(0, depth - 1);
          if (depth === 0) setOver(false);
        }}
        onDrop={(event) => {
          event.preventDefault();
          depth = 0;
          setOver(false);
          if (!props.disabled && event.dataTransfer?.files.length) props.pick(event.dataTransfer.files, true);
        }}>
        <input type="file" multiple hidden ref={(element) => { picker = element; }}
          onChange={(event) => {
            const field = event.currentTarget;
            if (!props.disabled && field.files?.length) props.pick(field.files, pickedWithPointer);
            pickedWithPointer = false;
            field.value = "";
          }} />
        <IconButton icon="upload" label="Pick files" onClick={(event) => {
          pickedWithPointer = event.detail > 0;
          picker?.click();
        }} />
        <span>{over() && !props.disabled ? "Drop to attach" : "Drop files here or use the file picker."}</span>
      </div>
      <ul class="file-list picked-files" hidden={!props.items.length}>
        <For each={props.items}>{(item) => (
          <li class="file-row picked-file" data-motion-shared="" ref={(element) => {
            element.style.setProperty("--file-name", `picked-${item.id}`);
          }}>
            {item.thumbnail && <img class="thumbnail" src={item.thumbnail} alt="" />}
            <div class="file-info">
              <span>{item.file.name}</span><small>{fileSize(item.file.size)}</small>
            </div>
            <IconButton icon="remove" label={`Remove ${item.file.name}`}
              onClick={(event) => {
                const pointer = event.detail > 0;
                if (!pointer) picker?.closest(".drop-zone")?.querySelector<HTMLElement>("button")?.focus();
                props.remove(item, pointer);
              }} />
          </li>
        )}</For>
      </ul>
    </>
  );
}
