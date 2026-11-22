// Adapted from Bencho "Upload dropzone" (bencho.dev), used under the Bencho Pro licence.
import { For, createSignal } from "solid-js";
import { safeFileName } from "./attachments";
import { Icon } from "./icons";
import { FileName, IconButton, fileSize } from "./ui";

export interface PickedFile {
  file: File;
  thumbnail?: string;
  metadataKept: boolean;
}

export function UploadDropzone(props: {
  disabled: boolean;
  items: PickedFile[];
  pick: (files: FileList, pointer: boolean) => void;
  remove: (item: PickedFile, pointer: boolean) => void;
}) {
  const [over, setOver] = createSignal(false);
  let picker: HTMLInputElement | undefined;
  let choose: HTMLButtonElement | undefined;
  let pickedWithPointer = false;
  let depth = 0;

  const carriesFiles = (event: DragEvent) => event.dataTransfer?.types.includes("Files") === true;
  return (
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
      <div class="drop-prompt">
        <span class="drop-icon"><Icon name="upload" /></span>
        <span>Drop photos or files here, or{" "}
          <button class="sentence-button" type="button" aria-label="Choose files"
            ref={(element) => { choose = element; }} onClick={(event) => {
              pickedWithPointer = event.detail > 0;
              picker?.click();
            }}><span>choose</span></button></span>
      </div>
      <ul class="file-list picked-files" hidden={!props.items.length}>
        <For each={props.items}>{(item) => (
          <li class="picked-file">
            <div class="file-preview">
              {item.thumbnail ? <img class="thumbnail" src={item.thumbnail} alt="" /> : <Icon name="files" />}
              <IconButton icon="remove" label={`Remove ${safeFileName(item.file.name)}`} onClick={(event) => {
                const pointer = event.detail > 0;
                if (!pointer) choose?.focus();
                props.remove(item, pointer);
              }} />
            </div>
            <div class="file-info"><FileName name={item.file.name} /><small>{fileSize(item.file.size)}{item.metadataKept ? " • Metadata kept" : ""}</small></div>
          </li>
        )}</For>
      </ul>
    </div>
  );
}
