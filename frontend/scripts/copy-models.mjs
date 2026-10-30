// Copies the neural-network models FaceVault needs from node_modules into public/models,
// so face recognition works fully offline (no CDN).
import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "node_modules", "@vladmandic", "face-api", "model");
const dest = join(root, "public", "models");
const models = ["ssd_mobilenetv1_model", "tiny_face_detector_model", "face_landmark_68_model", "face_recognition_model"];

mkdirSync(dest, { recursive: true });
let copied = 0;
for (const m of models) {
  for (const file of [`${m}-weights_manifest.json`, `${m}.bin`]) {
    if (!existsSync(join(dest, file))) {
      copyFileSync(join(src, file), join(dest, file));
      copied++;
    }
  }
}
console.log(`[models] ${copied ? `copied ${copied} file(s) to` : "already present in"} public/models`);
