#pragma once

// Applies the refined dark theme (spacing, rounding, palette) to the current
// ImGui context and attempts to load a mono/sans font pair from ./assets if
// present, falling back to the built-in font otherwise.
void apply_theme();

// Accent colour packed as ImU32, reused by the UI for AI highlights and plots.
unsigned int accent_u32();
