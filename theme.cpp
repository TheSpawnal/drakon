#include "theme.hpp"

#include <filesystem>

#include "imgui.h"

namespace {
// A cohesive, low-saturation palette. Cool neutral surfaces, a single soft-cyan
// accent, warm-neutral text. Nothing shouts; the data does the talking.
constexpr ImVec4 kBg      = {0.078f, 0.086f, 0.102f, 1.00f};  // window
constexpr ImVec4 kPanel   = {0.106f, 0.118f, 0.141f, 1.00f};  // frames
constexpr ImVec4 kPanelHi = {0.145f, 0.161f, 0.192f, 1.00f};
constexpr ImVec4 kBorder  = {0.180f, 0.200f, 0.235f, 1.00f};
constexpr ImVec4 kText    = {0.860f, 0.878f, 0.902f, 1.00f};
constexpr ImVec4 kTextDim = {0.520f, 0.549f, 0.596f, 1.00f};
constexpr ImVec4 kAccent  = {0.361f, 0.784f, 1.000f, 1.00f};  // soft cyan
constexpr ImVec4 kAccentD = {0.220f, 0.470f, 0.610f, 1.00f};

ImVec4 mix(const ImVec4& c, float a) { return {c.x, c.y, c.z, a}; }
}  // namespace

unsigned int accent_u32() { return ImGui::ColorConvertFloat4ToU32(kAccent); }

void apply_theme() {
    ImGuiStyle& s = ImGui::GetStyle();

    s.WindowPadding     = {14, 12};
    s.FramePadding      = {10, 6};
    s.CellPadding       = {8, 5};
    s.ItemSpacing       = {10, 8};
    s.ItemInnerSpacing  = {8, 6};
    s.ScrollbarSize     = 12;
    s.GrabMinSize       = 10;

    s.WindowBorderSize  = 1;
    s.FrameBorderSize   = 1;
    s.PopupBorderSize   = 1;

    s.WindowRounding    = 8;
    s.ChildRounding     = 8;
    s.FrameRounding     = 6;
    s.PopupRounding     = 6;
    s.ScrollbarRounding = 8;
    s.GrabRounding      = 6;
    s.TabRounding       = 6;

    ImVec4* c = s.Colors;
    c[ImGuiCol_WindowBg]            = kBg;
    c[ImGuiCol_ChildBg]             = mix(kPanel, 0.0f);
    c[ImGuiCol_PopupBg]             = kPanel;
    c[ImGuiCol_Border]              = kBorder;
    c[ImGuiCol_FrameBg]             = kPanel;
    c[ImGuiCol_FrameBgHovered]      = kPanelHi;
    c[ImGuiCol_FrameBgActive]       = kPanelHi;
    c[ImGuiCol_TitleBg]             = kBg;
    c[ImGuiCol_TitleBgActive]       = kPanel;
    c[ImGuiCol_MenuBarBg]           = kBg;
    c[ImGuiCol_Text]                = kText;
    c[ImGuiCol_TextDisabled]        = kTextDim;
    c[ImGuiCol_CheckMark]           = kAccent;
    c[ImGuiCol_SliderGrab]          = kAccentD;
    c[ImGuiCol_SliderGrabActive]    = kAccent;
    c[ImGuiCol_Button]              = kPanelHi;
    c[ImGuiCol_ButtonHovered]       = mix(kAccent, 0.25f);
    c[ImGuiCol_ButtonActive]        = mix(kAccent, 0.40f);
    c[ImGuiCol_Header]              = mix(kAccent, 0.20f);
    c[ImGuiCol_HeaderHovered]       = mix(kAccent, 0.30f);
    c[ImGuiCol_HeaderActive]        = mix(kAccent, 0.40f);
    c[ImGuiCol_Separator]          = kBorder;
    c[ImGuiCol_SeparatorHovered]    = kAccentD;
    c[ImGuiCol_Tab]                 = kPanel;
    c[ImGuiCol_TabHovered]          = mix(kAccent, 0.30f);
    c[ImGuiCol_TabActive]           = kPanelHi;
    c[ImGuiCol_TabUnfocused]        = kBg;
    c[ImGuiCol_TabUnfocusedActive]  = kPanel;
    c[ImGuiCol_PlotLines]           = kAccent;
    c[ImGuiCol_PlotHistogram]       = kAccent;
    c[ImGuiCol_TableHeaderBg]       = kPanel;
    c[ImGuiCol_TableBorderStrong]   = kBorder;
    c[ImGuiCol_TableBorderLight]    = mix(kBorder, 0.5f);
    c[ImGuiCol_TableRowBg]          = mix(kPanel, 0.0f);
    c[ImGuiCol_TableRowBgAlt]       = mix(kPanelHi, 0.35f);
    c[ImGuiCol_ScrollbarBg]         = kBg;
    c[ImGuiCol_ScrollbarGrab]       = kPanelHi;
    c[ImGuiCol_ScrollbarGrabHovered]= kBorder;

    // Optional font pair. Drop JetBrainsMono-Regular.ttf and Inter-Regular.ttf
    // into ./assets to upgrade from the built-in font; absence is harmless.
    ImGuiIO& io = ImGui::GetIO();
    namespace fs = std::filesystem;
    const char* sans = "assets/Inter-Regular.ttf";
    const char* mono = "assets/JetBrainsMono-Regular.ttf";
    if (fs::exists(sans)) io.Fonts->AddFontFromFileTTF(sans, 16.0f);
    if (fs::exists(mono)) io.Fonts->AddFontFromFileTTF(mono, 15.0f);
    if (io.Fonts->Fonts.empty()) io.Fonts->AddFontDefault();
}
